"""跨节点消费归属转移（consumer ownership handoff）。

用于滚动维护与容量调整：把一个审计租户的消费状态从一个中继实例**原样**
搬到另一个实例，且任何时刻至多一个节点对外服务、已确认前缀不回退、越序
完成记录不丢失。

阶段（``tenants.serve_phase``）::

    serving ──prepare──▶ draining ──export──▶ exported ──finalize(receipt)──▶ handed_over
       ▲                   │  undrain              │  undrain
       └───────────────────┴───────────────────────┘   （接管回执产生后不可逆）

    接收方：(无同名消费方) ──import──▶ incoming ──confirm──▶ adopted（产生接管回执）

安全要点：

* **draining**：不发放新窗口（调用方仍持有的有效短租约可回放，其自然结束）；
  短租约在此期间到期，完成提交仍可登记，连续提交屏障照常补洞推进；
* **export（封存清单）**：要求所有在途短租约均已结束；清单封存筛选条件、
  已确认前缀（``cursor_end``）、每个未决区间的边界、完成标记与尝试次数
  （``lease_count/lease_epoch``），并绑定导出时刻的**可信树头**；
  ``handoff_epoch`` 只增；导出后转移前凭据在双方都不能再改变已确认前缀；
* **import**：接收方必须独立验清单签名（机构 transparency 信任锚）、验内容
  摘要、证明自己的透明日志**至少包含**清单绑定的树头（落后即拒、同高不同根
  即分叉拒）、且没有同名消费方，才能原样恢复；相同清单重复导入返回首次结果，
  旧代次/并发导入/身份串用全部失败；
* **confirm**：产生签名接管回执（receipt）并换发**新**租户令牌；回执一经
  产生，原节点登记回执（finalize）后永久失去服务权，且原租户令牌在双方失效。

崩溃恢复只依赖持久化阶段：draining/exported/incoming/handed_over 都不会对外
发放新窗口，因此准备/导出/导入/确认任一步退出后，结果只能是“原节点继续”
（draining 撤销）或“新节点接管”（import→confirm），不可能双主。
"""

from __future__ import annotations

import json
import secrets as pysecrets
import sqlite3
from typing import Any

from .canonical import dumps_canon, hmac_hex, sha256_hex, token_hash, utcnow
from .errors import (
    HandoffBadManifest,
    HandoffConcurrent,
    HandoffLogBehind,
    HandoffLogForked,
    HandoffNotDrained,
    HandoffSealed,
    HandoffStaleEpoch,
    HandoffState,
    HandoffTenantExists,
    HandoffWrongIdentity,
    TenantDraining,
    TenantHandedOver,
    TransferNotFound,
)
from .merkle import envelope_leaf_hash, verify_inclusion
from .verify import CHECKPOINT_VERSION, _verify_checkpoint

MANIFEST_VERSION = "aft1"
RECEIPT_VERSION = "aftr1"

# 租户在各阶段下的对外服务语义
SERVING_PHASES = ("serving", "adopted")
NON_SERVING_PHASES = ("draining", "exported", "incoming", "handed_over")
_OPEN_STATES = ("draining", "exported", "imported")


def _sealed_digest(body: dict) -> str:
    """清单封存摘要：覆盖除 sig / manifest_digest 外的全部字段。"""
    material = {k: v for k, v in body.items()
                if k not in ("sig", "manifest_digest")}
    return sha256_hex(dumps_canon(material).encode("utf-8"))


class HandoffMixin:
    # Relay 提供：db / _lock / handoff_key / _event / _now / _state_row / ...

    # ------------------------------------------------------------------ #
    # instance identity
    # ------------------------------------------------------------------ #

    @property
    def node_id(self) -> str:
        row = self.db.execute(
            "SELECT value FROM meta WHERE key='node_id'").fetchone()
        if row is not None:
            return row["value"]
        node = "afrn_" + pysecrets.token_hex(12)
        self.db.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES('node_id', ?)",
            (node,))
        row = self.db.execute(
            "SELECT value FROM meta WHERE key='node_id'").fetchone()
        return row["value"]

    # ------------------------------------------------------------------ #
    # origin side: prepare / export / undo / finalize
    # ------------------------------------------------------------------ #

    def prepare_handoff(self, tenant_id: str) -> dict:
        """发起方进入 draining：不再分配新任务，已有短租约自然结束。"""
        with self._lock:
            tenant = self._require_tenant_id(tenant_id)
            self._require_serving_for_handoff(tenant)
            open_row = self._open_transfer(tenant_id)
            if open_row is not None:
                if open_row["direction"] == "outgoing" and \
                        open_row["state"] == "draining":
                    return self._transfer_view(open_row, tenant,
                                               idempotent=True)
                raise HandoffState(
                    f"tenant has an open {open_row['state']} transfer; "
                    "cannot prepare another")
            transfer_id = "aft_" + pysecrets.token_hex(16)
            self.db.execute("BEGIN IMMEDIATE")
            committed = False
            try:
                self.db.execute(
                    "UPDATE tenants SET serve_phase='draining' "
                    "WHERE tenant_id=?", (tenant_id,))
                self.db.execute(
                    """INSERT INTO transfers
                       (transfer_id, tenant_id, direction, state, handoff_epoch,
                        manifest_json, manifest_digest, node_id, created_at,
                        updated_at)
                       VALUES (?,?, 'outgoing','draining', ?, '{}', '', ?, ?, ?)""",
                    (transfer_id, tenant_id, int(tenant["handoff_epoch"]),
                     self.node_id, utcnow(), utcnow()))
                self._event("handoff_prepared", tenant_id=tenant_id,
                            detail={"transfer_id": transfer_id})
                self.db.execute("COMMIT")
                committed = True
            except Exception:
                if not committed:
                    self.db.execute("ROLLBACK")
                raise
            row = self._get_transfer_row(transfer_id)
            return self._transfer_view(row, self._reload_tenant(tenant_id))

    def export_handoff(self, tenant_id: str) -> dict:
        """封存并返回签名 transfer manifest（幂等：导出后返回同一份）。"""
        with self._lock:
            tenant = self._require_tenant_id(tenant_id)
            row = self._require_open_outgoing(tenant_id)
            if row["state"] == "exported":
                manifest = json.loads(row["manifest_json"])
                view = self._transfer_view(row, tenant, idempotent=True)
                view["manifest"] = manifest
                return view
            if row["state"] != "draining":
                raise HandoffState(
                    f"transfer is {row['state']}; prepare draining before export")

            # quiescence：所有在途短租约必须已自然结束（过期或仅待补洞完成）。
            active = self.db.execute(
                "SELECT delivery_id, lease_owner, lease_expires_at FROM deliveries "
                "WHERE tenant_id=? AND state='leased' AND lease_expires_at > ?",
                (tenant_id, str(self._now()))).fetchall()
            if active:
                first = active[0]
                raise HandoffNotDrained(
                    "active short leases remain; wait for them to expire "
                    "before exporting the transfer manifest",
                    detail={"active_lease": first["delivery_id"],
                            "lease_owner": first["lease_owner"],
                            "lease_expires_at": first["lease_expires_at"],
                            "active_lease_count": len(active)})

            manifest = self._build_manifest(tenant, row)
            new_epoch = int(manifest["handoff_epoch"])
            self.db.execute("BEGIN IMMEDIATE")
            committed = False
            try:
                self.db.execute(
                    "UPDATE tenants SET serve_phase='exported', handoff_epoch=? "
                    "WHERE tenant_id=?", (new_epoch, tenant_id))
                self.db.execute(
                    """UPDATE transfers SET state='exported', manifest_json=?,
                       manifest_digest=?, handoff_epoch=?, updated_at=?
                       WHERE transfer_id=?""",
                    (dumps_canon(manifest), manifest["manifest_digest"],
                     new_epoch, utcnow(), row["transfer_id"]))
                self._event("handoff_exported", tenant_id=tenant_id,
                            detail={"transfer_id": row["transfer_id"],
                                    "handoff_epoch": new_epoch,
                                    "anchor": manifest["log_anchor"]["tree_size"],
                                    "pending_windows": len(manifest["windows"])})
                self.db.execute("COMMIT")
                committed = True
            except Exception:
                if not committed:
                    self.db.execute("ROLLBACK")
                raise
            row = self._get_transfer_row(row["transfer_id"])
            view = self._transfer_view(row, self._reload_tenant(tenant_id))
            view["manifest"] = manifest
            return view

    def undo_handoff(self, tenant_id: str) -> dict:
        """撤销 draining/已封存导出，原节点继续服务。

        接管回执一旦产生（receiver 已 confirm），原节点登记回执后即为
        handed_over，此操作永久失败。导出后撤销会使旧代次清单失效：再次导出
        使用只增后的新 ``handoff_epoch``。
        """
        with self._lock:
            tenant = self._require_tenant_id(tenant_id)
            if tenant["serve_phase"] in SERVING_PHASES:
                raise HandoffState("tenant is serving; nothing to undo")
            if tenant["serve_phase"] == "handed_over":
                raise TenantHandedOver(
                    "takeover receipt already produced; origin has permanently "
                    "lost serving rights")
            row = self._require_open_outgoing(tenant_id)
            if row["state"] not in ("draining", "exported"):
                raise HandoffState(
                    f"transfer is {row['state']}; undo is not permitted")
            self.db.execute("BEGIN IMMEDIATE")
            committed = False
            try:
                self.db.execute(
                    "UPDATE tenants SET serve_phase='serving' WHERE tenant_id=?",
                    (tenant_id,))
                self.db.execute(
                    "UPDATE transfers SET state='undrained', updated_at=? "
                    "WHERE transfer_id=?", (utcnow(), row["transfer_id"]))
                self._event("handoff_undrained", tenant_id=tenant_id,
                            detail={"transfer_id": row["transfer_id"],
                                    "from_state": row["state"]})
                self.db.execute("COMMIT")
                committed = True
            except Exception:
                if not committed:
                    self.db.execute("ROLLBACK")
                raise
            row = self._get_transfer_row(row["transfer_id"])
            return self._transfer_view(row, self._reload_tenant(tenant_id))

    def finalize_handoff(self, receipt: dict) -> dict:
        """原节点登记接管回执：原节点永久失去服务权。"""
        with self._lock:
            parsed = self._verify_receipt(receipt)
            transfer_id = parsed["transfer_id"]
            row = self._get_transfer_row(transfer_id)
            if row is None or row["direction"] != "outgoing":
                raise HandoffWrongIdentity(
                    "receipt does not correspond to an outgoing transfer of "
                    "this node")
            tenant = self._require_tenant_id(row["tenant_id"])
            manifest = json.loads(row["manifest_json"]) if row["manifest_json"] \
                and row["manifest_json"] != "{}" else None
            if manifest is None:
                raise HandoffWrongIdentity("transfer has no sealed manifest")
            if parsed["manifest_digest"] != row["manifest_digest"] or \
                    parsed["manifest_digest"] != manifest["manifest_digest"]:
                raise HandoffWrongIdentity(
                    "receipt is bound to a different manifest digest")
            if parsed["origin_instance"] != self.node_id:
                raise HandoffWrongIdentity(
                    "receipt origin instance is not this node")
            if parsed["tenant_id"] != row["tenant_id"] or \
                    parsed["handoff_epoch"] != int(row["handoff_epoch"]):
                raise HandoffWrongIdentity(
                    "receipt tenant/epoch do not match the sealed transfer")
            if row["state"] == "finalized":
                # 同一回执重复登记幂等，返回首次结果
                return self._transfer_view(row, tenant, idempotent=True)
            if row["state"] != "exported":
                raise HandoffState(
                    f"transfer is {row['state']}, not exported; cannot finalize")
            self.db.execute("BEGIN IMMEDIATE")
            committed = False
            try:
                self.db.execute(
                    "UPDATE tenants SET serve_phase='handed_over' "
                    "WHERE tenant_id=?", (row["tenant_id"],))
                self.db.execute(
                    "UPDATE transfers SET state='finalized', receipt_json=?, "
                    "node_id=?, updated_at=? WHERE transfer_id=?",
                    (dumps_canon(parsed), parsed["receiver_instance"],
                     utcnow(), transfer_id))
                self._event("handoff_finalized", tenant_id=row["tenant_id"],
                            detail={"transfer_id": transfer_id,
                                    "handoff_epoch": parsed["handoff_epoch"],
                                    "receiver_instance":
                                        parsed["receiver_instance"]})
                self.db.execute("COMMIT")
                committed = True
            except Exception:
                if not committed:
                    self.db.execute("ROLLBACK")
                raise
            row = self._get_transfer_row(transfer_id)
            return self._transfer_view(row, self._reload_tenant(row["tenant_id"]))

    # ------------------------------------------------------------------ #
    # receiver side: import / confirm
    # ------------------------------------------------------------------ #

    def import_handoff(self, manifest: dict) -> dict:
        """校验并原样恢复一份签名 transfer manifest。

        相同清单再次导入返回首次结果；旧代次、内容篡改、日志落后或分叉、
        同名消费方仍在服务、并发导入一律失败。
        """
        with self._lock:
            parsed = self._verify_manifest(manifest)
            transfer_id = parsed["transfer_id"]
            tid = parsed["tenant"]["tenant_id"]
            epoch = int(parsed["handoff_epoch"])

            existing = self._get_transfer_row(transfer_id)
            if existing is not None:
                if existing["direction"] != "incoming":
                    raise HandoffWrongIdentity(
                        "transfer id collides with a transfer of different role")
                # 相同清单导入：无论后续是否已确认，永远返回首次导入结果
                result = json.loads(existing["result_json"]) if existing["result_json"] \
                    else self._transfer_view(existing, self._reload_tenant(tid))
                result["idempotent"] = True
                return result

            self._verify_log_anchor(parsed)
            self._verify_pending_windows(parsed)
            tenant_row = self.db.execute(
                "SELECT * FROM tenants WHERE tenant_id=?", (tid,)).fetchone()
            self._verify_name_slot(tenant_row, parsed, epoch)

            result = self._commit_import(parsed, tenant_row)
            result["idempotent"] = False
            return result

    def confirm_handoff(self, transfer_id: str) -> dict:
        """接收方确认接管：换发新租户令牌并产生签名接管回执。"""
        with self._lock:
            row = self._get_transfer_row(transfer_id)
            if row is None or row["direction"] != "incoming":
                raise TransferNotFound(f"incoming transfer {transfer_id} not found")
            if row["state"] == "confirmed":
                tenant = self._reload_tenant(row["tenant_id"])
                return {"transfer_id": transfer_id,
                        "tenant_id": row["tenant_id"], "state": "confirmed",
                        "phase": tenant["serve_phase"], "idempotent": True,
                        "receipt": json.loads(row["receipt_json"]),
                        "note": "new tenant token is shown only once and cannot "
                                "be displayed again"}
            if row["state"] != "imported":
                raise HandoffState(
                    f"transfer is {row['state']}, not imported; cannot confirm")
            tenant = self._require_tenant_id(row["tenant_id"])
            if tenant["serve_phase"] != "incoming":
                raise HandoffState(
                    f"tenant phase is {tenant['serve_phase']}; cannot confirm")
            manifest = json.loads(row["manifest_json"])
            plain = "dprt_" + pysecrets.token_urlsafe(24)
            receipt = self._build_receipt(manifest, row)
            self.db.execute("BEGIN IMMEDIATE")
            committed = False
            try:
                self.db.execute(
                    "UPDATE tenants SET serve_phase='adopted', token_sha256=? "
                    "WHERE tenant_id=?", (token_hash(plain), row["tenant_id"]))
                self.db.execute(
                    "UPDATE transfers SET state='confirmed', receipt_json=?, "
                    "updated_at=? WHERE transfer_id=?",
                    (dumps_canon(receipt), utcnow(), transfer_id))
                self._event("handoff_confirmed", tenant_id=row["tenant_id"],
                            detail={"transfer_id": transfer_id,
                                    "handoff_epoch": row["handoff_epoch"],
                                    "origin_instance":
                                        manifest["origin_instance"]})
                self.db.execute("COMMIT")
                committed = True
            except Exception:
                if not committed:
                    self.db.execute("ROLLBACK")
                raise
            return {"transfer_id": transfer_id, "tenant_id": row["tenant_id"],
                    "state": "confirmed", "phase": "adopted",
                    "idempotent": False, "token": plain,
                    "note": "new tenant token shown only once",
                    "receipt": receipt}

    # ------------------------------------------------------------------ #
    # manifest / receipt construction and verification
    # ------------------------------------------------------------------ #

    def _build_manifest(self, tenant: sqlite3.Row,
                        transfer_row: sqlite3.Row) -> dict:
        trusted = int(self._state_row()["trusted_tree_size"])
        cp_row = self.db.execute(
            "SELECT checkpoint_json FROM mirror_cps WHERE tree_size=?",
            (trusted,)).fetchone()
        if cp_row is None:
            raise HandoffBadManifest(
                f"no archived signed checkpoint at trusted size {trusted}")
        checkpoint = json.loads(cp_row["checkpoint_json"])
        root_row = self.db.execute(
            "SELECT root_hash FROM mirror_cps WHERE tree_size=?",
            (trusted,)).fetchone()

        pending = self.db.execute(
            "SELECT * FROM deliveries WHERE tenant_id=? AND end_index > ? "
            "ORDER BY seq", (tenant["tenant_id"], tenant["cursor_end"])).fetchall()
        windows = []
        for r in pending:
            packet = json.loads(r["packet_json"])
            windows.append({
                "delivery_id": r["delivery_id"],
                "seq": int(r["seq"]),
                "start_index": int(r["start_index"]),
                "end_index": int(r["end_index"]),
                "state": r["state"],          # leased | completed（完成标记封存）
                "lease_owner": r["lease_owner"],
                "lease_epoch": int(r["lease_epoch"]),
                "lease_count": int(r["lease_count"]),     # 尝试次数
                "lease_expires_epoch": float(r["lease_expires_at"])
                    if r["lease_expires_at"] is not None else None,
                "lease_token": r["lease_token"],
                "completed_at": r["completed_at"],
                "packet": packet,
            })
        epoch = int(tenant["handoff_epoch"]) + 1
        rule = json.loads(tenant["filter_json"])
        body = {
            "manifest_version": MANIFEST_VERSION,
            "transfer_id": transfer_row["transfer_id"],
            "handoff_epoch": epoch,
            "tenant": {
                "tenant_id": tenant["tenant_id"],
                "name": tenant["name"],
                "filter": rule,
                "token_sha256": tenant["token_sha256"],
                "cursor_end": int(tenant["cursor_end"]),
                "max_inflight": int(tenant["max_inflight"]),
                "filter_locked": bool(tenant["filter_locked"]),
            },
            "log_anchor": {
                "tree_size": trusted,
                "root_hash": root_row["root_hash"],
                "checkpoint": checkpoint,
            },
            "windows": windows,
            "origin_instance": self.node_id,
            "exported_at": utcnow(),
        }
        body["manifest_digest"] = _sealed_digest(body)
        body["sig"] = hmac_hex(
            self.handoff_key,
            dumps_canon({k: v for k, v in body.items() if k != "sig"})
            .encode("utf-8"))
        return body

    def _verify_manifest(self, manifest: Any) -> dict:
        if not isinstance(manifest, dict):
            raise HandoffBadManifest("manifest must be an object")
        if manifest.get("manifest_version") != MANIFEST_VERSION:
            raise HandoffBadManifest("unsupported manifest_version")
        sig = manifest.get("sig")
        expect_sig = hmac_hex(
            self.handoff_key,
            dumps_canon({k: v for k, v in manifest.items() if k != "sig"})
            .encode("utf-8"))
        if not isinstance(sig, str) or not _consteq(sig, expect_sig):
            raise HandoffBadManifest("manifest signature invalid (tampered or "
                                     "signed by a different trust domain)")
        if not isinstance(manifest.get("manifest_digest"), str) or \
                not _consteq(manifest["manifest_digest"], _sealed_digest(manifest)):
            raise HandoffBadManifest("manifest sealed digest does not reproduce")
        for field in ("transfer_id", "handoff_epoch"):
            if not isinstance(manifest.get(field), str if field == "transfer_id"
                              else int):
                raise HandoffBadManifest(f"manifest.{field} malformed")
        if not isinstance(manifest.get("origin_instance"), str):
            raise HandoffBadManifest("manifest.origin_instance required")
        tenant = manifest.get("tenant")
        if not isinstance(tenant, dict) or not isinstance(
                tenant.get("tenant_id"), str) or not tenant["tenant_id"]:
            raise HandoffBadManifest("manifest.tenant.tenant_id required")
        if not isinstance(tenant.get("cursor_end"), int) \
                or tenant["cursor_end"] < 0:
            raise HandoffBadManifest("manifest.tenant.cursor_end malformed")
        if not isinstance(tenant.get("token_sha256"), str):
            raise HandoffBadManifest("manifest.tenant.token_sha256 required")
        if not isinstance(manifest.get("windows"), list):
            raise HandoffBadManifest("manifest.windows must be a list")
        anchor = manifest.get("log_anchor")
        if not isinstance(anchor, dict):
            raise HandoffBadManifest("manifest.log_anchor required")
        return manifest

    def _verify_log_anchor(self, manifest: dict) -> None:
        anchor = manifest["log_anchor"]
        cp = anchor.get("checkpoint")
        report = _verify_checkpoint(cp, self.handoff_key)
        if not report["ok"]:
            raise HandoffBadManifest("anchor " + "; ".join(report["errors"]))
        size, root = anchor.get("tree_size"), anchor.get("root_hash")
        if not isinstance(size, int) or size < 0 or cp.get("tree_size") != size \
                or cp.get("root_hash") != root:
            raise HandoffBadManifest("anchor size/root disagree with checkpoint")
        local = int(self._state_row()["trusted_tree_size"])
        if local < size:
            raise HandoffLogBehind(
                f"local transparency log at {local} does not contain the "
                f"manifest's trusted tree head at {size}; sync before import",
                detail={"local_tree_size": local, "anchor_tree_size": size})
        local_row = self.db.execute(
            "SELECT root_hash FROM mirror_cps WHERE tree_size=?",
            (size,)).fetchone()
        if local_row is None or local_row["root_hash"] != root:
            local_root = local_row["root_hash"] if local_row else None
            raise HandoffLogForked(
                f"local log at size {size} has root {local_root}, manifest "
                f"anchors {root}; histories diverged",
                detail={"tree_size": size, "local_root": local_root,
                        "anchor_root": root})

    def _verify_pending_windows(self, manifest: dict) -> None:
        """校验未决区间边界连续、完成标记/尝试次数完整，且每个区间的包都能
        用机构 transparency 锚独立折到本节点已存档的同一树头（防内容篡改）。"""
        tid = manifest["tenant"]["tenant_id"]
        cursor = int(manifest["tenant"]["cursor_end"])
        anchor_size = int(manifest["log_anchor"]["tree_size"])
        pos = cursor
        prev_seq = None
        for i, w in enumerate(manifest["windows"]):
            if not isinstance(w, dict):
                raise HandoffBadManifest(f"window {i} malformed")
            try:
                seq = int(w["seq"]); start = int(w["start_index"])
                end = int(w["end_index"]); state = w["state"]
            except (KeyError, TypeError, ValueError):
                raise HandoffBadManifest(f"window {i} indices malformed")
            if start != pos:
                raise HandoffBadManifest(
                    f"window {i} boundary gap: expected start {pos}, got {start}")
            if end <= start:
                raise HandoffBadManifest(f"window {i} has empty range")
            if prev_seq is not None and seq != prev_seq + 1:
                raise HandoffBadManifest(
                    f"window seq not dense: {prev_seq} -> {seq}")
            prev_seq = seq
            if state not in ("leased", "completed"):
                raise HandoffBadManifest(
                    f"window {i} state {state!r} is not a pending state")
            if not isinstance(w.get("lease_count"), int) \
                    or int(w["lease_count"]) < 1 \
                    or int(w.get("lease_epoch", 0)) < 1:
                raise HandoffBadManifest(f"window {i} attempts/epoch malformed")
            if state == "leased":
                for field in ("lease_owner", "lease_token", "lease_expires_epoch"):
                    if w.get(field) is None:
                        raise HandoffBadManifest(
                            f"window {i} leased but missing {field}")
            packet = w.get("packet")
            if not isinstance(packet, dict):
                raise HandoffBadManifest(f"window {i} packet missing")
            if packet.get("tenant_id") != tid \
                    or packet.get("delivery_id") != w.get("delivery_id") \
                    or int(packet.get("seq", -1)) != seq \
                    or int(packet.get("start_index", -1)) != start \
                    or int(packet.get("end_index", -1)) != end:
                raise HandoffBadManifest(
                    f"window {i} packet header does not match sealed boundaries")
            self._verify_packet_anchor(packet, anchor_size, i)
            pos = end

    def _verify_packet_anchor(self, packet: dict, anchor_size: int,
                               index: int) -> None:
        cp = packet.get("checkpoint")
        report = _verify_checkpoint(cp, self.handoff_key)
        if not report["ok"]:
            raise HandoffBadManifest(
                f"window {index} anchor: " + "; ".join(report["errors"]))
        end = int(packet["end_index"])
        if end > anchor_size:
            raise HandoffBadManifest(
                f"window {index} anchored beyond the manifest tree head")
        local = self.db.execute(
            "SELECT root_hash FROM mirror_cps WHERE tree_size=?",
            (end,)).fetchone()
        if local is None or local["root_hash"] != cp["root_hash"]:
            raise HandoffLogForked(
                f"window {index} root at size {end} diverges from local log",
                detail={"tree_size": end,
                        "local_root": local["root_hash"] if local else None,
                        "packet_root": cp["root_hash"]})
        root = bytes.fromhex(cp["root_hash"])
        for r in packet.get("records", []):
            try:
                idx = int(r["leaf_index"])
                if envelope_leaf_hash(r["envelope"]) != r["leaf_hash"]:
                    raise HandoffBadManifest(
                        f"window {index} leaf {idx}: content address mismatch")
                path = [bytes.fromhex(h) for h in r.get("inclusion_path", [])]
                if not verify_inclusion(root, bytes.fromhex(r["leaf_hash"]),
                                        idx, end, path):
                    raise HandoffBadManifest(
                        f"window {index} leaf {idx}: inclusion fold to the "
                        "anchored root failed")
            except KeyError as exc:
                raise HandoffBadManifest(
                    f"window {index} record malformed: {exc}")

    def _build_receipt(self, manifest: dict,
                       transfer_row: sqlite3.Row) -> dict:
        body = {
            "receipt_version": RECEIPT_VERSION,
            "transfer_id": transfer_row["transfer_id"],
            "tenant_id": manifest["tenant"]["tenant_id"],
            "handoff_epoch": int(transfer_row["handoff_epoch"]),
            "manifest_digest": manifest["manifest_digest"],
            "log_anchor": {
                "tree_size": manifest["log_anchor"]["tree_size"],
                "root_hash": manifest["log_anchor"]["root_hash"],
            },
            "origin_instance": manifest["origin_instance"],
            "receiver_instance": self.node_id,
            "adopted_at": utcnow(),
        }
        body["sig"] = hmac_hex(
            self.handoff_key,
            dumps_canon({k: v for k, v in body.items() if k != "sig"})
            .encode("utf-8"))
        return body

    def _verify_receipt(self, receipt: Any) -> dict:
        if not isinstance(receipt, dict):
            raise HandoffBadManifest("receipt must be an object")
        if receipt.get("receipt_version") != RECEIPT_VERSION:
            raise HandoffBadManifest("unsupported receipt_version")
        sig = receipt.get("sig")
        expect = hmac_hex(
            self.handoff_key,
            dumps_canon({k: v for k, v in receipt.items() if k != "sig"})
            .encode("utf-8"))
        if not isinstance(sig, str) or not _consteq(sig, expect):
            raise HandoffBadManifest("receipt signature invalid")
        for field in ("transfer_id", "tenant_id", "manifest_digest",
                      "origin_instance", "receiver_instance"):
            if not isinstance(receipt.get(field), str):
                raise HandoffBadManifest(f"receipt.{field} required")
        if not isinstance(receipt.get("handoff_epoch"), int):
            raise HandoffBadManifest("receipt.handoff_epoch required")
        return receipt

    # ------------------------------------------------------------------ #
    # import commit / conflict checks
    # ------------------------------------------------------------------ #

    def _verify_name_slot(self, tenant_row: sqlite3.Row | None,
                           manifest: dict, epoch: int) -> None:
        tid = manifest["tenant"]["tenant_id"]
        name = manifest["tenant"]["name"]
        if tenant_row is None:
            clash = self.db.execute(
                "SELECT tenant_id, serve_phase FROM tenants WHERE name=? "
                "AND serve_phase != 'handed_over'", (name,)).fetchall()
            if clash:
                raise HandoffTenantExists(
                    f"a live consumer named {name!r} already exists",
                    detail={"name": name,
                            "tenant_id": clash[0]["tenant_id"],
                            "phase": clash[0]["serve_phase"]})
            return
        phase = tenant_row["serve_phase"]
        if phase == "handed_over":
            # 同租户回迁：代次必须严格更新，且不能有未决转移
            if epoch <= int(tenant_row["handoff_epoch"]):
                raise HandoffStaleEpoch(
                    f"manifest epoch {epoch} is not newer than last adopted "
                    f"epoch {int(tenant_row['handoff_epoch'])}",
                    detail={"manifest_epoch": epoch,
                            "current_epoch": int(tenant_row["handoff_epoch"])})
            open_row = self._open_transfer(tid)
            if open_row is not None:
                raise HandoffConcurrent(
                    "an open transfer exists for this tenant",
                    detail={"transfer_id": open_row["transfer_id"],
                            "state": open_row["state"]})
            return
        if phase == "incoming":
            # 同一待确认导入的更低代次：旧代次；同代次不同清单：并发串用
            if epoch < int(tenant_row["handoff_epoch"]):
                raise HandoffStaleEpoch(
                    f"manifest epoch {epoch} is older than the pending import "
                    f"epoch {int(tenant_row['handoff_epoch'])}",
                    detail={"manifest_epoch": epoch,
                            "current_epoch": int(tenant_row["handoff_epoch"])})
            raise HandoffConcurrent(
                "another import for this tenant is in progress")
        if phase in SERVING_PHASES:
            if epoch <= int(tenant_row["handoff_epoch"]):
                raise HandoffStaleEpoch(
                    f"manifest epoch {epoch} is not newer than the epoch "
                    f"{int(tenant_row['handoff_epoch'])} already serving here",
                    detail={"manifest_epoch": epoch,
                            "current_epoch": int(tenant_row["handoff_epoch"])})
            raise HandoffTenantExists(
                f"consumer {tid} is already serving on this node",
                detail={"tenant_id": tid, "phase": phase})
        raise HandoffConcurrent(
            f"tenant is in phase {phase}; cannot import concurrently",
            detail={"tenant_id": tid, "phase": phase})

    def _commit_import(self, manifest: dict,
                        tenant_row: sqlite3.Row | None) -> dict:
        tid = manifest["tenant"]["tenant_id"]
        t = manifest["tenant"]
        epoch = int(manifest["handoff_epoch"])
        windows = manifest["windows"]
        self.db.execute("BEGIN IMMEDIATE")
        committed = False
        try:
            if tenant_row is None:
                self.db.execute(
                    """INSERT INTO tenants
                       (tenant_id, name, token_sha256, filter_json, active,
                        cursor_end, max_inflight, filter_locked, serve_phase,
                        handoff_epoch, created_at)
                       VALUES (?,?,?,?,1,?,?,?, 'incoming', ?, ?)""",
                    (tid, t["name"], t["token_sha256"],
                     dumps_canon(t["filter"]), t["cursor_end"],
                     int(t["max_inflight"]), 1 if t["filter_locked"] else 0,
                     epoch, utcnow()))
            else:
                # 回迁：旧实例上的窗口历史全部位于旧已确认前缀之前，以新清单
                # 为唯一权威，清空后原样恢复
                self.db.execute("DELETE FROM deliveries WHERE tenant_id=?", (tid,))
                self.db.execute(
                    """UPDATE tenants SET name=?, token_sha256=?, filter_json=?,
                       cursor_end=?, max_inflight=?, filter_locked=?,
                       serve_phase='incoming', handoff_epoch=?, disabled_at=NULL,
                       disable_reason=NULL, active=1 WHERE tenant_id=?""",
                    (t["name"], t["token_sha256"], dumps_canon(t["filter"]),
                     t["cursor_end"], int(t["max_inflight"]),
                     1 if t["filter_locked"] else 0, epoch, tid))
            self._restore_windows(manifest)
            self.db.execute(
                """INSERT INTO transfers
                   (transfer_id, tenant_id, direction, state, handoff_epoch,
                    manifest_json, manifest_digest, node_id, created_at,
                    updated_at)
                   VALUES (?,?, 'incoming','imported', ?, ?, ?, ?, ?, ?)""",
                (manifest["transfer_id"], tid, epoch,
                 dumps_canon(manifest), manifest["manifest_digest"],
                 manifest["origin_instance"], utcnow(), utcnow()))
            self._event("handoff_imported", tenant_id=tid,
                        detail={"transfer_id": manifest["transfer_id"],
                                "handoff_epoch": epoch,
                                "origin_instance": manifest["origin_instance"],
                                "anchor": manifest["log_anchor"]["tree_size"],
                                "pending_windows": len(windows)})
            self.db.execute("COMMIT")
            committed = True
        except Exception:
            if not committed:
                self.db.execute("ROLLBACK")
            raise
        row = self._get_transfer_row(manifest["transfer_id"])
        view = self._transfer_view(row, self._reload_tenant(tid))
        # 首次结果落库，保证相同清单再导入逐字段重放
        self.db.execute("UPDATE transfers SET result_json=? WHERE transfer_id=?",
                        (dumps_canon(view), manifest["transfer_id"]))
        return view

    def _restore_windows(self, manifest: dict) -> None:
        tid = manifest["tenant"]["tenant_id"]
        now = utcnow()
        for w in manifest["windows"]:
            packet = w["packet"]
            self.db.execute(
                """INSERT INTO deliveries
                   (delivery_id, tenant_id, seq, start_index, end_index,
                    packet_json, state, lease_owner, lease_expires_at,
                    lease_count, lease_epoch, lease_token, created_at,
                    last_leased_at, completed_at, committed_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)""",
                (w["delivery_id"], tid, int(w["seq"]), int(w["start_index"]),
                 int(w["end_index"]), dumps_canon(packet), w["state"],
                 w.get("lease_owner"),
                 str(w["lease_expires_epoch"])
                     if w.get("lease_expires_epoch") is not None else None,
                 int(w["lease_count"]), int(w["lease_epoch"]),
                 w.get("lease_token"), now, now, w.get("completed_at")))

    # ------------------------------------------------------------------ #
    # recovery after a crash during prepare/export/import/confirm
    # ------------------------------------------------------------------ #

    def recover_handoffs(self) -> dict:
        """重启恢复：未决转移的各阶段本身都不对外服务，这里只做不变量核对与
        可观察记录。结果必然是“原节点继续”（draining 可撤销）或“新节点接管”
        （imported 待确认），不会出现双主。"""
        with self._lock:
            rows = self.db.execute(
                "SELECT * FROM transfers WHERE state IN "
                "('draining','exported','imported') ORDER BY rowid").fetchall()
            recovered = []
            for row in rows:
                tenant = self._reload_tenant(row["tenant_id"])
                want_phase = {"draining": "draining", "exported": "exported",
                              "imported": "incoming"}[row["state"]]
                if tenant is None or tenant["serve_phase"] != want_phase:
                    # 不变量被破坏：宁可继续拒绝服务也不能双主
                    self._event("handoff_recover_inconsistent",
                                tenant_id=row["tenant_id"],
                                detail={"transfer_id": row["transfer_id"],
                                        "state": row["state"],
                                        "tenant_phase":
                                            None if tenant is None
                                            else tenant["serve_phase"],
                                        "expected_phase": want_phase})
                else:
                    self._event("handoff_recovered",
                                tenant_id=row["tenant_id"],
                                detail={"transfer_id": row["transfer_id"],
                                        "state": row["state"],
                                        "direction": row["direction"]})
                recovered.append({"transfer_id": row["transfer_id"],
                                  "tenant_id": row["tenant_id"],
                                  "state": row["state"],
                                  "direction": row["direction"],
                                  "phase": want_phase})
            return {"node_id": self.node_id, "open_transfers": recovered}

    # ------------------------------------------------------------------ #
    # phase gating used by claim / complete
    # ------------------------------------------------------------------ #

    def _gate_claim_phase(self, tenant: sqlite3.Row) -> None:
        phase = tenant["serve_phase"]
        if phase in SERVING_PHASES:
            return
        if phase == "draining":
            raise TenantDraining(
                "tenant is draining for a cross-node handoff; no new windows "
                "are assigned; existing short leases finish naturally")
        if phase == "exported" or phase == "incoming":
            raise HandoffSealed(
                "transfer manifest is sealed; pre-transfer credentials cannot "
                "obtain windows on either side")
        if phase == "handed_over":
            raise TenantHandedOver(
                "consumer ownership has moved with the takeover receipt")

    def _gate_complete_phase(self, tenant: sqlite3.Row) -> None:
        phase = tenant["serve_phase"]
        if phase in SERVING_PHASES or phase == "draining":
            return
        if phase == "exported" or phase == "incoming":
            raise HandoffSealed(
                "transfer manifest is sealed; pre-transfer credentials cannot "
                "move the confirmed prefix on either side")
        if phase == "handed_over":
            raise TenantHandedOver(
                "consumer ownership has moved with the takeover receipt")

    # ------------------------------------------------------------------ #
    # views / helpers
    # ------------------------------------------------------------------ #

    def list_transfers(self, *, tenant_id: str | None = None) -> list[dict]:
        with self._lock:
            if tenant_id:
                rows = self.db.execute(
                    "SELECT * FROM transfers WHERE tenant_id=? ORDER BY rowid",
                    (tenant_id,)).fetchall()
            else:
                rows = self.db.execute(
                    "SELECT * FROM transfers ORDER BY rowid DESC").fetchall()
            return [self._transfer_view(r) for r in rows]

    def get_transfer(self, transfer_id: str) -> dict:
        with self._lock:
            row = self._get_transfer_row(transfer_id)
            if row is None:
                raise TransferNotFound(f"transfer {transfer_id} not found")
            return self._transfer_view(row)

    def _get_transfer_row(self, transfer_id: str) -> sqlite3.Row | None:
        return self.db.execute(
            "SELECT * FROM transfers WHERE transfer_id=?",
            (transfer_id,)).fetchone()

    def _open_transfer(self, tenant_id: str) -> sqlite3.Row | None:
        return self.db.execute(
            "SELECT * FROM transfers WHERE tenant_id=? AND state IN "
            "('draining','exported','imported') ORDER BY rowid",
            (tenant_id,)).fetchone()

    def _require_open_outgoing(self, tenant_id: str) -> sqlite3.Row:
        row = self.db.execute(
            "SELECT * FROM transfers WHERE tenant_id=? AND direction='outgoing' "
            "ORDER BY rowid DESC LIMIT 1", (tenant_id,)).fetchone()
        if row is None:
            raise HandoffState(
                "no prepared transfer for this tenant; call prepare first")
        return row

    def _require_serving_for_handoff(self, tenant: sqlite3.Row) -> None:
        phase = tenant["serve_phase"]
        if phase in SERVING_PHASES:
            return
        if phase == "draining":
            return
        if phase == "exported":
            raise HandoffState("transfer already exported; undo or finalize it")
        if phase == "incoming":
            raise HandoffState("node is the takeover receiver for this tenant")
        if phase == "handed_over":
            raise TenantHandedOver("tenant already handed over to another node")

    def _reload_tenant(self, tenant_id: str) -> sqlite3.Row:
        return self.db.execute(
            "SELECT * FROM tenants WHERE tenant_id=?", (tenant_id,)).fetchone()

    def _anchor_brief(self, manifest: dict | None) -> dict | None:
        if not manifest:
            return None
        anchor = manifest.get("log_anchor") or {}
        return {"tree_size": anchor.get("tree_size"),
                "root_hash": anchor.get("root_hash")}

    def _transfer_view(self, row: sqlite3.Row,
                        tenant: sqlite3.Row | None = None, *,
                        idempotent: bool = False) -> dict:
        manifest = None
        if row["manifest_json"] and row["manifest_json"] != "{}":
            try:
                manifest = json.loads(row["manifest_json"])
            except json.JSONDecodeError:
                manifest = None
        if tenant is None:
            tenant = self._reload_tenant(row["tenant_id"])
        pending = []
        if manifest is not None:
            for w in manifest.get("windows", []):
                pending.append({
                    "delivery_id": w["delivery_id"], "seq": w["seq"],
                    "start_index": w["start_index"], "end_index": w["end_index"],
                    "state": w["state"], "lease_owner": w.get("lease_owner"),
                    "lease_epoch": w.get("lease_epoch"),
                    "lease_count": w.get("lease_count"),
                    "retries": (int(w["lease_count"]) - 1)
                        if w.get("lease_count") else None,
                    "completed_at": w.get("completed_at"),
                })
        phase = tenant["serve_phase"] if tenant is not None else None
        return {
            "transfer_id": row["transfer_id"],
            "tenant_id": row["tenant_id"],
            "direction": row["direction"],
            "state": row["state"],
            "phase": phase,
            "handoff_epoch": int(row["handoff_epoch"]),
            "origin_instance": manifest["origin_instance"] if manifest else
                (row["node_id"] if row["direction"] == "incoming" else
                 self.node_id),
            "receiver_instance": json.loads(row["receipt_json"])[
                "receiver_instance"] if row["receipt_json"] else
                (self.node_id if row["direction"] == "incoming" else None),
            "node_id": self.node_id,
            "log_anchor": self._anchor_brief(manifest),
            "confirmed_prefix": manifest["tenant"]["cursor_end"]
                if manifest else (int(tenant["cursor_end"]) if tenant else None),
            "pending_windows": pending,
            "rejected_reason": row["rejected_reason"],
            "receipt": json.loads(row["receipt_json"]) if row["receipt_json"]
                else None,
            "idempotent": idempotent,
            "updated_at": row["updated_at"],
        }


def _consteq(a: str, b: str) -> bool:
    import hmac as _hmac
    return _hmac.compare_digest(a or "", b or "")
