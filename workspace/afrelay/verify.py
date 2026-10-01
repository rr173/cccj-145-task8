"""离线投递包 / 转移清单 / 接管回执校验器（无需中继进程）。

审计租户拿到 afp1 投递包文件、跨节点转移的 aft1 清单或 aftr1 接管回执，加上
中继的 secrets.json（或显式密钥材料）即可独立复核。

* afp1 包级 HMAC、delivery_id 确定性重算、叶内容地址、锚 checkpoint 签名、
  每条 inclusion_path 折到已签名根、区间连续与记录边界；
* aft1 转移清单：机构 transparency 密钥的 HMAC、封存摘要、筛选条件/已确认
  前缀/未决区间边界/完成标记/尝试次数一致性、每个未决区间锚 checkpoint 与
  叶证明；
* aftr1 接管回执：HMAC、与清单摘要/双方实例/代次绑定。

退出码：0=有效；2=验签/折根失败；3=参数/文件错误。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

from .canonical import dumps_canon, hmac_hex
from .merkle import (
    EMPTY_HASH,
    envelope_leaf_hash,
    merkle_root,
    verify_inclusion,
)

CHECKPOINT_VERSION = "tc1"


def load_relay_keys(secrets_path: str) -> dict:
    """接受 secrets.json 文件路径或 relay home 目录。"""
    if os.path.isdir(secrets_path):
        secrets_path = os.path.join(secrets_path, "secrets.json")
    with open(secrets_path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    out: dict[str, bytes] = {
        "relay_packet_secret": bytes.fromhex(raw["relay_packet_secret"])}
    if raw.get("transparency_secret"):
        out["transparency_secret"] = bytes.fromhex(raw["transparency_secret"])
    return out


def verify_packet(packet: dict, keys: dict, *,
                  expected_tenant: str | None = None) -> dict:
    errors: list[str] = []
    checks: dict[str, Any] = {}

    if not isinstance(packet, dict):
        return {"ok": False, "errors": ["packet must be an object"],
                "checks": {}}

    packet_key = keys.get("relay_packet_secret")
    if packet_key is None:
        return {"ok": False, "errors": ["missing relay_packet_secret"],
                "checks": {}}

    # ---- 1) packet envelope HMAC ----
    sig = packet.get("sig")
    expect_sig = hmac_hex(
        packet_key,
        dumps_canon({k: v for k, v in packet.items() if k != "sig"})
        .encode("utf-8"))
    checks["packet_signature"] = isinstance(sig, str) and \
        hmac.compare_digest(sig or "", expect_sig)
    if not checks["packet_signature"]:
        errors.append("packet HMAC invalid (content tampered or wrong key)")

    if packet.get("packet_version") != "afp1":
        errors.append("unsupported packet_version")
    tenant = packet.get("tenant_id")
    if expected_tenant is not None and tenant != expected_tenant:
        errors.append(f"packet tenant {tenant!r} != expected {expected_tenant!r}")

    start, end, seq = packet.get("start_index"), packet.get("end_index"), \
        packet.get("seq")
    records = packet.get("records", [])
    leaf_hashes = packet.get("leaf_hashes", [])
    cp = packet.get("checkpoint", {})

    # ---- 2) anchor checkpoint signature (gateway transparency key) ----
    cp_report = _verify_checkpoint(cp, keys.get("transparency_secret"))
    checks["checkpoint_signature"] = cp_report["ok"]
    errors.extend("checkpoint: " + e for e in cp_report["errors"])

    # ---- 3) structural continuity ----
    if not isinstance(records, list) or not records:
        errors.append("packet must carry a non-empty records list")
        records = []
    if not isinstance(start, int) or not isinstance(end, int) \
            or not isinstance(seq, int) or start < 0 or end <= start:
        errors.append("packet indices malformed (require 0 <= start < end)")
    elif records:
        indices = [r.get("leaf_index") for r in records]
        if indices != sorted(indices) or len(set(indices)) != len(indices):
            errors.append("record leaf_index values are not strictly increasing")
        if indices[0] < start or indices[-1] >= end:
            errors.append("record indices fall outside [start_index, end_index)")
        if len(leaf_hashes) != len(records):
            errors.append("leaf_hashes length does not match records")
        else:
            for r, lh in zip(records, leaf_hashes):
                if r.get("leaf_hash") != lh:
                    errors.append(
                        f"leaf {r.get('leaf_index')}: leaf_hashes row mismatch")

    # ---- 4) delivery_id determinism ----
    want_did = "afd_" + hmac_hex(
        packet_key,
        dumps_canon({"tenant_id": tenant, "seq": seq, "start_index": start,
                     "end_index": end, "leaf_hashes": leaf_hashes})
        .encode("utf-8"))[:32]
    checks["delivery_id"] = packet.get("delivery_id") == want_did
    if not checks["delivery_id"]:
        errors.append("delivery_id does not reproduce from packet contents")

    # ---- 5) anchor root + per-leaf content address + inclusion folds ----
    if cp_report["ok"]:
        cp_end = cp["tree_size"]
        if cp_end != end:
            errors.append(f"checkpoint tree_size {cp_end} != end_index {end}")
        root_hex = cp["root_hash"]

        dense_root = None
        # records embed their subtree fold at tree_size=end: we cannot rebuild
        # skipped leaves, but every record's own path must fold to the signed
        # root using its sibling hashes.
        for r in records:
            try:
                idx = int(r["leaf_index"])
                size = int(r["tree_size"])
                lh = envelope_leaf_hash(r["envelope"])
                if lh != r["leaf_hash"]:
                    errors.append(
                        f"leaf {idx}: content address mismatch")
                if r["envelope"].get("event_key") != r.get("event_key") or \
                        r["envelope"].get("event_type") != r.get("event_type"):
                    errors.append(f"leaf {idx}: event binding mismatch")
                if size != end or r.get("root_hash") != root_hex:
                    errors.append(
                        f"leaf {idx}: anchor size/root mismatch")
                path = [bytes.fromhex(h) for h in r.get("inclusion_path", [])]
                if not verify_inclusion(bytes.fromhex(root_hex),
                                        bytes.fromhex(r["leaf_hash"]),
                                        idx, end, path):
                    errors.append(
                        f"leaf {idx}: inclusion path does not fold to root")
            except (KeyError, TypeError, ValueError) as exc:
                errors.append(f"record malformed: {exc}")

        # dense leaf hashes delivered in the packet must all hash consistently
        # with the single anchor root only if a full [0,end) prefix is present
        # via an optional dense_hashes field (bundled exports); otherwise each
        # leaf is independently anchored as above.
        dense = packet.get("dense_leaf_hashes")
        if dense is not None:
            try:
                if len(dense) != end:
                    errors.append("dense_leaf_hashes length != end_index")
                dense_root = merkle_root(
                    [bytes.fromhex(h) for h in dense]).hex()
                if dense_root != root_hex:
                    errors.append(
                        "dense leaf hashes do not reproduce anchor root")
                delivered = {r["leaf_index"]: r["leaf_hash"] for r in records}
                for idx, lh in delivered.items():
                    if dense[idx] != lh:
                        errors.append(
                            f"leaf {idx}: delivered hash != dense hash")
            except (TypeError, ValueError) as exc:
                errors.append(f"dense_leaf_hashes malformed: {exc}")

    return {"ok": not errors, "errors": errors, "checks": checks,
            "delivery_id": packet.get("delivery_id"),
            "tenant_id": tenant, "seq": seq,
            "start_index": start, "end_index": end,
            "leaf_count": len(records),
            "tree_size": cp.get("tree_size"),
            "root_hash": cp.get("root_hash")}


def _verify_checkpoint(cp: Any, key: bytes | None) -> dict:
    errors: list[str] = []
    if not isinstance(cp, dict):
        return {"ok": False, "errors": ["checkpoint missing"]}
    if key is None:
        return {"ok": False,
                "errors": ["missing transparency_secret for anchor checkpoint"]}
    sig = cp.get("sig")
    expect = hmac.new(
        key,
        dumps_canon({k: v for k, v in cp.items() if k != "sig"}).encode("utf-8"),
        hashlib.sha256).hexdigest()
    if not isinstance(sig, str) or not hmac.compare_digest(sig, expect):
        errors.append("checkpoint HMAC invalid")
    if cp.get("checkpoint_version") != CHECKPOINT_VERSION:
        errors.append("unsupported checkpoint_version")
    size = cp.get("tree_size")
    root = cp.get("root_hash")
    if not isinstance(size, int) or size < 0 or not isinstance(root, str) \
            or len(root) != 64:
        errors.append("malformed checkpoint size/root")
    if size == 0 and root != EMPTY_HASH:
        errors.append("genesis root mismatch")
    return {"ok": not errors, "errors": errors}


# --------------------------------------------------------------------------- #
# cross-node transfer manifest (aft1) and takeover receipt (aftr1)
# --------------------------------------------------------------------------- #

MANIFEST_VERSION = "aft1"
RECEIPT_VERSION = "aftr1"


def _sealed_digest(body: dict) -> str:
    material = {k: v for k, v in body.items()
                if k not in ("sig", "manifest_digest")}
    return hashlib.sha256(
        dumps_canon(material).encode("utf-8")).hexdigest()


def verify_transfer_manifest(manifest: dict, key: bytes, *,
                             expected_tenant: str | None = None) -> dict:
    """离线校验一份 aft1 转移清单（只用机构 transparency 密钥）。"""
    errors: list[str] = []
    checks: dict[str, Any] = {}
    if not isinstance(manifest, dict):
        return {"ok": False, "errors": ["manifest must be an object"]}
    if manifest.get("manifest_version") != MANIFEST_VERSION:
        errors.append("unsupported manifest_version")
    expect_sig = hmac.new(
        key,
        dumps_canon({k: v for k, v in manifest.items() if k != "sig"})
        .encode("utf-8"), hashlib.sha256).hexdigest()
    sig = manifest.get("sig")
    checks["manifest_signature"] = isinstance(sig, str) and \
        hmac.compare_digest(sig or "", expect_sig)
    if not checks["manifest_signature"]:
        errors.append("manifest HMAC invalid (tampered or foreign trust domain)")
    checks["sealed_digest"] = isinstance(manifest.get("manifest_digest"), str) \
        and hmac.compare_digest(manifest.get("manifest_digest", ""),
                                _sealed_digest(manifest))
    if not checks["sealed_digest"]:
        errors.append("manifest sealed digest does not reproduce")

    tenant = manifest.get("tenant") or {}
    if expected_tenant is not None and \
            tenant.get("tenant_id") != expected_tenant:
        errors.append(f"tenant {tenant.get('tenant_id')!r} != expected "
                      f"{expected_tenant!r}")
    cursor = tenant.get("cursor_end")
    if not isinstance(cursor, int) or cursor < 0:
        errors.append("tenant.cursor_end malformed")

    anchor = manifest.get("log_anchor") or {}
    cp = anchor.get("checkpoint")
    cp_report = _verify_checkpoint(cp, key)
    checks["anchor_signature"] = cp_report["ok"]
    errors.extend("anchor: " + e for e in cp_report["errors"])
    if cp_report["ok"]:
        if cp.get("tree_size") != anchor.get("tree_size") or \
                cp.get("root_hash") != anchor.get("root_hash"):
            errors.append("anchor size/root disagree with its checkpoint")

    pos = cursor if isinstance(cursor, int) else 0
    prev_seq = None
    pending = manifest.get("windows", [])
    if not isinstance(pending, list):
        errors.append("windows must be a list")
        pending = []
    for i, w in enumerate(pending):
        try:
            seq, start, end = int(w["seq"]), int(w["start_index"]), \
                int(w["end_index"])
        except (KeyError, TypeError, ValueError):
            errors.append(f"window {i}: indices malformed")
            continue
        if start != pos:
            errors.append(f"window {i}: boundary gap (want start {pos})")
        if end <= start:
            errors.append(f"window {i}: empty range")
        if prev_seq is not None and seq != prev_seq + 1:
            errors.append(f"window {i}: seq not dense")
        prev_seq = seq
        if w.get("state") not in ("leased", "completed"):
            errors.append(f"window {i}: bad completion marker {w.get('state')!r}")
        if not isinstance(w.get("lease_count"), int) or w["lease_count"] < 1:
            errors.append(f"window {i}: attempt count malformed")
        packet = w.get("packet")
        if isinstance(packet, dict):
            sub = _verify_embedded_packet_anchor(packet, key, i)
            errors.extend(sub)
        else:
            errors.append(f"window {i}: packet missing")
        pos = end

    return {"ok": not errors, "errors": errors, "checks": checks,
            "transfer_id": manifest.get("transfer_id"),
            "tenant_id": tenant.get("tenant_id"),
            "handoff_epoch": manifest.get("handoff_epoch"),
            "confirmed_prefix": cursor,
            "anchor_tree_size": anchor.get("tree_size"),
            "anchor_root": anchor.get("root_hash"),
            "pending_windows": len(pending),
            "origin_instance": manifest.get("origin_instance")}


def _verify_embedded_packet_anchor(packet: dict, key: bytes,
                                    window_index: int) -> list[str]:
    """清单内嵌窗口包的**锚定**校验（只需机构 transparency 密钥）：

    包自身的 delivery HMAC 由发起方节点的 relay_packet_secret 签发，跨节点
    离线校验时不持有该节点私有包钥，因此这里只验证跨节点信任所需的部分——
    锚 checkpoint 的机构签名、叶内容地址、每条 inclusion_path 折到已签名根、
    区间与封存边界一致。
    """
    pfx = f"window {window_index} packet: "
    errors: list[str] = []
    cp = packet.get("checkpoint")
    rep = _verify_checkpoint(cp, key)
    if not rep["ok"]:
        errors.extend(pfx + e for e in rep["errors"])
        return errors
    end = packet.get("end_index")
    if not isinstance(end, int) or end != cp.get("tree_size"):
        errors.append(pfx + "end_index does not equal anchor tree_size")
        return errors
    root = bytes.fromhex(cp["root_hash"])
    for r in packet.get("records", []):
        try:
            idx = int(r["leaf_index"])
            if envelope_leaf_hash(r["envelope"]) != r["leaf_hash"]:
                errors.append(pfx + f"leaf {idx}: content address mismatch")
            path = [bytes.fromhex(h) for h in r.get("inclusion_path", [])]
            if not verify_inclusion(root, bytes.fromhex(r["leaf_hash"]),
                                    idx, end, path):
                errors.append(pfx + f"leaf {idx}: inclusion fold failed")
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(pfx + f"record malformed: {exc}")
    return errors


def verify_takeover_receipt(receipt: dict, key: bytes, *,
                            manifest: dict | None = None) -> dict:
    """离线校验 aftr1 接管回执；给定清单时核对其绑定关系。"""
    errors: list[str] = []
    checks: dict[str, Any] = {}
    if not isinstance(receipt, dict):
        return {"ok": False, "errors": ["receipt must be an object"]}
    if receipt.get("receipt_version") != RECEIPT_VERSION:
        errors.append("unsupported receipt_version")
    expect = hmac.new(
        key,
        dumps_canon({k: v for k, v in receipt.items() if k != "sig"})
        .encode("utf-8"), hashlib.sha256).hexdigest()
    sig = receipt.get("sig")
    checks["receipt_signature"] = isinstance(sig, str) and \
        hmac.compare_digest(sig or "", expect)
    if not checks["receipt_signature"]:
        errors.append("receipt HMAC invalid")
    if manifest is not None:
        if receipt.get("manifest_digest") != manifest.get("manifest_digest"):
            errors.append("receipt bound to a different manifest digest")
        if receipt.get("origin_instance") != manifest.get("origin_instance"):
            errors.append("receipt origin instance does not match manifest")
        if receipt.get("handoff_epoch") != manifest.get("handoff_epoch"):
            errors.append("receipt handoff_epoch does not match manifest")
        anchor = manifest.get("log_anchor") or {}
        ra = receipt.get("log_anchor") or {}
        if ra.get("tree_size") != anchor.get("tree_size") or \
                ra.get("root_hash") != anchor.get("root_hash"):
            errors.append("receipt log anchor does not match manifest")
    return {"ok": not errors, "errors": errors, "checks": checks,
            "transfer_id": receipt.get("transfer_id"),
            "tenant_id": receipt.get("tenant_id"),
            "handoff_epoch": receipt.get("handoff_epoch"),
            "origin_instance": receipt.get("origin_instance"),
            "receiver_instance": receipt.get("receiver_instance")}
