"""跨节点消费归属转移：签名 transfer manifest / takeover receipt 纯函数。

两个互相独立的中继节点（各自独立 ``relay.sqlite``、独立 ``relay_packet_secret``）
之间整体迁移一个消费方（审计租户）的消费状态时，唯一共享的信任锚是机构带外
分发的 ``transparency_secret``（与网关同名密钥一致），因此清单与回执都用它
签名——与 dpgw 分叉证据只信任该密钥签名 checkpoint 的做法一致。

清单格式 ``hfm1``（handoff manifest v1）封存::

    消费方身份（tenant_id/name）、只增的 handoff_epoch、发起方实例、
    筛选规则、已确认前缀 cursor_end、日志锚点（可信树高 + 根 + 已签名
    checkpoint）、每个未决区间的边界/完成标记/尝试次数、以及该消费方
    afp1 包的 HMAC 密钥（使接收方重建出逐字节相同的 delivery_id/包）。

回执格式 ``hfr1``（handoff receipt v1）在接收方**确认接管**时产生，绑定
清单摘要、双方实例与日志锚点；原节点凭有效回执永久放弃服务权。

``manifest_digest = sha256(canonical(body without sig))``，规范编码与
afp1/dpgw 完全一致；任何字段被篡改都会使验签或摘要比对失败。
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from .canonical import dumps_canon
from .errors import HandoffReceiptInvalid, HandoffTampered

MANIFEST_VERSION = "hfm1"
RECEIPT_VERSION = "hfr1"
MANIFEST_KIND = "consumer_handoff"


def manifest_digest(doc: dict) -> str:
    body = {k: v for k, v in doc.items() if k != "sig"}
    return hashlib.sha256(dumps_canon(body).encode("utf-8")).hexdigest()


def _sign(tkey: bytes, doc: dict) -> str:
    return hmac.new(
        tkey,
        dumps_canon({k: v for k, v in doc.items() if k != "sig"}).encode("utf-8"),
        hashlib.sha256).hexdigest()


def build_manifest(*, tenant_id: str, tenant_name: str, handoff_epoch: int,
                   origin_instance: str, filter_rule: dict, max_inflight: int,
                   cursor_end: int, anchor: dict, pending: list[dict],
                   packet_key_hex: str, sealed_at: str,
                   transparency_key: bytes) -> dict:
    """构造并签名一份 transfer manifest（确定性；同输入逐字节相同）。"""
    doc = {
        "manifest_version": MANIFEST_VERSION,
        "kind": MANIFEST_KIND,
        "tenant_id": tenant_id,
        "tenant_name": tenant_name,
        "handoff_epoch": int(handoff_epoch),
        "origin_instance": origin_instance,
        "filter": filter_rule or {},
        "max_inflight": int(max_inflight),
        "cursor_end": int(cursor_end),
        "anchor": anchor,
        "pending": pending,
        "packet_key": packet_key_hex,
        "sealed_at": sealed_at,
    }
    doc["sig"] = _sign(transparency_key, doc)
    return doc


def verify_manifest(doc: Any, transparency_key: bytes) -> dict:
    """独立验签一份 transfer manifest；任何不符即抛 :class:`HandoffTampered`。

    只做**自洽**校验（签名、版本、形状、锚 checkpoint 与根一致）；
    “接收方日志是否已包含锚点高度”由接收方结合自己的镜像库另行判定
    （落后 / 分叉是不同的拒绝原因）。
    """
    def fail(msg: str) -> None:
        raise HandoffTampered(msg)

    if not isinstance(doc, dict):
        fail("manifest must be an object")
    sig = doc.get("sig")
    if not isinstance(sig, str) or not hmac.compare_digest(sig or "",
                                                          _sign(transparency_key, doc)):
        fail("manifest HMAC invalid (content tampered or wrong transparency key)")
    if doc.get("manifest_version") != MANIFEST_VERSION:
        fail("unsupported manifest_version")
    if doc.get("kind") != MANIFEST_KIND:
        fail("manifest kind mismatch")
    for field in ("tenant_id", "tenant_name", "origin_instance"):
        if not isinstance(doc.get(field), str) or not doc[field]:
            fail(f"manifest.{field} must be a non-empty string")
    epoch = doc.get("handoff_epoch")
    if not isinstance(epoch, int) or epoch < 1:
        fail("handoff_epoch must be a positive integer")
    if not isinstance(doc.get("filter"), dict):
        fail("manifest.filter must be an object")
    if not isinstance(doc.get("max_inflight"), int) or doc["max_inflight"] < 1:
        fail("manifest.max_inflight must be a positive integer")
    cursor = doc.get("cursor_end")
    if not isinstance(cursor, int) or cursor < 0:
        fail("manifest.cursor_end must be a non-negative integer")
    anchor = doc.get("anchor")
    _verify_anchor(anchor, fail)
    pending = doc.get("pending")
    if not isinstance(pending, list):
        fail("manifest.pending must be a list")
    pos = cursor
    for i, w in enumerate(pending):
        for field in ("delivery_id", "seq", "start_index", "end_index",
                      "completed", "lease_count"):
            if field not in w:
                fail(f"pending[{i}] missing {field}")
        if not isinstance(w["delivery_id"], str) or \
                not w["delivery_id"].startswith("afd_"):
            fail(f"pending[{i}].delivery_id malformed")
        if not isinstance(w["seq"], int) or w["seq"] < 1:
            fail(f"pending[{i}].seq must be a positive integer")
        s, e = w["start_index"], w["end_index"]
        if not isinstance(s, int) or not isinstance(e, int) or not (0 <= s < e):
            fail(f"pending[{i}] bounds malformed")
        if s != pos:
            fail(f"pending[{i}] is not adjacent to the previous interval")
        if not isinstance(w["completed"], bool):
            fail(f"pending[{i}].completed must be boolean")
        if not isinstance(w["lease_count"], int) or w["lease_count"] < 1:
            fail(f"pending[{i}].lease_count must be a positive integer")
        pos = e
    if pos > int(anchor["tree_size"]):
        fail("pending intervals extend beyond the anchored tree head")
    try:
        bytes.fromhex(doc.get("packet_key") or "")
    except (TypeError, ValueError):
        fail("manifest.packet_key must be hex")
    return {
        "tenant_id": doc["tenant_id"], "tenant_name": doc["tenant_name"],
        "handoff_epoch": epoch, "origin_instance": doc["origin_instance"],
        "filter": doc["filter"], "max_inflight": doc["max_inflight"],
        "cursor_end": cursor, "anchor": anchor, "pending": pending,
        "packet_key_hex": doc["packet_key"], "sealed_at": doc.get("sealed_at"),
        "digest": manifest_digest(doc),
    }


def _verify_anchor(anchor: Any, fail) -> dict:
    if not isinstance(anchor, dict):
        fail("manifest.anchor must be an object")
    size, root, cp = (anchor.get("tree_size"), anchor.get("root_hash"),
                      anchor.get("checkpoint"))
    if not isinstance(size, int) or size < 0:
        fail("anchor.tree_size must be a non-negative integer")
    if not isinstance(root, str) or len(root) != 64:
        fail("anchor.root_hash must be 64 hex chars")
    if not isinstance(cp, dict):
        fail("anchor.checkpoint must be the signed checkpoint document")
    if cp.get("tree_size") != size or cp.get("root_hash") != root:
        fail("anchor checkpoint disagrees with sealed size/root")
    # checkpoint 自身签名由调用方（持有 transparency_key）在外部验，这里只
    # 校验形状；verify_receipt/verify_manifest 的调用路径会补验
    return {"tree_size": size, "root_hash": root, "checkpoint": cp}


def build_receipt(*, tenant_id: str, handoff_epoch: int, manifest_dig: str,
                  origin_instance: str, receiver_instance: str, anchor: dict,
                  cursor_end: int, pending_count: int, confirmed_at: str,
                  transparency_key: bytes) -> dict:
    doc = {
        "receipt_version": RECEIPT_VERSION,
        "kind": MANIFEST_KIND,
        "tenant_id": tenant_id,
        "handoff_epoch": int(handoff_epoch),
        "manifest_digest": manifest_dig,
        "origin_instance": origin_instance,
        "receiver_instance": receiver_instance,
        "anchor": {"tree_size": int(anchor["tree_size"]),
                   "root_hash": anchor["root_hash"]},
        "cursor_end": int(cursor_end),
        "pending_count": int(pending_count),
        "confirmed_at": confirmed_at,
    }
    doc["sig"] = _sign(transparency_key, doc)
    return doc


def verify_receipt(doc: Any, transparency_key: bytes) -> dict:
    if not isinstance(doc, dict):
        raise HandoffReceiptInvalid("receipt must be an object")
    sig = doc.get("sig")
    if not isinstance(sig, str) or not hmac.compare_digest(
            sig or "", _sign(transparency_key, doc)):
        raise HandoffReceiptInvalid(
            "receipt HMAC invalid (forged or wrong transparency key)")
    if doc.get("receipt_version") != RECEIPT_VERSION:
        raise HandoffReceiptInvalid("unsupported receipt_version")
    for field in ("tenant_id", "manifest_digest", "origin_instance",
                  "receiver_instance"):
        if not isinstance(doc.get(field), str) or not doc[field]:
            raise HandoffReceiptInvalid(f"receipt.{field} malformed")
    if not isinstance(doc.get("handoff_epoch"), int) \
            or doc["handoff_epoch"] < 1:
        raise HandoffReceiptInvalid("receipt.handoff_epoch malformed")
    anchor = doc.get("anchor")
    if not isinstance(anchor, dict) \
            or not isinstance(anchor.get("tree_size"), int) \
            or not isinstance(anchor.get("root_hash"), str):
        raise HandoffReceiptInvalid("receipt.anchor malformed")
    if doc["origin_instance"] == doc["receiver_instance"]:
        raise HandoffReceiptInvalid(
            "receipt binds two identical instance ids (identity mix-up)")
    return {
        "tenant_id": doc["tenant_id"],
        "handoff_epoch": doc["handoff_epoch"],
        "manifest_digest": doc["manifest_digest"],
        "origin_instance": doc["origin_instance"],
        "receiver_instance": doc["receiver_instance"],
        "anchor": anchor,
        "cursor_end": doc.get("cursor_end"),
        "pending_count": doc.get("pending_count"),
        "confirmed_at": doc.get("confirmed_at"),
        "digest": hashlib.sha256(
            dumps_canon({k: v for k, v in doc.items() if k != "sig"})
            .encode("utf-8")).hexdigest(),
    }
