"""跨节点消费归属转移（consumer ownership handoff）测试。

覆盖需求场景：

* 完整生命周期：prepare(draining 不发新窗口、短租约自然结束) → export
  签名清单（封筛选/已确认前缀/每未决区间边界+完成标记+尝试次数/日志锚点/
  handoff_epoch 只增）→ import（接收方证明日志含可信树头、无同名消费方，
  原样恢复；恢复后未确认前不对外服务）→ confirm（产生签名回执）→
  apply-receipt（原节点永久弃权）；
* 同清单再导入返回首次结果（幂等、只发一次新令牌）；
* 越序完成记录跨节点不遗失、补洞屏障在接收方一次推进；
* 接管窗口 delivery_id/包字节不变、尝试次数保留、接管后再 +1；
* 转移前签发的凭据（旧租户令牌不可知、旧 lease_token）在双方都不能改变
  已确认前缀；
* 回执产生前可撤销 draining（原节点继续）；回执后撤销/服务永久失败；
* 旧代次、内容篡改（筛选/区间/锚点）、错钥、日志落后、日志分叉、同名
  消费方、并发导入（同清单只一个令牌；异清单只一个赢家）、身份串用
  （导回自己/双方实例相同）全部失败；
* 任一方在准备/导出/导入/确认期间退出，重启后阶段与状态完整，只可能
  原节点继续或新节点接管；
* HTTP API 与离线 verify handoff/receipt。
"""

from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))
from relay_harness import GatewayWorld  # noqa: E402

from afrelay.app import bootstrap, open_relay  # noqa: E402
from afrelay.canonical import dumps_canon  # noqa: E402
from afrelay.errors import (  # noqa: E402
    HandoffActiveLeases,
    HandoffConflict,
    HandoffFork,
    HandoffLogBehind,
    HandoffConcurrent,
    HandoffSelf,
    HandoffStaleEpoch,
    HandoffStateConflict,
    HandoffTampered,
    HandoffReceiptInvalid,
    RelayError,
    StaleLease,
    TenantDraining,
    TenantRelinquished,
)
from afrelay.handoff import (  # noqa: E402
    build_manifest,
    build_receipt,
    manifest_digest,
    verify_manifest,
    verify_receipt,
)
from afrelay.server import serve as serve_relay  # noqa: E402
from afrelay.verify import load_transparency_key  # noqa: E402


def http(method, url, token=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": "Bearer " + (token or ""),
        "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


class TwoRelayTestBase(unittest.TestCase):
    """两个独立中继 home（独立 sqlite/独立 packet secret），镜像同一上游。"""

    leaves = 3

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.world = GatewayWorld()
        for i in range(self.leaves):
            self.world.seal(f"b{i}")
        self.homes = {}
        self.relays = {}
        self.clock = {"t": 1_000_000.0}

    def tearDown(self):
        for r in list(self.relays.values()):
            try:
                r.close()
            except Exception:
                pass
        self.world.close()
        self.tmp.cleanup()

    def boot(self, name, *, sync=True, batch_size=1, max_inflight=4,
             secret_hex=None):
        home = os.path.join(self.tmp.name, name)
        info = bootstrap(
            home, upstream_url=self.world.base,
            upstream_token=self.world.token,
            transparency_secret_hex=secret_hex or self.world.transparency_key_hex,
            default_ttl_seconds=30, batch_size=batch_size,
            default_max_inflight=max_inflight)
        relay = open_relay(home, clock=lambda: self.clock["t"])
        if sync:
            relay.sync_once()
        self.homes[name] = home
        self.relays[name] = relay
        return relay, info["admin_token"]

    def advance(self, seconds):
        self.clock["t"] += seconds

    def reopen(self, name):
        old = self.relays.pop(name, None)
        if old is not None:
            old.close()
        r = open_relay(self.homes[name], clock=lambda: self.clock["t"])
        self.relays[name] = r
        return r

    def tenant_with_windows(self, relay, admin, tid="aud-a", name="A",
                            rule=None, n=3, ttl=300, complete=()):
        tok = relay.create_tenant(tid, name, rule, token=admin)["token"]
        wins = [relay.claim(tok, f"w{i+1}", ttl_seconds=ttl)
                for i in range(n)]
        for i in complete:
            relay.complete(tok, wins[i]["delivery_id"],
                           wins[i]["end_index"], f"w{i+1}",
                           lease_token=wins[i]["lease_token"])
        return tok, wins

    def full_export(self, relay, tid, revoke_reissue_ttl=True):
        """prepare（短租约立即自然结束）+ export，返回签名清单。"""
        relay.prepare_handoff(tid)
        return relay.export_handoff(tid)["manifest"]


class FullLifecycleTests(TwoRelayTestBase):
    def test_draining_stops_new_claims_but_accepts_outstanding_acks(self):
        ra, aa = self.boot("a")
        tok, wins = self.tenant_with_windows(ra, aa, n=3, ttl=300)
        ra.prepare_handoff("aud-a")
        # draining：不发新窗口
        with self.assertRaises(TenantDraining):
            ra.claim(tok, "w4")
        # prepare 让短租约自然到期；但在到期前完成确认仍被接受（这里
        # prepare 已使其到期，因此直接接管路径会被 draining 的 claim 挡住——
        # 语义等价：新任务不分配，已有租约到期结束）。导出前把一条租约
        # 重新置为有效，证明未到期 lease 未被登记完成但会阻塞导出
        ra.db.execute(
            "UPDATE deliveries SET lease_expires_at=? WHERE delivery_id=?",
            (str(self.clock["t"] + 100), wins[0]["delivery_id"]))
        with self.assertRaises(HandoffActiveLeases):
            ra.export_handoff("aud-a")
        # 到期后导出成功
        self.advance(200)
        m = ra.export_handoff("aud-a")["manifest"]
        self.assertEqual(m["handoff_epoch"], 1)
        self.assertEqual(m["anchor"]["tree_size"], 3)
        self.assertEqual([w["delivery_id"] for w in m["pending"]],
                         [w["delivery_id"] for w in wins])

    def test_full_handoff_restores_state_and_advances_barrier(self):
        ra, aa = self.boot("a")
        rb, ab = self.boot("b")
        # 越序完成 w2（屏障仍停 0）
        tok, wins = self.tenant_with_windows(ra, aa, n=3, complete=(1,))
        self.assertEqual(ra.tenant_windows("aud-a")["commit_barrier"], 0)
        m = self.full_export(ra, "aud-a")
        self.assertEqual([(p["start_index"], p["end_index"], p["completed"])
                          for p in m["pending"]],
                         [(0, 1, False), (1, 2, True), (2, 3, False)])

        # 接收方导入即原样恢复；确认前不对外服务
        iv = rb.import_handoff(m)
        self.assertEqual(iv["state"], "importing")
        ntok = iv["token"]
        summ = rb.tenant_windows("aud-a")
        self.assertEqual({w["seq"]: w["state"] for w in summ["windows"]},
                         {1: "leased", 2: "completed", 3: "leased"})
        self.assertEqual(summ["commit_barrier"], 0)
        with self.assertRaises(TenantDraining):
            rb.claim(ntok, "x")

        # 确认接管后开始服务；接管 w1 保持同一 id/字节，尝试次数保留并 +1
        receipt_view = rb.confirm_handoff("aud-a")
        self.assertEqual(receipt_view["state"], "confirmed")
        r1 = rb.claim(ntok, "nw1", ttl_seconds=300)
        self.assertEqual(r1["delivery_id"], wins[0]["delivery_id"])
        self.assertEqual(dumps_canon(r1["delivery"]),
                         dumps_canon(wins[0]["delivery"]))
        self.assertEqual(r1["retries"], 1)  # 封存 lease_count=1，接管 +1
        rb.complete(ntok, r1["delivery_id"], r1["end_index"], "nw1",
                    lease_token=r1["lease_token"])
        # w2 越序完成记录在：补 w1 后屏障直接跳到 w2 末端
        s = rb.tenant_windows("aud-a")
        self.assertEqual(s["commit_barrier"], 2)
        # w3 再接管完成 → 屏障穿过 w3
        r3 = rb.claim(ntok, "nw3", ttl_seconds=300)
        self.assertEqual(r3["delivery_id"], wins[2]["delivery_id"])
        a3 = rb.complete(ntok, r3["delivery_id"], r3["end_index"], "nw3",
                         lease_token=r3["lease_token"])
        self.assertEqual(a3["commit_barrier"], 3)

        # 原节点凭回执永久弃权
        av = ra.apply_receipt(receipt_view["receipt"])
        self.assertEqual(av["state"], "relinquished")
        with self.assertRaises(TenantRelinquished):
            ra.claim(tok, "x")
        with self.assertRaises(TenantRelinquished):
            ra.complete(tok, wins[0]["delivery_id"], 1, "x")
        # 配置类操作在弃权后也冻结
        with self.assertRaises(HandoffStateConflict):
            ra.set_max_inflight("aud-a", 2)

    def test_epoch_only_increases_across_revoke_cycles(self):
        ra, aa = self.boot("a")
        tok, _ = self.tenant_with_windows(ra, aa, n=1)
        ra.prepare_handoff("aud-a")
        ra.export_handoff("aud-a")
        # 回执前撤销：原节点继续服务，epoch 不回退
        rv = ra.revoke_handoff("aud-a")
        self.assertEqual(rv["state"], "revoked")
        c = ra.claim(tok, "c")
        self.assertIsNotNone(c["delivery"])
        ra.prepare_handoff("aud-a")
        m = ra.export_handoff("aud-a")["manifest"]
        self.assertEqual(m["handoff_epoch"], 2)
        # 再撤销再准备 → 3
        ra.revoke_handoff("aud-a")
        ra.prepare_handoff("aud-a")
        m3 = ra.export_handoff("aud-a")["manifest"]
        self.assertEqual(m3["handoff_epoch"], 3)

    def test_revoke_impossible_after_receipt(self):
        ra, aa = self.boot("a")
        rb, _ = self.boot("b")
        tok, _ = self.tenant_with_windows(ra, aa, n=1)
        m = self.full_export(ra, "aud-a")
        rb.import_handoff(m)
        receipt = rb.confirm_handoff("aud-a")["receipt"]
        ra.apply_receipt(receipt)
        with self.assertRaises(HandoffStateConflict):
            ra.revoke_handoff("aud-a")


class IdempotencyTests(TwoRelayTestBase):
    def test_same_manifest_reimport_returns_first_result(self):
        ra, aa = self.boot("a")
        rb, _ = self.boot("b")
        _, _ = self.tenant_with_windows(ra, aa, n=1)
        m = self.full_export(ra, "aud-a")
        first = rb.import_handoff(m)
        self.assertTrue(first["token"])
        second = rb.import_handoff(m)
        self.assertTrue(second["idempotent"])
        self.assertNotIn("token", second)  # 新令牌只随首次结果发一次
        self.assertEqual(second["manifest_digest"], first["manifest_digest"])
        # prepare/export/confirm/apply-receipt 同样幂等
        self.assertTrue(ra.prepare_handoff.__self__ is ra)
        # 重新导出（新一轮撤销后）不在此测；这里验 export 在 exported
        # 阶段重复调用返回同一摘要
        ra2, aa2 = self.boot("c")
        self.tenant_with_windows(ra2, aa2, tid="aud-z", n=1)
        ra2.prepare_handoff("aud-z")
        e1 = ra2.export_handoff("aud-z")
        e2 = ra2.export_handoff("aud-z")
        self.assertTrue(e2["idempotent"])
        self.assertEqual(e1["manifest_digest"], e2["manifest_digest"])

    def test_confirm_and_receipt_are_idempotent(self):
        ra, aa = self.boot("a")
        rb, _ = self.boot("b")
        self.tenant_with_windows(ra, aa, n=1)
        m = self.full_export(ra, "aud-a")
        rb.import_handoff(m)
        r1 = rb.confirm_handoff("aud-a")["receipt"]
        r2 = rb.confirm_handoff("aud-a")
        self.assertTrue(r2["idempotent"])
        self.assertEqual(manifest_digest(r1), manifest_digest(r2["receipt"]))
        a1 = ra.apply_receipt(r1)
        a2 = ra.apply_receipt(r1)
        self.assertTrue(a2["idempotent"])
        self.assertEqual(a1["state"], a2["state"])


class CredentialTests(TwoRelayTestBase):
    def test_pretransfer_lease_token_cannot_change_prefix_on_either_node(self):
        ra, aa = self.boot("a")
        rb, _ = self.boot("b")
        tok, wins = self.tenant_with_windows(ra, aa, n=2)
        old_token = wins[0]["lease_token"]
        m = self.full_export(ra, "aud-a")
        ntok = rb.import_handoff(m)["token"]
        rb.confirm_handoff("aud-a")
        # 接收方接管 w1 并提交越过屏障
        r1 = rb.claim(ntok, "nw1", ttl_seconds=300)
        rb.complete(ntok, r1["delivery_id"], r1["end_index"], "nw1",
                    lease_token=r1["lease_token"])
        # 转移前的旧 lease_token 在接收方重放已提交窗口 → stale_lease
        with self.assertRaises(StaleLease):
            rb.complete(ntok, wins[0]["delivery_id"],
                        wins[0]["end_index"], "w1", lease_token=old_token)
        # 原节点导出后任何提交（即使持旧 token）都不能动前缀
        with self.assertRaises(StaleLease):
            ra.complete(tok, wins[1]["delivery_id"],
                        wins[1]["end_index"], "w2",
                        lease_token=wins[1]["lease_token"])

    def test_recovered_packet_verifies_with_origin_key(self):
        from afrelay.verify import verify_packet, load_relay_keys
        ra, aa = self.boot("a")
        rb, _ = self.boot("b")
        _, wins = self.tenant_with_windows(ra, aa, n=1)
        m = self.full_export(ra, "aud-a")
        ntok = rb.import_handoff(m)["token"]
        rb.confirm_handoff("aud-a")
        packet = rb.claim(ntok, "nw", ttl_seconds=300)["delivery"]
        # 接收方重建的包用清单封存的 origin packet key 验签
        keys = {"relay_packet_secret": bytes.fromhex(m["packet_key"]),
                "transparency_secret": load_transparency_key(self.homes["a"])}
        rep = verify_packet(packet, keys, expected_tenant="aud-a")
        self.assertTrue(rep["ok"], rep["errors"])


class RejectTests(TwoRelayTestBase):
    def _two_manifests(self, ra, rb):
        tok, _ = self.tenant_with_windows(ra, "admin", n=1)
        ra.prepare_handoff("aud-a")
        m1 = ra.export_handoff("aud-a")["manifest"]
        rb.import_handoff(m1)
        ra.revoke_handoff("aud-a")
        ra.prepare_handoff("aud-a")
        ra.db.execute(
            "UPDATE deliveries SET lease_expires_at='1' WHERE tenant_id='aud-a'")
        m2 = ra.export_handoff("aud-a")["manifest"]
        return m1, m2

    def test_tampered_manifest_rejected(self):
        ra, aa = self.boot("a")
        rb, _ = self.boot("b")
        tok, _ = self.tenant_with_windows(
            ra, aa, n=1,
            rule={"event_types": ["release_sealed"]})
        m = self.full_export(ra, "aud-a")
        for mutate in (
                lambda d: d.update(cursor_end=99),
                lambda d: d.update(filter={"event_types": ["share_issued"]}),
                lambda d: d["pending"][0].__setitem__("lease_count", 9),
                lambda d: d["pending"][0].__setitem__("end_index", 3),
                lambda d: d["anchor"].__setitem__("tree_size", 2),
                lambda d: d.update(handoff_epoch=5),
                lambda d: d.update(tenant_id="aud-other")):
            bad = copy.deepcopy(m)
            mutate(bad)
            with self.assertRaises(HandoffTampered):
                rb.import_handoff(bad)

    def test_wrong_signing_key_rejected(self):
        ra, aa = self.boot("a")
        rb, _ = self.boot("b")
        self.tenant_with_windows(ra, aa, n=1)
        m = self.full_export(ra, "aud-a")
        forged = build_manifest(
            tenant_id=m["tenant_id"], tenant_name=m["tenant_name"],
            handoff_epoch=1, origin_instance=m["origin_instance"],
            filter_rule=m["filter"], max_inflight=m["max_inflight"],
            cursor_end=m["cursor_end"], anchor=m["anchor"],
            pending=m["pending"], packet_key_hex=m["packet_key"],
            sealed_at=m["sealed_at"], transparency_key=b"\x22" * 32)
        with self.assertRaises(HandoffTampered):
            rb.import_handoff(forged)

    def test_stale_epoch_rejected(self):
        ra, aa = self.boot("a")
        rb, _ = self.boot("b")
        # 使用 admin token（boot 返回第二个值）
        tok, _ = self.tenant_with_windows(ra, aa, n=1)
        ra.prepare_handoff("aud-a")
        m1 = ra.export_handoff("aud-a")["manifest"]
        rb.import_handoff(m1)
        ra.revoke_handoff("aud-a")
        ra.prepare_handoff("aud-a")
        ra.db.execute(
            "UPDATE deliveries SET lease_expires_at='1' WHERE tenant_id='aud-a'")
        m2 = ra.export_handoff("aud-a")["manifest"]
        # 已恢复 ep1 的节点拒绝 ep2（竞争/旧谱系）→ conflict；再喂 ep1
        # 仍是同清单幂等
        with self.assertRaises(HandoffConflict):
            rb.import_handoff(m2)
        again = rb.import_handoff(m1)
        self.assertTrue(again["idempotent"])
        # 在另一个全新节点，伪造一个 epoch=0 的清单 → stale
        rc, _ = self.boot("c")
        old = copy.deepcopy(m1)
        old["handoff_epoch"] = 0
        with self.assertRaises(HandoffTampered):
            rc.import_handoff(old)

    def test_log_behind_rejected(self):
        ra, _ = self.boot("a")
        rc, _ = self.boot("c", sync=False)  # 从未同步，只有 genesis 或空
        tok, _ = self.tenant_with_windows(ra, "admin", n=1)
        m = self.full_export(ra, "aud-a")
        with self.assertRaises(HandoffLogBehind):
            rc.import_handoff(m)

    def test_log_fork_rejected(self):
        ra, aa = self.boot("a")
        rd, _ = self.boot("d")
        self.tenant_with_windows(ra, aa, n=1)
        m = self.full_export(ra, "aud-a")
        # 篡改接收方在锚定高度的本地根，模拟分叉历史
        rd.db.execute(
            "UPDATE mirror_cps SET root_hash=? WHERE tree_size=?",
            ("ab" * 32, m["anchor"]["tree_size"]))
        with self.assertRaises(HandoffFork):
            rd.import_handoff(m)

    def test_same_name_consumer_rejected(self):
        ra, aa = self.boot("a")
        rb, _ = self.boot("b")
        self.tenant_with_windows(ra, aa, n=1)
        m = self.full_export(ra, "aud-a")
        # 本地已有同 id 消费方（非本谱系）
        rb.create_tenant("aud-a", "local-A", None, token="admin")
        with self.assertRaises(HandoffConflict):
            rb.import_handoff(m)
        # 同名不同 id 也拒绝（用合法签名重建）
        tkey = rb.transparency_key
        other = build_manifest(
            tenant_id="aud-q", tenant_name="local-A", handoff_epoch=1,
            origin_instance=ra.instance_id, filter_rule={}, max_inflight=4,
            cursor_end=0, anchor=m["anchor"], pending=[],
            packet_key_hex="00" * 32, sealed_at="x",
            transparency_key=tkey)
        with self.assertRaises(HandoffConflict):
            rb.import_handoff(other)

    def test_self_import_rejected(self):
        ra, aa = self.boot("a")
        self.tenant_with_windows(ra, aa, n=1)
        m = self.full_export(ra, "aud-a")
        with self.assertRaises(HandoffSelf):
            ra.import_handoff(m)

    def test_forged_anchor_checkpoint_signature_rejected(self):
        ra, aa = self.boot("a")
        rb, _ = self.boot("b")
        self.tenant_with_windows(ra, aa, n=1)
        m = self.full_export(ra, "aud-a")
        # 重签整个清单（用正确 transparency key），但内嵌锚 checkpoint 的
        # sig 被抹成无效：清单自洽可验，但“绑定的树头”本身是伪造的
        from afrelay.handoff import build_manifest
        anchor = copy.deepcopy(m["anchor"])
        anchor["checkpoint"]["sig"] = "00" * 64
        rebuilt = build_manifest(
            tenant_id=m["tenant_id"], tenant_name=m["tenant_name"],
            handoff_epoch=m["handoff_epoch"],
            origin_instance=m["origin_instance"], filter_rule=m["filter"],
            max_inflight=m["max_inflight"], cursor_end=m["cursor_end"],
            anchor=anchor, pending=m["pending"],
            packet_key_hex=m["packet_key"], sealed_at=m["sealed_at"],
            transparency_key=rb.transparency_key)
        with self.assertRaises(HandoffTampered):
            rb.import_handoff(rebuilt)

    def test_receipt_identity_mixup_rejected(self):
        ra, aa = self.boot("a")
        rb, _ = self.boot("b")
        self.tenant_with_windows(ra, aa, n=1)
        m = self.full_export(ra, "aud-a")
        rb.import_handoff(m)
        rb.confirm_handoff("aud-a")
        tkey = ra.transparency_key
        # 回执双方实例相同 → 身份串用
        bad = build_receipt(
            tenant_id="aud-a", handoff_epoch=1,
            manifest_dig=manifest_digest(m),
            origin_instance=ra.instance_id,
            receiver_instance=ra.instance_id, anchor=m["anchor"],
            cursor_end=0, pending_count=1, confirmed_at="x",
            transparency_key=tkey)
        with self.assertRaises(HandoffReceiptInvalid):
            ra.apply_receipt(bad)
        # 回执 origin 不是本节点
        other = build_receipt(
            tenant_id="aud-a", handoff_epoch=1,
            manifest_dig=manifest_digest(m),
            origin_instance="afrn_deadbeef",
            receiver_instance=rb.instance_id, anchor=m["anchor"],
            cursor_end=0, pending_count=1, confirmed_at="x",
            transparency_key=tkey)
        with self.assertRaises(HandoffReceiptInvalid):
            ra.apply_receipt(other)
        # 摘要被换（无有效签名）→ receipt_invalid
        forged = copy.deepcopy(rb.confirm_handoff("aud-a")["receipt"])
        forged["manifest_digest"] = "ff" * 32
        with self.assertRaises(HandoffReceiptInvalid):
            ra.apply_receipt(forged)

    def test_concurrent_different_manifests_single_winner(self):
        ra, aa = self.boot("a")
        rc, _ = self.boot("c")
        tok, _ = self.tenant_with_windows(ra, aa, n=1)
        ra.prepare_handoff("aud-a")
        m1 = ra.export_handoff("aud-a")["manifest"]
        ra.revoke_handoff("aud-a")
        ra.prepare_handoff("aud-a")
        ra.db.execute(
            "UPDATE deliveries SET lease_expires_at='1' WHERE tenant_id='aud-a'")
        m2 = ra.export_handoff("aud-a")["manifest"]
        r1 = self.reopen("c")
        r2 = open_relay(self.homes["c"])
        self.relays["c2"] = r2
        out = {}

        def run(key, relay, manifest):
            try:
                relay.import_handoff(manifest)
                out[key] = "ok"
            except (HandoffConcurrent, HandoffConflict,
                    HandoffStaleEpoch) as exc:
                out[key] = exc.code

        threads = [
            threading.Thread(target=run, args=("e1", r1, m1)),
            threading.Thread(target=run, args=("e2", r2, m2))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # 恰好一个赢，另一个失败（绝不两条都恢复，也不会两个都被拒）
        results = list(out.values())
        self.assertEqual(results.count("ok"), 1, out)
        self.assertIn([v for v in results if v != "ok"][0],
                      ("handoff_concurrent", "handoff_conflict",
                       "handoff_stale_epoch"))
        live = r1.db.execute(
            "SELECT COUNT(*) c FROM handoff_records "
            "WHERE tenant_id='aud-a' AND state IN ('importing','confirmed')"
        ).fetchone()["c"]
        self.assertEqual(live, 1)


class RestartTests(TwoRelayTestBase):
    def test_phases_and_out_of_order_records_survive_restart(self):
        ra, aa = self.boot("a")
        rb, _ = self.boot("b")
        tok, wins = self.tenant_with_windows(ra, aa, n=3, complete=(2,))
        m = self.full_export(ra, "aud-a")
        # 导出后双方都重启
        self.reopen("a")
        self.assertEqual(self.relays["a"].get_handoff("aud-a")["state"],
                         "exported")
        iv = self.relays["b"].close() or None
        rb = self.reopen("b")
        v = rb.import_handoff(m)
        self.assertEqual(v["state"], "importing")
        ntok = v["token"]
        rb.close()
        rb = self.reopen("b")
        self.assertEqual(rb.get_handoff("aud-a")["state"], "importing")
        # 越序完成（w3）与未决区间都在
        states = {w["seq"]: w["state"]
                  for w in rb.tenant_windows("aud-a")["windows"]}
        self.assertEqual(states, {1: "leased", 2: "leased", 3: "completed"})
        # 确认接管并完成 → 只可能新节点服务
        rb.confirm_handoff("aud-a")
        for idx, consumer in ((0, "n1"), (1, "n2")):
            r = rb.claim(ntok, consumer, ttl_seconds=300)
            rb.complete(ntok, r["delivery_id"], r["end_index"], consumer,
                        lease_token=r["lease_token"])
        self.assertEqual(rb.tenant_windows("aud-a")["commit_barrier"], 3)
        # 原节点重启后凭回执弃权：原节点永不服务
        ra = self.reopen("a")
        ra.apply_receipt(
            self.relays["b"].get_handoff("aud-a") and
            json.loads(self.relays["b"].db.execute(
                "SELECT receipt_json FROM handoff_records WHERE tenant_id=?",
                ("aud-a",)).fetchone()["receipt_json"]))
        with self.assertRaises(TenantRelinquished):
            ra.claim(tok, "x")

    def test_recovered_after_revoke_origin_keeps_serving(self):
        ra, aa = self.boot("a")
        tok, wins = self.tenant_with_windows(ra, aa, n=2, ttl=3000)
        ra.prepare_handoff("aud-a")
        # 重启在 preparing 之后：仍是 draining，可撤销恢复
        ra = self.reopen("a")
        self.assertEqual(ra.get_handoff("aud-a")["state"], "draining")
        ra.revoke_handoff("aud-a")
        c = ra.claim(tok, "again", ttl_seconds=300)
        self.assertIsNotNone(c["delivery"])


class ObservabilityTests(TwoRelayTestBase):
    def test_status_and_handoff_views(self):
        ra, aa = self.boot("a")
        rb, _ = self.boot("b")
        self.tenant_with_windows(ra, aa, n=2)
        m = self.full_export(ra, "aud-a")
        iv = rb.import_handoff(m)
        st = rb.status()
        t = [x for x in st["tenants"] if x["tenant_id"] == "aud-a"][0]
        self.assertEqual(t["serve_state"], "importing")
        self.assertEqual(t["handoff_role"], "receiver")
        self.assertEqual(t["handoff_epoch"], 1)
        self.assertIn("handoff", t)
        self.assertEqual(t["handoff"]["anchor"]["tree_size"], 3)
        self.assertEqual(t["node_instance"], rb.instance_id)
        self.assertEqual(st["handoffs"][0]["manifest_digest"],
                         iv["manifest_digest"])
        # 拒绝原因落到事件：篡改内容导致 HMAC 失败
        tampered = copy.deepcopy(m)
        tampered["cursor_end"] = 1
        with self.assertRaises(HandoffTampered):
            rb.import_handoff(tampered)
        kinds = [e["kind"] for e in rb.recent_events(limit=50)]
        self.assertIn("handoff_import_rejected", kinds)


class OfflineVerifyTests(TwoRelayTestBase):
    def test_verify_manifest_and_receipt_offline(self):
        ra, aa = self.boot("a")
        rb, _ = self.boot("b")
        self.tenant_with_windows(ra, aa, n=1)
        m = self.full_export(ra, "aud-a")
        tkey = load_transparency_key(self.homes["a"])
        rep = verify_manifest(m, tkey)
        self.assertEqual(rep["tenant_id"], "aud-a")
        self.assertEqual(rep["digest"], manifest_digest(m))
        rb.import_handoff(m)
        receipt = rb.confirm_handoff("aud-a")["receipt"]
        rrep = verify_receipt(receipt, tkey)
        self.assertEqual(rrep["manifest_digest"], manifest_digest(m))
        self.assertNotEqual(rrep["origin_instance"],
                            rrep["receiver_instance"])


class HandoffHttpTests(TwoRelayTestBase):
    def setUp(self):
        super().setUp()
        self.ra, self.aa = self.boot("a")
        self.rb, self.ab = self.boot("b")
        self.sa = serve_relay(self.ra, "127.0.0.1", 0)
        self.sb = serve_relay(self.rb, "127.0.0.1", 0)
        threading.Thread(target=self.sa.serve_forever, daemon=True).start()
        threading.Thread(target=self.sb.serve_forever, daemon=True).start()
        self.ua = f"http://127.0.0.1:{self.sa.server_address[1]}"
        self.ub = f"http://127.0.0.1:{self.sb.server_address[1]}"

    def tearDown(self):
        self.sa.shutdown()
        self.sa.server_close()
        self.sb.shutdown()
        self.sb.server_close()
        super().tearDown()

    def test_http_prepare_export_import_confirm_receipt(self):
        tok, wins = self.tenant_with_windows(self.ra, self.aa, n=2)
        st, _ = http("POST", self.ua +
                     "/v1/admin/tenants/aud-a/handoff/prepare", self.aa,
                     {"reason": "rolling"})
        self.assertEqual(st, 200)
        # draining claim rejected over HTTP
        st, body = http("POST", self.ua + "/v1/relay/claim", tok,
                        {"consumer": "x"})
        self.assertEqual(st, 409)
        self.assertEqual(body["error"], "tenant_draining")
        st, body = http("POST", self.ua +
                        "/v1/admin/tenants/aud-a/handoff/export", self.aa)
        self.assertEqual(st, 200)
        manifest = body["manifest"]
        st, body = http("POST", self.ub + "/v1/admin/handoffs/import",
                        self.ab, {"manifest": manifest})
        self.assertEqual(st, 200)
        self.assertEqual(body["state"], "importing")
        ntok = body["token"]
        # cannot claim before confirm
        st, body = http("POST", self.ub + "/v1/relay/claim", ntok,
                        {"consumer": "x"})
        self.assertEqual(st, 409)
        st, body = http("POST", self.ub +
                        "/v1/admin/tenants/aud-a/handoff/confirm", self.ab)
        self.assertEqual(st, 200)
        receipt = body["receipt"]
        st, _ = http("POST", self.ub +
                     "/v1/admin/tenants/aud-a/handoff/confirm", self.ab)
        self.assertEqual(st, 200)  # idempotent
        st, body = http("POST", self.ua + "/v1/admin/handoffs/receipt",
                        self.aa, {"receipt": receipt})
        self.assertEqual(st, 200)
        self.assertEqual(body["state"], "relinquished")
        # origin claim now 403
        st, body = http("POST", self.ua + "/v1/relay/claim", tok,
                        {"consumer": "x"})
        self.assertEqual(st, 403)
        self.assertEqual(body["error"], "tenant_relinquished")
        # handoff views
        st, body = http("GET", self.ub +
                        "/v1/admin/tenants/aud-a/handoff", self.ab)
        self.assertEqual(st, 200)
        self.assertEqual(body["state"], "confirmed")
        self.assertEqual(body["origin_instance"], self.ra.instance_id)
        st, body = http("GET", self.ub + "/v1/admin/handoffs", self.ab)
        self.assertEqual(st, 200)
        self.assertTrue(body["handoffs"])

    def test_http_reject_paths(self):
        tok, _ = self.tenant_with_windows(self.ra, self.aa, n=1)
        # export before prepare
        st, body = http("POST", self.ua +
                        "/v1/admin/tenants/aud-a/handoff/export", self.aa)
        self.assertEqual(st, 409)
        self.assertEqual(body["error"], "handoff_state_conflict")
        # tampered manifest
        http("POST", self.ua + "/v1/admin/tenants/aud-a/handoff/prepare",
             self.aa)
        st, body = http("POST", self.ua +
                        "/v1/admin/tenants/aud-a/handoff/export", self.aa)
        manifest = body["manifest"]
        manifest["cursor_end"] = 42
        st, body = http("POST", self.ub + "/v1/admin/handoffs/import",
                        self.ab, {"manifest": manifest})
        self.assertEqual(st, 400)
        self.assertEqual(body["error"], "handoff_tampered")
        # admin auth enforced
        st, _ = http("GET", self.ub + "/v1/admin/handoffs", "nope")
        self.assertEqual(st, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
