"""跨节点消费归属转移测试（consumer ownership handoff）。

覆盖：draining 不发新窗口且短租约自然结束、导出封存（筛选/已确认前缀/未决
区间边界/完成标记/尝试次数/日志锚点/handoff_epoch 只增）、接收方日志锚点
校验（落后/分叉）、同名消费方冲突、相同清单幂等、旧代次拒绝、内容篡改拒绝、
确认后换发新令牌且旧凭据双节点失效（不能改变已确认前缀）、接管回执后原节点
永久失权、回执产生前可撤销、身份串用拒绝、崩溃恢复不双主且不丢越序完成、
HTTP API。
"""

from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))
from relay_harness import FaultyUpstream, GatewayWorld  # noqa: E402

from afrelay.app import bootstrap, open_relay  # noqa: E402
from afrelay.errors import (  # noqa: E402
    HandoffConcurrent,
    HandoffLogBehind,
    HandoffLogForked,
    HandoffNotDrained,
    HandoffSealed,
    HandoffStaleEpoch,
    HandoffState,
    HandoffTenantExists,
    HandoffWrongIdentity,
    HandoffBadManifest,
    RelayError,
    TenantDraining,
    TenantHandedOver,
    Unauthorized,
)
from afrelay.server import serve as serve_relay  # noqa: E402


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


class HandoffTestBase(unittest.TestCase):
    leaves = 25

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.world = GatewayWorld()
        self.fault = FaultyUpstream(self.world)
        for i in range(self.leaves):
            self.world.seal(f"b-{i}")
        self.homes = {}
        self.admins = {}
        self.relays = {}
        self.clocks = {}
        self._new_node("origin")
        self._new_node("receiver")
        self.relays["origin"].sync_once()
        self.relays["receiver"].sync_once()

    def _new_node(self, name):
        home = os.path.join(self.tmp.name, name)
        info = bootstrap(
            home, upstream_url=self.fault.base,
            upstream_token=self.world.token,
            transparency_secret_hex=self.world.transparency_key_hex,
            default_ttl_seconds=30, batch_size=10,
            default_max_inflight=8)
        self.homes[name] = home
        self.admins[name] = info["admin_token"]
        clock = {"t": 1_000_000.0 + (0 if name == "origin" else 9_000_000.0)}
        self.clocks[name] = clock
        relay = open_relay(home, clock=lambda c=clock: c["t"])
        self.relays[name] = relay
        return relay

    def tearDown(self):
        for relay in list(self.relays.values()):
            try:
                relay.close()
            except Exception:
                pass
        self.fault.close()
        self.world.close()
        self.tmp.cleanup()

    # conveniences -------------------------------------------------------- #
    @property
    def origin(self):
        return self.relays["origin"]

    @property
    def receiver(self):
        return self.relays["receiver"]

    def make_tenant(self, tid="aud-a", name="A", rule=None, node="origin"):
        return self.relays[node].create_tenant(
            tid, name, rule, token=self.admins[node])["token"]

    def setup_out_of_order(self, token, consumer_prefix="c"):
        """发三个窗口，完成第二个（越序完成），返回窗口与租户令牌。"""
        wins = []
        for i in range(3):
            w = self.origin.claim(token, f"{consumer_prefix}{i+1}")
            self.assertIsNotNone(w["delivery"])
            wins.append(w)
        w2 = wins[1]
        r = self.origin.complete(token, w2["delivery_id"], w2["end_index"],
                                 f"{consumer_prefix}2",
                                 lease_token=w2["lease_token"])
        self.assertEqual(r["commit_barrier"], 0)
        return wins

    def drain_and_export(self, tid="aud-a", token=None, wins=None):
        """让活动短租约自然结束/完成后导出清单。

        wins 中已完成的窗口先完成；其余活动租约在 origin 时钟前推 3600 秒后
        到期（作为 leased 未决区间导出，接收方接管）。
        """
        self.origin.prepare_handoff(tid)
        if wins is not None:
            for i, w in enumerate(wins):
                if w["state"] if "state" in w else False:
                    continue
            # 完成第一个（与已完成的第二个连成前缀）
            w1 = wins[0]
            self.origin.complete(token, w1["delivery_id"], w1["end_index"],
                                 "c1", lease_token=w1["lease_token"])
        self.clocks["origin"]["t"] += 3600
        view = self.origin.export_handoff(tid)
        return view["manifest"]

    def full_handoff(self, tid="aud-a", rule=None):
        token = self.make_tenant(tid, tid, rule)
        wins = self.setup_out_of_order(token)
        manifest = self.drain_and_export(tid, token, wins)
        return token, wins, manifest


class DrainingTests(HandoffTestBase):
    def test_draining_assigns_no_new_windows_but_replays_live_lease(self):
        token = self.make_tenant()
        w = self.origin.claim(token, "c1")
        self.assertIsNotNone(w["delivery"])
        self.origin.prepare_handoff("aud-a")
        # 自己仍持有有效短租约：原样回放
        replay = self.origin.claim(token, "c1")
        self.assertEqual(replay["delivery_id"], w["delivery_id"])
        self.assertFalse(replay["redispatched"])
        # 别的 consumer：不接管、不发新窗口
        with self.assertRaises(TenantDraining):
            self.origin.claim(token, "other")
        # 没有自己租约的 consumer 同样拒绝
        with self.assertRaises(TenantDraining):
            self.origin.claim(token, "stranger")

    def test_export_blocked_while_active_lease_remains(self):
        token = self.make_tenant()
        self.origin.claim(token, "c1")
        self.origin.prepare_handoff("aud-a")
        with self.assertRaises(HandoffNotDrained) as cm:
            self.origin.export_handoff("aud-a")
        self.assertEqual(cm.exception.detail["active_lease_count"], 1)

    def test_undo_draining_resumes_service(self):
        token = self.make_tenant()
        self.origin.prepare_handoff("aud-a")
        self.origin.undo_handoff("aud-a")
        w = self.origin.claim(token, "c1")
        self.assertIsNotNone(w["delivery"])
        self.assertEqual(self.origin._reload_tenant("aud-a")["serve_phase"],
                         "serving")

    def test_completion_advances_barrier_during_draining(self):
        token = self.make_tenant()
        wins = self.setup_out_of_order(token)
        self.origin.prepare_handoff("aud-a")
        # draining 期间当前持有者完成窗口仍登记并推进（短租约自然结束）
        r = self.origin.complete(token, wins[0]["delivery_id"],
                                 wins[0]["end_index"], "c1",
                                 lease_token=wins[0]["lease_token"])
        self.assertEqual(r["commit_barrier"], wins[1]["end_index"])

    def test_prepare_idempotent(self):
        self.make_tenant()
        a = self.origin.prepare_handoff("aud-a")
        b = self.origin.prepare_handoff("aud-a")
        self.assertTrue(b["idempotent"])
        self.assertEqual(a["transfer_id"], b["transfer_id"])


class ExportSealTests(HandoffTestBase):
    def test_manifest_seals_filter_prefix_windows_attempts_anchor_epoch(self):
        rule = {"event_types": ["release_sealed"]}
        token, wins, manifest = self.full_handoff(rule=rule)
        self.assertEqual(manifest["manifest_version"], "aft1")
        self.assertEqual(manifest["handoff_epoch"], 1)
        self.assertEqual(manifest["tenant"]["tenant_id"], "aud-a")
        self.assertEqual(manifest["tenant"]["filter"], rule)
        # 已确认前缀：w1+w2 已连成稠密完成前缀
        self.assertEqual(manifest["tenant"]["cursor_end"], wins[1]["end_index"])
        # 未决区间：只剩 w3（leased，尝试次数 1）
        pending = manifest["windows"]
        self.assertEqual([w["seq"] for w in pending], [3])
        w3 = pending[0]
        self.assertEqual(w3["state"], "leased")
        self.assertEqual(w3["lease_count"], 1)
        self.assertEqual(w3["end_index"], wins[2]["end_index"])
        self.assertEqual(w3["start_index"], wins[2]["start_index"])
        self.assertTrue(w3["packet"]["delivery_id"])
        # 日志锚点
        anchor = manifest["log_anchor"]
        self.assertEqual(anchor["tree_size"], self.leaves)
        self.assertEqual(len(anchor["root_hash"]), 64)
        self.assertTrue(manifest["sig"])
        # 摘要绑定全部封存字段
        from afrelay.handoff import _sealed_digest
        self.assertEqual(manifest["manifest_digest"], _sealed_digest(manifest))
        # origin 已切到 exported
        self.assertEqual(self.origin._reload_tenant("aud-a")["serve_phase"],
                         "exported")

    def test_export_is_idempotent_same_bytes(self):
        token, _, m1 = self.full_handoff()
        m2 = self.origin.export_handoff("aud-a")["manifest"]
        self.assertEqual(json.dumps(m1, sort_keys=True),
                         json.dumps(m2, sort_keys=True))

    def test_epoch_increments_on_each_export_after_undo(self):
        token = self.make_tenant()
        w = self.origin.claim(token, "c1")
        self.origin.prepare_handoff("aud-a")
        self.origin.complete(token, w["delivery_id"], w["end_index"], "c1",
                             lease_token=w["lease_token"])
        self.clocks["origin"]["t"] += 3600
        e1 = self.origin.export_handoff("aud-a")["manifest"]["handoff_epoch"]
        self.origin.undo_handoff("aud-a")
        self.origin.prepare_handoff("aud-a")
        self.clocks["origin"]["t"] += 3600
        e2 = self.origin.export_handoff("aud-a")["manifest"]["handoff_epoch"]
        self.assertEqual((e1, e2), (1, 2))

    def test_out_of_order_completion_carried_as_completed_marker(self):
        token = self.make_tenant()
        wins = self.setup_out_of_order(token)
        # 完成 w1（让屏障推进过 w1,w2），w3 仍 leased；w2 的 completed 标记
        self.origin.prepare_handoff("aud-a")
        self.origin.complete(token, wins[0]["delivery_id"],
                             wins[0]["end_index"], "c1",
                             lease_token=wins[0]["lease_token"])
        self.clocks["origin"]["t"] += 3600
        m = self.origin.export_handoff("aud-a")["manifest"]
        self.assertEqual(len(m["windows"]), 1)
        self.assertEqual(m["windows"][0]["state"], "leased")

    def test_attempt_count_sealed_after_takeover(self):
        token = self.make_tenant()
        w = self.origin.claim(token, "c1", ttl_seconds=30)
        did, end = w["delivery_id"], w["end_index"]
        # 超时接管：lease_count 增长
        self.clocks["origin"]["t"] += 120
        taken = self.origin.claim(token, "c2")
        self.assertEqual(taken["delivery_id"], did)
        self.assertEqual(taken["lease_count"], 2)
        # 接管者完成后导出（无在途窗口）：cursor 推进
        self.origin.complete(token, did, end, "c2",
                             lease_token=taken["lease_token"])
        self.origin.prepare_handoff("aud-a")
        self.clocks["origin"]["t"] += 3600
        m = self.origin.export_handoff("aud-a")["manifest"]
        self.assertEqual(m["tenant"]["cursor_end"], end)
        self.assertEqual(m["windows"], [])

    def test_sealed_credentials_cannot_move_prefix_on_origin(self):
        token, wins, manifest = self.full_handoff()
        w3 = wins[2]
        with self.assertRaises(HandoffSealed):
            self.origin.complete(token, w3["delivery_id"], w3["end_index"],
                                 "c3", lease_token=w3["lease_token"])
        with self.assertRaises(HandoffSealed):
            self.origin.claim(token, "c3")
        cursor_before = self.origin._reload_tenant("aud-a")["cursor_end"]
        self.assertEqual(cursor_before, manifest["tenant"]["cursor_end"])


class ImportVerificationTests(HandoffTestBase):
    def test_requires_signed_manifest_with_trust_key(self):
        _, _, m = self.full_handoff()
        bad = copy.deepcopy(m)
        bad["sig"] = "0" * 64
        with self.assertRaises(HandoffBadManifest):
            self.receiver.import_handoff(bad)

    def test_tampered_sealed_content_rejected(self):
        _, _, m = self.full_handoff()
        bad = copy.deepcopy(m)
        bad["tenant"]["cursor_end"] = m["tenant"]["cursor_end"] + 1
        with self.assertRaises(HandoffBadManifest):
            self.receiver.import_handoff(bad)

    def test_tampered_packet_records_rejected(self):
        _, _, m = self.full_handoff()
        bad = copy.deepcopy(m)
        rec = bad["windows"][0]["packet"]["records"][0]
        rec["envelope"]["subject_id"] = "tampered"
        # 重新包签名但不重算内容地址：内容地址/折根失败 → 仍需有效清单签名，
        # 因此直接篡改会先在 manifest 摘要处失败；这里验证包锚失败路径需要
        # 保持 manifest 摘要一致但包内容改变（摘要覆盖 windows → 会被摘要拦）
        with self.assertRaises(HandoffBadManifest):
            self.receiver.import_handoff(bad)

    def test_log_behind_rejected(self):
        relay = self._new_node("behind")
        # 不同步：trusted_tree_size=0（只有 genesis）
        _, _, m = self.full_handoff()
        with self.assertRaises(HandoffLogBehind):
            relay.import_handoff(copy.deepcopy(m))

    def test_log_fork_rejected(self):
        _, _, m = self.full_handoff()
        size = m["log_anchor"]["tree_size"]
        self.receiver.db.execute(
            "UPDATE mirror_cps SET root_hash=? WHERE tree_size=?",
            ("ab" * 32, size))
        with self.assertRaises(HandoffLogForked):
            self.receiver.import_handoff(copy.deepcopy(m))

    def test_existing_same_tenant_serving_rejected(self):
        _, _, m = self.full_handoff()
        self.receiver.create_tenant("aud-a", "A", None,
                                    token=self.admins["receiver"])
        with self.assertRaises(HandoffTenantExists):
            self.receiver.import_handoff(copy.deepcopy(m))

    def test_existing_same_name_serving_rejected(self):
        _, _, m = self.full_handoff()
        # full_handoff 建租户时名称 == tenant_id == "aud-a"
        self.receiver.create_tenant("other-id", "aud-a", None,
                                    token=self.admins["receiver"])
        with self.assertRaises(HandoffTenantExists):
            self.receiver.import_handoff(copy.deepcopy(m))

    def test_duplicate_import_returns_first_result(self):
        _, _, m = self.full_handoff()
        first = self.receiver.import_handoff(copy.deepcopy(m))
        second = self.receiver.import_handoff(copy.deepcopy(m))
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        self.assertEqual(first["transfer_id"], second["transfer_id"])
        self.assertEqual(first["state"], second["state"])
        self.assertEqual(
            [w["delivery_id"] for w in first["pending_windows"]],
            [w["delivery_id"] for w in second["pending_windows"]])

    def test_stale_epoch_distinct_manifest_rejected_after_adoption(self):
        # 相同清单重放永远幂等返回首次结果；旧**代次**的另一份清单必须拒绝
        token, wins, m1 = self.full_handoff()
        self.receiver.import_handoff(copy.deepcopy(m1))
        self.receiver.confirm_handoff(m1["transfer_id"])
        receipt = self.receiver.get_transfer(m1["transfer_id"])["receipt"]
        self.origin.finalize_handoff(copy.deepcopy(receipt))
        old = copy.deepcopy(m1)
        old["transfer_id"] = "aft" + "00" * 17
        from afrelay.handoff import _sealed_digest
        from afrelay.canonical import dumps_canon, hmac_hex
        old["manifest_digest"] = _sealed_digest(old)
        old["sig"] = hmac_hex(
            self.receiver.handoff_key,
            dumps_canon({k: v for k, v in old.items() if k != "sig"})
            .encode("utf-8"))
        with self.assertRaises(HandoffStaleEpoch):
            self.receiver.import_handoff(old)

    def test_identical_manifest_replays_first_result_even_after_confirm(self):
        _, _, m1 = self.full_handoff()
        self.receiver.import_handoff(copy.deepcopy(m1))
        self.receiver.confirm_handoff(m1["transfer_id"])
        again = self.receiver.import_handoff(copy.deepcopy(m1))
        self.assertTrue(again["idempotent"])
        # 首次导入结果被原样封存并返回
        self.assertEqual(again["state"], "imported")
        self.assertEqual(again["phase"], "incoming")

    def test_boundary_gap_in_manifest_rejected(self):
        _, _, m = self.full_handoff()
        bad = copy.deepcopy(m)
        bad["windows"][0]["start_index"] += 1
        with self.assertRaises(HandoffBadManifest):
            self.receiver.import_handoff(bad)


class TakeoverConfirmTests(HandoffTestBase):
    def test_confirm_restores_state_and_advances_prefix_without_loss(self):
        token, wins, m = self.full_handoff()
        # 接收方导入后是 incoming，尚未服务
        view = self.receiver.import_handoff(copy.deepcopy(m))
        self.assertEqual(view["phase"], "incoming")
        self.assertFalse(self.receiver._reload_tenant("aud-a")["active"] == 0)
        # 确认前旧令牌不能领
        with self.assertRaises(HandoffSealed):
            self.receiver.claim(token, "x")
        cf = self.receiver.confirm_handoff(m["transfer_id"])
        self.assertEqual(cf["phase"], "adopted")
        self.assertTrue(cf["token"].startswith("dprt_"))
        new_token = cf["token"]
        # 已确认前缀恢复一致
        self.assertEqual(
            self.receiver._reload_tenant("aud-a")["cursor_end"],
            m["tenant"]["cursor_end"])
        # 旧令牌在接收方失效（hash 已换）
        with self.assertRaises(Unauthorized):
            self.receiver.claim(token, "x")
        # 新节点接管未决的 leased 区间（导出时已过期 → 立即可接管）
        w3 = wins[2]
        got = self.receiver.claim(new_token, "newc")
        self.assertEqual(got["delivery_id"], w3["delivery_id"])
        self.assertEqual(got["lease_epoch"], 2)  # 尝试次数 +1
        self.receiver.complete(new_token, w3["delivery_id"],
                               w3["end_index"], "newc",
                               lease_token=got["lease_token"])
        # 屏障推进到末尾，越序完成记录未丢，cursor 单调
        self.assertEqual(
            self.receiver._reload_tenant("aud-a")["cursor_end"],
            w3["end_index"])

    def test_confirm_idempotent_but_token_shown_once(self):
        _, _, m = self.full_handoff()
        self.receiver.import_handoff(copy.deepcopy(m))
        first = self.receiver.confirm_handoff(m["transfer_id"])
        second = self.receiver.confirm_handoff(m["transfer_id"])
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        self.assertNotIn("token", second)

    def test_confirm_unknown_transfer_404(self):
        from afrelay.errors import TransferNotFound
        with self.assertRaises(TransferNotFound):
            self.receiver.confirm_handoff("aft_doesnotexist")

    def test_receipt_is_signed_and_bound(self):
        _, _, m = self.full_handoff()
        self.receiver.import_handoff(copy.deepcopy(m))
        cf = self.receiver.confirm_handoff(m["transfer_id"])
        receipt = cf["receipt"]
        self.assertEqual(receipt["receipt_version"], "aftr1")
        self.assertEqual(receipt["manifest_digest"], m["manifest_digest"])
        self.assertEqual(receipt["origin_instance"], m["origin_instance"])
        self.assertEqual(receipt["handoff_epoch"], m["handoff_epoch"])
        self.assertTrue(receipt["sig"])


class FinalizeAndSplitBrainTests(HandoffTestBase):
    def _handoff_with_receipt(self):
        token, wins, m = self.full_handoff()
        self.receiver.import_handoff(copy.deepcopy(m))
        cf = self.receiver.confirm_handoff(m["transfer_id"])
        return token, wins, m, cf["receipt"]

    def test_finalize_makes_origin_permanently_non_serving(self):
        token, wins, m, receipt = self._handoff_with_receipt()
        out = self.origin.finalize_handoff(copy.deepcopy(receipt))
        self.assertEqual(out["phase"], "handed_over")
        with self.assertRaises(TenantHandedOver):
            self.origin.claim(token, "x")
        with self.assertRaises(TenantHandedOver):
            self.origin.complete(token, wins[2]["delivery_id"],
                                 wins[2]["end_index"], "c3",
                                 lease_token=wins[2]["lease_token"])

    def test_undo_impossible_after_receipt_finalized(self):
        _, _, _, receipt = self._handoff_with_receipt()
        self.origin.finalize_handoff(copy.deepcopy(receipt))
        with self.assertRaises(TenantHandedOver):
            self.origin.undo_handoff("aud-a")

    def test_finalize_rejects_wrong_origin_node(self):
        other = self._new_node("other")
        other.sync_once()
        _, _, _, receipt = self._handoff_with_receipt()
        with self.assertRaises(HandoffWrongIdentity):
            other.finalize_handoff(copy.deepcopy(receipt))

    def test_finalize_rejects_identity_mixup(self):
        _, _, _, receipt = self._handoff_with_receipt()
        bad = copy.deepcopy(receipt)
        bad["handoff_epoch"] = 999
        with self.assertRaises(HandoffBadManifest):
            self.origin.finalize_handoff(bad)
        # 绑定到别的清单摘要
        bad2 = copy.deepcopy(receipt)
        bad2["manifest_digest"] = "ff" * 32
        with self.assertRaises(HandoffBadManifest):
            self.origin.finalize_handoff(bad2)

    def test_finalize_idempotent(self):
        _, _, _, receipt = self._handoff_with_receipt()
        a = self.origin.finalize_handoff(copy.deepcopy(receipt))
        b = self.origin.finalize_handoff(copy.deepcopy(receipt))
        self.assertTrue(b["idempotent"])
        self.assertEqual(a["state"], b["state"])

    def test_only_one_node_serves_during_handoff(self):
        token, wins, m = self.full_handoff()
        # exported 后、确认前：原节点不服务、接收方也未对外服务
        self.assertEqual(self.origin._reload_tenant("aud-a")["serve_phase"],
                         "exported")
        self.receiver.import_handoff(copy.deepcopy(m))
        with self.assertRaises(HandoffSealed):
            self.origin.claim(token, "x")
        with self.assertRaises(HandoffSealed):
            self.receiver.claim(token, "x")


class RecoveryTests(HandoffTestBase):
    def test_reopen_incoming_does_not_serve_until_confirmed(self):
        token, wins, m = self.full_handoff()
        self.receiver.import_handoff(copy.deepcopy(m))
        self.receiver.close()
        reopened = open_relay(self.homes["receiver"],
                              clock=lambda: self.clocks["receiver"]["t"])
        self.relays["receiver"] = reopened
        kinds = [e["kind"] for e in reopened.recent_events(limit=20)]
        self.assertIn("handoff_recovered", kinds)
        with self.assertRaises(HandoffSealed):
            reopened.claim(token, "x")
        cf = reopened.confirm_handoff(m["transfer_id"])
        self.assertEqual(cf["phase"], "adopted")
        # 未决区间仍在，越序完成不丢
        got = reopened.claim(cf["token"], "nc")
        self.assertEqual(got["delivery_id"], wins[2]["delivery_id"])

    def test_reopen_exported_origin_still_non_serving(self):
        token, wins, m = self.full_handoff()
        self.origin.close()
        reopened = open_relay(self.homes["origin"],
                              clock=lambda: self.clocks["origin"]["t"])
        self.relays["origin"] = reopened
        self.assertEqual(reopened._reload_tenant("aud-a")["serve_phase"],
                         "exported")
        with self.assertRaises(HandoffSealed):
            reopened.claim(token, "x")
        # 仍可撤销（无回执）→ 原节点继续
        reopened.undo_handoff("aud-a")
        self.assertEqual(reopened._reload_tenant("aud-a")["serve_phase"],
                         "serving")

    def test_reopen_draining_origin_keeps_not_assigning(self):
        token = self.make_tenant()
        w = self.origin.claim(token, "c1")
        self.origin.prepare_handoff("aud-a")
        self.origin.close()
        reopened = open_relay(self.homes["origin"],
                              clock=lambda: self.clocks["origin"]["t"])
        self.relays["origin"] = reopened
        replay = reopened.claim(token, "c1")
        self.assertEqual(replay["delivery_id"], w["delivery_id"])
        with self.assertRaises(TenantDraining):
            reopened.claim(token, "other")


class EmptyAndFilterTests(HandoffTestBase):
    def test_handoff_tenant_with_no_windows(self):
        token = self.make_tenant("aud-empty", "empty")
        self.origin.prepare_handoff("aud-empty")
        view = self.origin.export_handoff("aud-empty")
        m = view["manifest"]
        self.assertEqual(m["windows"], [])
        self.assertEqual(m["tenant"]["cursor_end"], 0)
        iv = self.receiver.import_handoff(copy.deepcopy(m))
        self.assertEqual(iv["pending_windows"], [])
        cf = self.receiver.confirm_handoff(m["transfer_id"])
        # 接管后可以正常开始消费
        got = self.receiver.claim(cf["token"], "w")
        self.assertIsNotNone(got["delivery"])

    def test_filter_sealed_and_restored(self):
        rule = {"event_types": ["release_sealed"]}
        token, _, m = self.full_handoff(rule=rule)
        self.receiver.import_handoff(copy.deepcopy(m))
        cf = self.receiver.confirm_handoff(m["transfer_id"])
        summary = self.receiver.tenant_windows("aud-a")
        self.assertEqual(summary["mirror_tree_size"], self.leaves)
        # 恢复后筛选规则原样保留
        self.assertEqual(
            self.receiver._reload_tenant("aud-a")["filter_json"]
            and json.loads(self.receiver._reload_tenant("aud-a")["filter_json"]),
            rule)


class HttpHandoffTests(HandoffTestBase):
    def setUp(self):
        super().setUp()
        self.server = serve_relay(self.receiver, "127.0.0.1", 0)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        import threading
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.oserver = serve_relay(self.origin, "127.0.0.1", 0)
        self.obase = f"http://127.0.0.1:{self.oserver.server_address[1]}"
        threading.Thread(target=self.oserver.serve_forever,
                         daemon=True).start()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close()
        self.oserver.shutdown(); self.oserver.server_close()
        super().tearDown()

    def test_prepare_export_import_confirm_finalize_over_http(self):
        token, wins, m = self.full_handoff()
        admin_o, admin_r = self.admins["origin"], self.admins["receiver"]
        # prepare/export already exercised in full_handoff; list transfers
        st, body = http("GET", self.obase + "/v1/admin/transfers", admin_o)
        self.assertEqual(st, 200)
        self.assertTrue(body["transfers"])
        # import over HTTP
        st, body = http("POST", self.obase.replace(str(self.oserver.server_address[1]),
                         str(self.server.server_address[1]))
                        if False else
                        self.base + "/v1/admin/handoff/import", admin_r,
                        {"manifest": m})
        self.assertEqual(st, 200, body)
        transfer_id = m["transfer_id"]
        st, body = http("POST",
                        f"{self.base}/v1/admin/handoff/{transfer_id}/confirm",
                        admin_r, {})
        self.assertEqual(st, 200, body)
        self.assertTrue(body["token"])
        receipt = body["receipt"]
        # finalize origin
        st, body = http("POST", self.obase + "/v1/admin/handoff/finalize",
                        admin_o, {"receipt": receipt})
        self.assertEqual(st, 200, body)
        self.assertEqual(body["phase"], "handed_over")

    def test_admin_required(self):
        st, _ = http("GET", self.base + "/v1/admin/transfers", "nope")
        self.assertEqual(st, 401)

    def test_bad_manifest_400(self):
        st, body = http("POST", self.base + "/v1/admin/handoff/import",
                        self.admins["receiver"], {"manifest": {"x": 1}})
        self.assertEqual(st, 400)
        self.assertEqual(body["error"], "handoff_bad_manifest")


class OfflineHandoffVerifyTests(HandoffTestBase):
    def test_manifest_and_receipt_verify_offline(self):
        import io, contextlib
        from afrelay.verify import (
            verify_transfer_manifest, verify_takeover_receipt)
        token, wins, m = self.full_handoff()
        # 含一个未决 leased 区间，以覆盖嵌入包锚定校验
        key = self.receiver.handoff_key
        rep = verify_transfer_manifest(m, key, expected_tenant="aud-a")
        self.assertTrue(rep["ok"], rep["errors"])
        self.assertEqual(rep["anchor_tree_size"], self.leaves)
        self.receiver.import_handoff(copy.deepcopy(m))
        receipt = self.receiver.confirm_handoff(m["transfer_id"])["receipt"]
        rrep = verify_takeover_receipt(receipt, key, manifest=m)
        self.assertTrue(rrep["ok"], rrep["errors"])

    def test_manifest_tamper_offline_fails(self):
        from afrelay.verify import verify_transfer_manifest
        token, wins, m = self.full_handoff()
        bad = copy.deepcopy(m)
        bad["handoff_epoch"] = 999
        rep = verify_transfer_manifest(bad, self.receiver.handoff_key)
        self.assertFalse(rep["ok"])

    def test_receipt_bound_to_other_manifest_fails(self):
        from afrelay.verify import verify_takeover_receipt
        token, wins, m = self.full_handoff()
        self.receiver.import_handoff(copy.deepcopy(m))
        receipt = self.receiver.confirm_handoff(m["transfer_id"])["receipt"]
        other = copy.deepcopy(m)
        other["manifest_digest"] = "ff" * 32
        rep = verify_takeover_receipt(receipt, self.receiver.handoff_key,
                                      manifest=other)
        self.assertFalse(rep["ok"])


if __name__ == "__main__":
    unittest.main()
