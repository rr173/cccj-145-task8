"""中继错误：稳定机器码 + HTTP 状态 + 拒绝归类。

``reject_reason`` 为真的错误表示租户请求被安全拒绝且**不移动消费位点**，
会落入租户隔离的拒绝日志并显示在运维页。
"""

from __future__ import annotations


class RelayError(Exception):
    code = "relay_error"
    status = 500
    reject_reason: str | None = None  # 非空表示这是一条对外可见的拒绝原因

    def __init__(self, message: str = "", *, detail: dict | None = None):
        super().__init__(message or self.code)
        self.message = message or self.code
        self.detail = detail or {}

    def to_dict(self) -> dict:
        d = {"error": self.code, "message": self.message}
        d.update(self.detail)
        return d


class InvalidBody(RelayError):
    code = "invalid_body"
    status = 400


class Unauthorized(RelayError):
    code = "unauthorized"
    status = 401


class TenantInactive(RelayError):
    """已停用租户的一切投递/确认请求都拒绝且不动位点。"""

    code = "tenant_inactive"
    status = 403
    reject_reason = "tenant_inactive"


class FilterLocked(RelayError):
    """租户一旦开始消费（有在途/已确认投递），其筛选规则即冻结。"""

    code = "filter_locked"
    status = 409
    reject_reason = "filter_locked"


class LeaseConflict(RelayError):
    """租户的全部窗口槽位都被**其他** consumer 有效持有（无可接管窗口）。"""

    code = "lease_conflict"
    status = 409
    reject_reason = "lease_conflict"


class InFlightCapReached(RelayError):
    """达到该租户最大在途窗口数，且没有可重放/可接管的窗口；稍后重试。

    与 :class:`LeaseConflict` 的区别：调用方往往**自己**也持有窗口（并行
    处理时这是常态），只是没有空余槽位；这不是争抢冲突而是背压。
    收缩生效后同样走到这里——已发放的窗口绝不被抢走。
    """

    code = "inflight_cap_reached"
    status = 409
    reject_reason = "inflight_cap_reached"


class AckEndMismatch(RelayError):
    """确认位置不是窗口末端（越过窗口末端/部分确认/跳段）。"""

    code = "ack_end_mismatch"
    status = 409
    reject_reason = "ack_end_mismatch"


class StaleLease(RelayError):
    """用旧租约（已超时被回收并改投）确认。"""

    code = "stale_lease"
    status = 409
    reject_reason = "stale_lease"


class BadDelivery(RelayError):
    """delivery_id 不属于该租户（越租户/未知 id）。"""

    code = "bad_delivery"
    status = 403
    reject_reason = "bad_delivery"


class FilterInvalid(RelayError):
    code = "filter_invalid"
    status = 400


class InvalidConfig(RelayError):
    code = "invalid_config"
    status = 400


class TenantNotFound(RelayError):
    code = "tenant_not_found"
    status = 404


class DeliveryNotFound(RelayError):
    code = "delivery_not_found"
    status = 404


class TenantAlreadyExists(RelayError):
    code = "tenant_already_exists"
    status = 409


# --------------------------------------------------------------------------- #
# cross-node consumer ownership handoff (rolling maintenance / capacity moves)
# --------------------------------------------------------------------------- #

class HandoffError(RelayError):
    """跨节点消费归属转移的拒绝基类（稳定机器码）。"""

    code = "handoff_error"
    status = 409


class HandoffActiveLeases(HandoffError):
    """导出时仍有未自然结束的短租约：等它们到期/完成后再导出。"""

    code = "handoff_active_leases"
    status = 409


class HandoffStateConflict(HandoffError):
    """操作与当前转移阶段不符（如未准备就导出、已导出再准备）。"""

    code = "handoff_state_conflict"
    status = 409


class HandoffStaleEpoch(HandoffError):
    """清单代次比接收方已有代次旧（handoff_epoch 只增）。"""

    code = "handoff_stale_epoch"
    status = 409


class HandoffConflict(HandoffError):
    """同消费方已有不同清单/谱系（内容被换、与既有导入不是同一条转移链）。"""

    code = "handoff_conflict"
    status = 409


class HandoffLogBehind(HandoffError):
    """接收方的可信日志尚未包含清单绑定的树头（同步上来再导入）。"""

    code = "handoff_log_behind"
    status = 409


class HandoffFork(HandoffError):
    """接收方在清单锚定高度的根与清单不一致：日志分叉，拒绝接管。"""

    code = "handoff_log_fork"
    status = 409


class HandoffConcurrent(HandoffError):
    """并发导入/确认竞争失败（同名消费方行已被另一个导入抢先建立）。"""

    code = "handoff_concurrent"
    status = 409


class HandoffIdentityMismatch(HandoffError):
    """回执/清单绑定的双方实例或消费方身份对不上（身份串用）。"""

    code = "handoff_identity_mismatch"
    status = 400


class HandoffSelf(HandoffError):
    """把节点自己导出的清单导回自己（实例身份相同）。"""

    code = "handoff_self"
    status = 400


class HandoffNotImported(HandoffError):
    code = "handoff_not_imported"
    status = 404


class HandoffReceiptInvalid(HandoffError):
    """接管回执验签/绑定失败（伪造、错钥、身份对不上）。"""

    code = "handoff_receipt_invalid"
    status = 400


class HandoffTampered(HandoffError):
    """转移清单验签失败或结构被篡改。"""

    code = "handoff_tampered"
    status = 400


class TenantRelinquished(RelayError):
    """原节点已产生接管回执：该消费方在本节点永久失去服务权。"""

    code = "tenant_relinquished"
    status = 403
    reject_reason = "tenant_relinquished"


class TenantDraining(RelayError):
    """消费方处于 draining：不再发放新窗口（短租约确认仍被接受至到期）。"""

    code = "tenant_draining"
    status = 409
    reject_reason = "tenant_draining"


class UpstreamError(RelayError):
    """拉取/验证失败：上游暂不可用、回退、坏签名、证明缺口等。

    同步在最后可信位置*停止前进*；这不是 4xx 客户端错误，同步循环捕获后
    只记运维事件，绝不伪造记录。
    """

    code = "upstream_error"
    status = 502

    def __init__(self, message: str = "", *, reason: str = "upstream_unavailable",
                 trusted_size: int | None = None, detail: dict | None = None):
        super().__init__(message, detail=detail)
        self.reason = reason
        self.trusted_size = trusted_size
        self.detail.setdefault("reason", reason)
        if trusted_size is not None:
            self.detail["trusted_tree_size"] = trusted_size
