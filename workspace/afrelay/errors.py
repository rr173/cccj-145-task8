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


class TenantHandedOver(RelayError):
    """消费归属已随接管回执永久转移：原节点不再具有服务权。"""

    code = "tenant_handed_over"
    status = 409
    reject_reason = "tenant_handed_over"


class TenantDraining(RelayError):
    """租户正在跨节点转移（draining/已导出）：不再分配新窗口。

    短租约在此期间自然结束；完成提交仍允许（直到清单导出封存），但不会有
    新窗口从本节点发出。
    """

    code = "tenant_draining"
    status = 409
    reject_reason = "tenant_draining"


class HandoffSealed(RelayError):
    """转移清单导出后，转移前签发的凭据不得再推动已确认前缀。"""

    code = "handoff_sealed"
    status = 409
    reject_reason = "handoff_sealed"


class HandoffNotDrained(RelayError):
    """导出清单时仍有未结束的有效短租约；等待其自然到期后再导出。"""

    code = "handoff_not_drained"
    status = 409


class HandoffBadManifest(RelayError):
    """转移清单格式错误、签名无效、内容被篡改或未决区间无法锚定本地日志。"""

    code = "handoff_bad_manifest"
    status = 400


class HandoffStaleEpoch(RelayError):
    """handoff_epoch 过时：每个租户的代次只增，旧代次清单拒绝导入。"""

    code = "handoff_stale_epoch"
    status = 409


class HandoffLogBehind(RelayError):
    """接收方透明日志尚未包含清单绑定的可信树头（高度落后）。"""

    code = "handoff_log_behind"
    status = 409


class HandoffLogForked(RelayError):
    """接收方在同一高度存档了不同根：日志分叉，拒绝接管。"""

    code = "handoff_log_forked"
    status = 409


class HandoffTenantExists(RelayError):
    """同名（同 id/名称）消费方仍在本节点服务；不能原样恢复。"""

    code = "handoff_tenant_exists"
    status = 409


class HandoffConcurrent(RelayError):
    """同一消费方有另一个进行中的导入；并发导入只允许一个胜出。"""

    code = "handoff_concurrent"
    status = 409


class HandoffWrongIdentity(RelayError):
    """接管回执与本节点导出的清单/租户/代次不一致（身份串用）。"""

    code = "handoff_wrong_identity"
    status = 409


class HandoffState(RelayError):
    """转移阶段不允许该操作（如回执产生后撤销、未导入就确认）。"""

    code = "handoff_state"
    status = 409


class TransferNotFound(RelayError):
    code = "transfer_not_found"
    status = 404


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
