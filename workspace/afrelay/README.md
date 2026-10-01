# afrelay — 独立审计馈送中继（audit-feed relay）

只读镜像现有 DPGW 网关的防分叉透明度日志，并向多个互相隔离的**审计租户**
发放可验证、可重放的连续投递包。中继是一个**独立运行**的进程与一套
**独立持久化**：它只通过网关的只读 HTTP 接口拉取数据，从不打开网关
SQLite、从不调用任何写接口，**绝不自行补造记录**。

零第三方依赖，仅用 Python 3.11 标准库；信任锚只有机构带外分发的
`transparency_secret`（与网关 `secrets.json` 中同名字段一致）。

## 核心安全语义

| 需求 | 实现 |
|---|---|
| 只经只读接口拉取 | 仅 `GET /v1/transparency{,/checkpoint,/inclusion/<i>}`；不打网关库，不调写接口 |
| 验证后才镜像 | 每个高度的签名 checkpoint 用 transparency_secret 独立验 HMAC；每片叶子校验内容地址 `SHA256(0x00‖规范信封)`、event 绑定、inclusion_path 折到已签名根、checkpoint prev 链接到本库存档的上一高度 |
| 失败停止并保留最后可信位置 | 上游不可用 / 回退高度 / 坏签名 / 证明缺口 / 坏叶子 → 本轮不落任何新行，`trusted_tree_size` 不动，记录停止原因；恢复后从同一高度续传 |
| 绝不补造 | 区间内任一叶子验证不过即停在该叶之前；不存在“跳过缺口继续”路径，镜像叶子按原始序号稠密 0..n-1 |
| 冻结上游封顶 | 上游 `frozen` 时只读到 `frozen_tree_size`（最后可信树头），之后的高度即使返回也不镜像 |
| 多租户隔离 | 每租户独立令牌（`dprt_…`）、独立筛选规则、独立提交屏障；越租户 delivery_id 返回 `403 bad_delivery` 且不泄露归属、不动屏障 |
| 并行窗口（相邻不重叠） | 同一审计租户可并行处理**多个相邻窗口**：中继把互不重叠的原始序号区间租给不同 worker，无需等上一包提交；窗口按发放前沿依次切出，天然稠密相邻 |
| 最大在途窗口数 | 每租户 `max_inflight`（默认 8，可动态收缩/放大）；槽位满且还有未发数据时领取返回 `409 inflight_cap_reached` 背压 |
| 收缩不抢持有者 | 收缩只更新上限、立即对新领取生效；已发放窗口（含已完成待补洞）继续属于其持有者，在途数降到新上限前新窗口一律不放 |
| 连续提交屏障 | 靠后的窗口先完成**只登记完成事实**（`completed`）；可见提交点 `cursor_end` 必须等前面的空洞补齐、完成窗口连成稠密前缀后才**一次推进**（`window_barrier_advanced`） |
| 超时接管 + epoch | 超时窗口可由新 worker 接管：窗口边界/`delivery_id`/字节不变，持有者替换、租约 epoch+1、旧 `lease_token` 作废；旧持有者随后提交返回 `409 stale_lease` |
| 稳定重投 | 窗口是已镜像叶子的确定性纯函数：接管或进程重启后重新领取返回**同一 `delivery_id` 与逐字节相同 JSON**，`lease_count/retries` 增长；重启不改边界、完成记录或提交顺序 |
| 非法提交不推进屏障 | 重复提交（幂等）、越过窗口末端、跨租户 id、停用状态、筛选规则变更——全部拒绝且屏障不动 |
| 慢窗口不阻塞 | 单个慢窗口不挡住其他租户或同租户后续窗口的领取/完成；它只挡住自己租户的屏障推进，后续窗口可继续发放与先完成 |
| 运行中改筛选拒绝 | 租户一旦发出过窗口（含在途），筛选规则锁定，修改返回 `409 filter_locked` 且规则不变 |
| 已停用租户拒绝 | 停用后 claim/complete 一律 `403 tenant_inactive`，屏障与历史保留，永不前移 |
| 拒绝可审计 | 每次拒绝（回滚业务写之后）单独落一条 `reject` 事件，带稳定 `reason`，运维页/状态/CLI 可见 |
| 跨节点归属转移 | 滚动维护/容量调整时把租户消费状态原样搬到另一实例：draining 不发新窗口、短租约自然结束；签名 `aft1` transfer manifest 封存筛选/已确认前缀/未决区间边界/完成标记/尝试次数并绑定可信树头，`handoff_epoch` 只增；接收方日志须包含锚点头且无同名消费方；`aftr1` 接管回执产生后原节点永久失权，转移前凭据双方都不能改变已确认前缀 |

## 跨节点消费归属转移（handoff）

把一个审计租户的消费状态从一个中继实例**原样**搬到另一个实例，任何时刻
至多一个节点对外服务，已确认前缀不回退、越序完成记录不丢失。信任锚仍是机构
带外分发的 `transparency_secret`：清单与回执都用它签名，跨节点可离线验真。

阶段（`tenants.serve_phase`）：

```
serving ──prepare──▶ draining ──export──▶ exported ──finalize(回执)──▶ handed_over
   ▲                     │ undrain              │ undrain
   └─────────────────────┴───────────────────────┘      （接管回执产生后不可逆）
接收方：(无同名消费方) ──import──▶ incoming ──confirm──▶ adopted（换发新租户令牌）
```

1. **准备（prepare → draining）**：发起方不再分配新窗口；调用方仍持有的
   有效短租约可以原样回放并**自然结束**，完成提交照常登记、连续提交屏障
   照常补洞推进。此阶段可以撤销（undo），原节点继续服务。
2. **导出（export → 签名 aft1 manifest）**：所有在途短租约必须已结束，否则
   返回 `409 handoff_not_drained`。清单封存：筛选条件、已确认前缀
   （`cursor_end`）、**每个未决区间的边界、完成标记（leased/completed）与
   尝试次数（lease_count/epoch）**、对应 afp1 包，以及导出时刻的**可信树头**
   （`log_anchor: tree_size/root_hash/checkpoint`）。`handoff_epoch` 每次导出
   **只增**（撤销后再导出用更新的代次）。导出幂等：重复导出返回同一份字节。
   导出后，转移前签发的凭据在**双方**都不能再取得窗口或改变已确认前缀
   （`409 handoff_sealed`）。
3. **导入（import）**：接收方独立验证：清单 HMAC 与封存摘要（内容篡改/外域
   密钥 → `400 handoff_bad_manifest`）；本地透明日志**至少包含**清单绑定的
   可信树头（落后 → `409 handoff_log_behind`）；同高度根一致（分叉 →
   `409 handoff_log_forked`）；没有同名/同 id 的在服消费方（→
   `handoff_tenant_exists`）；旧代次 → `handoff_stale_epoch`；并发导入 →
   `handoff_concurrent`；每个未决区间的锚 checkpoint 与叶 inclusion 证明都
   必须折到本地同一树头。通过后租户以 `incoming`（不对外服务）原样恢复。
   **相同清单再次导入永远返回首次结果**（`idempotent=true`）。
4. **确认接管（confirm → aftr1 回执）**：接收方产生签名接管回执并**换发新
   租户令牌**；旧令牌在双方失效。回执绑定 `manifest_digest`、双方实例 id、
   `handoff_epoch` 与日志锚点。回执产生**前**发起方可撤销 draining；回执
   一经产生，原节点登记回执（finalize）后进入 `handed_over`、**永久失去
   服务权**（claim/complete 一律 `409 tenant_handed_over`，undo 也失败）。
5. **崩溃恢复**：`recover_handoffs`（每次打开 home 自动执行）核对
   draining/exported/incoming 未决转移；这些阶段本身都不对外发放新窗口，
   因此准备/导出/导入/确认期间任一退出后，结果只能是“原节点继续”
   （draining 撤销）或“新节点接管”（import→confirm），不可能双主，越序完成
   记录随清单封存原样恢复。

```bash
# 发起方：准备 → 等待短租约到期 → 导出清单（可在回执前撤销）
python -m afrelay handoff ./relay-a prepare aud-a --admin-token afra_…
python -m afrelay handoff ./relay-a export  aud-a --out handoff.json --admin-token afra_…
python -m afrelay handoff ./relay-a undo    aud-a --admin-token afra_…        # 回执前可撤销

# 接收方：先 sync 到不低于清单锚点高度，再导入、确认（回执 + 一次性新令牌）
python -m afrelay sync ./relay-b
python -m afrelay handoff ./relay-b import  --manifest handoff.json --admin-token afra_…
python -m afrelay handoff ./relay-b confirm <transfer_id> --receipt-out receipt.json --admin-token afra_…

# 发起方登记回执 → 永久移交；查看转移（阶段/双方实例/锚点/epoch/未决区间/拒绝原因）
python -m afrelay handoff ./relay-a finalize --receipt receipt.json --admin-token afra_…
python -m afrelay handoff ./relay-a list --tenant aud-a --admin-token afra_…
python -m afrelay handoff ./relay-b get <transfer_id> --admin-token afra_…

# 离线验真（只需含 transparency_secret 的 secrets.json）
python -m afrelay verify manifest --manifest handoff.json --secrets ./relay-b/secrets.json
python -m afrelay verify receipt  --receipt receipt.json --manifest handoff.json \
    --secrets ./relay-b/secrets.json
```

HTTP（管理员）：`POST /v1/admin/tenants/<id>/handoff/{prepare,undo,export}`、
`POST /v1/admin/handoff/import`、`POST /v1/admin/handoff/<transfer_id>/confirm`、
`POST /v1/admin/handoff/finalize`、`GET /v1/admin/transfers{/<id>}`。
运维页 `/ui` 展示每个租户的转移阶段/epoch、转移卡片（双方实例、日志锚点、
未决区间、拒绝原因、回执），并支持准备、撤销、导出（下载清单）、导入清单、
确认接管（下载回执/显示一次性新令牌）与登记回执。

## 数据与包格式

镜像库（`relay.sqlite`，与 `gateway.sqlite` 完全分离）：

- `mirror_state`：`trusted_tree_size`（最后可信高度）、上游观察高度、
  冻结观察、`last_status`（`never|caught_up|caught_up_frozen|stopped`）、
  `last_stop_reason`、`consecutive_failures` 等；
- `mirror_leaves`：稠密叶子 0..trusted-1（内容寻址 + 规范信封）；
- `mirror_cps`：每个已验证高度的签名 checkpoint（逐字节存档）；
- `tenants`：令牌哈希、筛选 JSON、**连续提交屏障 `cursor_end`**、
  **最大在途窗口数 `max_inflight`**、启停、**跨节点转移阶段 `serve_phase`
  （serving/draining/exported/incoming/adopted/handed_over）与只增
  `handoff_epoch`**；
- `deliveries`：窗口（相邻区间）与持久化的 afp1 包字节、租约
  holder/到期/epoch/不透明 `lease_token`、`lease_count`、状态
  （`leased` 已租出未完成 | `completed` 已完成待补洞 |
  `committed` 已越过连续提交屏障）。边界 `start/end` 在首次发放时落库，
  此后永不改变；重启不改边界、完成记录或提交顺序；
- `transfers`：跨节点归属转移。每租户至多一个未决转移；保存签名 aft1 清单
  原文与摘要、首次导入结果（幂等重放）、aftr1 接管回执、双方实例 id、阶段
  （draining/exported/imported/confirmed/undrained/finalized）；
- `relay_events`：`first_sync / mirror_advanced / sync_stopped /
  upstream_frozen_cap / window_issued / window_retaken /
  window_force_expired / window_completed / window_barrier_advanced /
  max_inflight_shrunk / max_inflight_grown / reject / tenant_created /
  tenant_deactivated / filter_updated / handoff_prepared / handoff_exported /
  handoff_undrained / handoff_imported / handoff_confirmed / handoff_finalized /
  handoff_recovered / handoff_recover_inconsistent`。

### 并行窗口与连续提交屏障

```
镜像原始序号:   0  1  2  3  4  5 ...  (已验证、稠密、只增)
                 └─w1─┘ └─w2─┘ └─w3─┘   ← 相邻、互不重叠，租给不同 worker
状态:          leased  completed completed
                                       ↑ 屏障 cursor_end 仍停在 0（w1 未完成）
worker 提交 w3 → 只登记 completed；提交 w2 → 仍登记；提交 w1 → 三个窗口
连成稠密完成前缀，屏障一次性推进到 end(w3)，在途槽位同时释放。
```

- **领取**：调用方若仍持有效租约，重放同一窗口（同 id、同字节）；否则按
  顺序接管最前的超时窗口；再否则在 `max_inflight` 未满时发放一个新的
  相邻窗口；满额且有未发数据 → `409 inflight_cap_reached`，满额但无新
  数据而窗口都有主 → `409 lease_conflict`，无活可干 → `delivery: null`。
- **完成（提交）**：必须由当前持有者以当前 epoch 的 `lease_token`
  （首个 epoch 可省略）提交**恰为窗口末端**的 `end_index`；越过末端/
  部分提交 `409 ack_end_mismatch`，旧 epoch/错误持有者 `409 stale_lease`。
  重复提交幂等，绝不重复推进屏障。
- **重启恢复**：窗口边界、`leased/completed` 完成记录、`cursor_end` 与
  提交顺序全部持久化；重启后重新领取返回原窗口标识与原始字节，补洞顺序
  不变。
- **强制接管**：管理员可对卡住的 leased 窗口调用 `force-expire`
  （运维页每个窗口上的 ⏱），立即可被新 worker 接管以便观察超时语义。

投递包 `afp1`：`{packet_version, delivery_id, tenant_id, seq,
start_index, end_index, leaf_count, leaf_hashes, filter, records[],
checkpoint, sig}`。

- `records[i]` 含原始 `leaf_index`、规范信封、`leaf_hash`、以及锚定到
  `end_index` 高度的 `inclusion_path`/`root_hash`；
- `delivery_id = afd_‖HMAC(packet_secret, 规范(tenant,seq,start,end,
  leaf_hashes))` 的前 32 hex；同输入永远同 id；
- `sig` 是对去 `sig` 规范包体的 HMAC-SHA256。

## 快速开始

```bash
export PYTHONPATH=$(pwd)

# 1) 初始化独立中继 home（只复制 transparency_secret 这一个信任锚）
python -m afrelay init ./relay-home \
    --upstream-url http://127.0.0.1:8080 \
    --upstream-token dpa_...或任一团队只读令牌 \
    --gateway-secrets ./home/secrets.json     # 或 --transparency-secret <hex>
# 打印管理员令牌 afra_…（仅显示一次）

# 2) 运行（后台定时拉取 + HTTP API + 运维页 http://127.0.0.1:8090/ui）
python -m afrelay serve ./relay-home --port 8090 --interval 2

# 手动拉一轮 / 查全局状态
python -m afrelay sync   ./relay-home
python -m afrelay status ./relay-home --admin-token afra_…
```

租户管理（管理员）：

```bash
python -m afrelay tenants ./relay-home create --tenant-id aud-a --name "A组审计" \
    --filter filter.json --max-inflight 8 --admin-token afra_…   # 返回 dprt_… 一次性令牌
python -m afrelay tenants ./relay-home list --admin-token afra_…
python -m afrelay windows ./relay-home aud-a --committed --admin-token afra_…  # 窗口/屏障/空洞
python -m afrelay set-inflight ./relay-home aud-a --max-inflight 2 --admin-token afra_…  # 动态收缩
python -m afrelay force-expire ./relay-home aud-a afd_xxx --admin-token afra_…  # 强制接管
python -m afrelay filter  ./relay-home aud-a --filter filter.json --admin-token afra_…
python -m afrelay deactivate ./relay-home aud-a --reason "离场" --admin-token afra_…
```

筛选规则（消费开始前可改，开始后锁定；无 eval/正则）：

```json
{"event_types": ["release_sealed", "share_issued"],
 "event_key_prefix": "share_issued:",
 "subject_prefix": "shr_",
 "payload_field_equals": {"field": "value"}}
```

消费（审计租户，多个 worker 并行）：

```bash
# 领取一个窗口（租约内重放 / 超时接管 / 发放新相邻窗口）；保存返回的 lease_token
python -m afrelay fetch ./relay-home --token dprt_… --consumer worker-1 --out w1.json
# 只提交“窗口末端”；接管后的窗口必须带 --lease-token；乱序完成安全，屏障自动补洞推进
python -m afrelay ack ./relay-home --token dprt_… \
    --delivery-id afd_xxx --end-index 10 --consumer worker-1 [--lease-token afw_…]
# complete 是 ack 的别名
```

## HTTP API

租户（`dprt_…`）：

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/v1/relay/claim` | `{consumer, ttl_seconds?}`：租约内重放/超时接管/发放新相邻窗口；返回 `lease_token`、`inflight/max_inflight` |
| POST | `/v1/relay/ack`（`/complete` 同义） | `{delivery_id, end_index, consumer, lease_token?}`：登记窗口完成；乱序安全，补洞后屏障一次推进；重复幂等 |
| GET  | `/v1/relay/windows` | 本租户窗口清单、连续提交屏障、在途/上限、阻塞窗口、空洞（`?committed=1` 含已提交） |
| GET  | `/v1/relay/status` | 本租户镜像高度、屏障、积压、窗口/租约/重试、拒绝事件 |
| GET  | `/v1/relay/mirror` | 镜像高度/冻结/停止原因（无需租户作用域） |

管理员（`afra_…`）：`GET /v1/admin/status`、`POST /v1/admin/sync`、
`GET /v1/admin/mirror/leaves`、`POST /v1/admin/tenants`（可带
`max_inflight`）、`GET /v1/admin/tenants`、
`GET /v1/admin/tenants/<id>/windows`、
`POST /v1/admin/tenants/<id>/max-inflight`（动态收缩/放大，不抢占）、
`POST /v1/admin/tenants/<id>/deliveries/<delivery_id>/force-expire`
（强制超时接管）、`POST /v1/admin/tenants/<id>/filter`、
`POST /v1/admin/tenants/<id>/deactivate`。运维页 `/ui`。

错误码：`401 unauthorized`、`403 {tenant_inactive,bad_delivery}`、
`409 {lease_conflict,inflight_cap_reached,stale_lease,ack_end_mismatch,
filter_locked,tenant_already_exists,tenant_draining,handoff_sealed,
tenant_handed_over,handoff_not_drained,handoff_stale_epoch,
handoff_log_behind,handoff_log_forked,handoff_tenant_exists,
handoff_concurrent,handoff_wrong_identity,handoff_state}`、
`400 {invalid_body,invalid_config,filter_invalid,handoff_bad_manifest}`、
`404 {tenant_not_found,delivery_not_found,transfer_not_found}`。
`inflight_cap_reached` 表示达到并行度上限的**背压**（稍后重试即可），
与窗口有主的 `lease_conflict` 区分。

## 离线投递包校验器

无需中继进程，只需包文件 + 中继 `secrets.json`（内含 relay_packet_secret
与 transparency_secret）：

```bash
python -m afrelay verify packet --packet pkt.json \
    --secrets ./relay-home/secrets.json [--expect-tenant aud-a]
# 跨节点转移：清单（签名/封存摘要/前缀/未决区间/锚点）与接管回执（绑定清单）
python -m afrelay verify manifest --manifest handoff.json \
    --secrets ./relay-home/secrets.json [--expect-tenant aud-a]
python -m afrelay verify receipt --receipt receipt.json \
    --manifest handoff.json --secrets ./relay-home/secrets.json
# 退出码：0 有效；2 验签/折根失败；3 参数/文件错误
```

校验：包级 HMAC、`delivery_id` 确定性重算、每叶内容地址与 event 绑定、
锚 checkpoint 的 transparency 签名、每条 inclusion_path 折到已签名根、
区间连续与记录边界。篡改叶子/信封/证明/换钥都会失败。转移清单/回执还校验
机构密钥签名、封存摘要、未决区间边界/完成标记/尝试次数一致性，以及内嵌
窗口锚 checkpoint 与叶证明（清单窗口包自身的 afp1 HMAC 属发起方节点私钥，
跨节点只验机构锚，不验节点包钥）。

## 目录结构

```
afrelay/
  canonical.py  确定性 JSON / HMAC（与 dpgw 规范编码一致）
  merkle.py     RFC 9162 Merkle 纯函数（叶哈希/折根/包含路径）
  errors.py     稳定错误码 + HTTP 状态 + 拒绝归类
  store.py      独立 SQLite schema（镜像/租户/位点/租约/转移/事件）
  upstream.py   网关只读客户端：只 GET，独立验签/折根
  relay.py      同步推进、筛选、并行窗口租约/超时接管/完成/连续提交屏障、后台轮询、状态
  handoff.py    跨节点消费归属转移：draining/签名 aft1 清单/导入锚点校验/
                aftr1 接管回执/epoch 只增/崩溃恢复不双主
  verify.py     离线 afp1 包 / aft1 清单 / aftr1 回执校验器
  server.py     ThreadingHTTPServer JSON API（租户 + 管理）
  webui.py      零依赖运维单页（/ui）
  app.py        home 引导/密钥/打开 Relay
  cli.py        命令行
tests/test_relay.py      47 个场景测试（真实网关 HTTP、并行窗口/补洞/收缩/接管/重启、故障上游）
tests/test_handoff.py    43 个转移场景测试（draining/封存/锚点/同名/旧代次/篡改/
                         回执/撤销/崩溃恢复不双主/越序完成不丢/HTTP/离线验真）
tests/relay_harness.py   真实已签名叶子网关 + 故障注入代理
```

## 可观察的验收场景（测试覆盖）

**镜像**：首次同步（genesis→稠密叶子）、空上游仅 genesis、增量断线续传；
上游不可用/回退/坏签名/坏叶子/证明缺口时停在最后可信位置并恢复续传；
冻结上游封顶到最后可信树头；绝不跨缺口补造。

**并行窗口 / 连续提交屏障**：多 worker 领到相邻不重叠窗口；达到
`max_inflight` 的领取背压；靠后窗口先完成只登记、屏障不推进，补洞后
一次性推进稠密前缀并释放槽位；重复完成幂等不跳屏障；窗口只在恰好窗口
末端被接受（越过末端/部分提交拒绝）。

**租约/接管/重启**：租约内同 id 同字节重放；超时接管边界/字节不变、
epoch/retries 增长、返回新 `lease_token`；旧持有者（无新令牌）提交
`stale_lease`；管理端强制超时接管；重启后边界/完成记录/屏障/提交顺序/
`max_inflight` 全部保持，重新领取仍返回原窗口与原始字节。

**配置/隔离**：动态收缩不抢有效持有者（`shrink_pending`）、在途回落后
按新上限放行、放大立即释放更多槽位、非法上限拒绝；消费开始前可改规则、
开始后 `filter_locked`；跨租户/未知 id、错持有者、停用租户 claim/complete
一律拒绝且屏障保留；慢窗口不阻塞其他租户或同租户后续窗口；有效包离线
验签、篡改/错钥失败；完整 HTTP 流程、管理鉴权、窗口/收缩/接管接口与
运维页。

**跨节点归属转移**：draining 只回放有效短租约、不接管/不发新窗口、完成仍
补洞推进；有效租约未结束时导出 `handoff_not_drained`；清单封存筛选/已确认
前缀/未决区间边界/完成标记/尝试次数并绑定可信树头，`handoff_epoch` 只增，
重复导出同字节；清单签名/摘要篡改、外域密钥、未决区间锚点折根失败全部
`handoff_bad_manifest`；接收日志落后 `handoff_log_behind`、同高不同根
`handoff_log_forked`；同名/同 id 在服消费方 `handoff_tenant_exists`；相同
清单再导入返回首次结果、旧代次 `handoff_stale_epoch`、并发导入
`handoff_concurrent`；导出后转移前凭据在双方都不能改已确认前缀（
`handoff_sealed`）；确认换发新令牌、旧令牌双方失效，未决区间可被新节点
接管、越序完成不丢、屏障连续推进；回执绑定错节点/错清单/篡改均拒绝；
回执产生前可撤销、回执登记后原节点永久失权（claim/complete/undo 全部
`tenant_handed_over`）；准备/导出/导入/确认期间进程退出后重启不双主，
只能原节点继续或新节点接管；完整 HTTP/CLI/运维页与离线清单/回执验真。
