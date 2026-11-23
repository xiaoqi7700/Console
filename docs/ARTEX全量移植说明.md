# ARTEX 全量移植说明（Pojun 上游）

> 参照仓库：[chu0119/Pojun](https://github.com/chu0119/Pojun)（同源上游，ARTEX 的 v0.3.15 基线与它同祖）
> 移植日期：2026-11-23
> 校验状态：`go build ./cmd/artex` 通过（44MB）· `go vet` 通过 · `go test ./agent ./db ./traffic ./intercept` 全绿

---

## 一、总览

本次是**全量移植**，不是挑选。Pojun 有的功能模块，本地现在都有。

| 指标 | 移植前 | 移植后 |
|---|---|---|
| Go 文件（不含 data/refs/cache） | ~370 | **469** |
| 顶层模块目录 | 12 | **25**（新增 13 个） |
| skills | 3 | **23** |
| 数据库表 | 49 | **61** |
| 二进制 | 50MB | **44MB**（字体改运行期加载，反而更小） |

**你自己的 3 处手改全部保留**（备份在 `.backup-manual/`）：
- `agent/provider.go` — billing service unavailable 故障切换
- `server/engine.go` — planner 空转防停摆（15/30/45s 退避补规划）
- `server/logsink.go` — `ARTEX_LOG_QUIET` 日志静默

---

## 二、新增模块目录（11 个）

| 模块 | 文件数 | 作用 |
|---|---|---|
| `vulnintel/` | 14 | 离线漏洞情报库：NVD CVE + CISA KEV + GitHub Advisory + PoC 聚合 + nuclei 模板管理 |
| `vault/` | 1 | 凭据保险库（XChaCha20-Poly1305，主密钥 `data/vault.key`） |
| `egress/` | 1 | SSH 跳板出口：本地 SOCKS5 → 跳板机出网，出口地址直接入代理池 |
| `mihomo/` | 2 | Clash.Meta 内核管理（订阅 YAML → mixed-port → 代理池入口） |
| `proxyprobe/` | 1 | 代理探测 |
| `hosttools/` | 1 | 宿主工具清单（扫描器是否已装） |
| `hostd/` | 4 | 特权助手（一键装工具、自升级），不经主进程提权 |
| `llmpresets/` | 2 | LLM 厂商预置（模型清单、上下文窗口、价格元数据） |
| `docpreview/` | 1 | Office/PDF 文档取样转图片预览（LibreOffice headless） |
| `llmguard/` | 1 | 误拒答识别 |
| `listener/` | 1 | 回连接收器（C2 前置）：接住反弹 shell/OOB 回连并留证 |
| `mcp-servers/` | 6 | MCP 服务端：FOFA 资产测绘（Python，uv 管理） |
| `docker/` | 2 | 容器入口与工具安装脚本 |
| `scripts/` | 9 | 运维脚本（契约提取、路由抽取、Postgres 初始化等） |

---

## 三、db 层

### 新增 11 张表（49 → 61）

| 表 | 作用 |
|---|---|
| `vuln_cves` | CVE 主表（severity/cvss/cpe_criteria/refs/kev/cwes） |
| `vuln_cpe_products` | CPE (vendor, product) 倒排 + 结构化版本区间四列 |
| `vuln_pocs` | PoC/Exploit 聚合（github/exploit-db/nuclei） |
| `vuln_sync_state` | 每数据源同步水位（cursor + page_cursor） |
| `playbooks` | 经验层武器库：机验通过的 critical/high 自动快照攻击链 |
| `task_artifacts` | 证据附件（截图/数据样本/日志） |
| `task_progress` | 自动收尾进度快照（round_no 做 fencing） |
| `credentials` | 凭据保险库密文列 |
| `credential_access_log` | 凭据访问审计流水 |
| `finding_keys` | 漏洞多身份键去重（强键自动合并 / 弱键只做候选） |
| `finding_updates` | 漏洞变更时间线 |

### 增量列（幂等 ALTER，老库自动升级）

- `assets.simhash` — 结构指纹，支撑同模式端点分簇
- `tasks.autopilot` / `autopilot_extensions` / `paused_at` / `auth_config`
- `intercept_rules.tool_scope` + action CHECK 放开 `judge`
- `findings` 5 列、`llm_profiles.user_agent`

### 新增 db 文件（12 个）

`asset_simhash.go`（SimHash 分簇）、`playbooks.go`、`autopilot.go`、`task_artifacts.go`、`task_auth.go`、`task_progress.go`、`task_scope_guard.go`、`finding_keys.go`（多键去重）、`vulnclass.go`（漏洞类别归一）、`intercept_builtin_rules.go`（24 条内置规则单一事实源）、`intercept_builtin_migration.go`、`task_playbook_seed.go`

---

## 四、agent 层（工具与机制）

### 4.1 新增工具

| 工具 | 作用 |
|---|---|
| `http_request` / `session_login` | 原生 HTTP 执行器 + 任务级 cookie jar。一次调用拿结构化结果，「登录→越权→回读」成为基本能力 |
| `poc_scaffold` | 按漏洞类别生成可运行的 Python 验证骨架 |
| `job_start` / `job_status` / `job_output` / `job_stop` | 任务级后台作业，长扫描跨意图存活 |
| `save_script` / `run_script` | 任务级共享脚本，登录脚本/PoC 跨意图复用 |
| `http_probe` | 批量探活（1-40 URL），结果落盘不全进对话 |
| `js_audit` | SPA 前端源码泄露审计：sourcemap 还原 + 密钥/接口清单抽取 |
| `diff_responses` | 响应结构性差分（越权/可枚举/状态机三类的共同基础） |
| `api_contract` | API 契约提取（OpenAPI/Swagger/Postman），比爬虫更准 |
| `validate_finding` | 程序化验证探针，输出机验标记 `validate:<token>:pass` |
| `evidence_check` | 证据复核（13 项检查 + src_ready） |
| `save_evidence` / `list_artifacts` | 证据附件落盘登记 |
| `read_output` | 超长输出按行窗口回读（省 token） |
| `listener_start` / `listener_stop` / `listener_sessions` | 回连接收器（C2 前置） |
| `search_vulns` / `get_vuln` / `search_recent_critical` / `get_poc` / `scan_with_nuclei` / `net_context` | 漏洞情报库 |
| `retire_intent` | 退役前提已失效的排队意图（每轮上限 6 条） |

### 4.2 新增机制

- **全量危害验证协议**（`verification_depth.go`）：影响阶梯 L0-L4、数据量硬要求（≥10 条或全量）、权限矩阵、写测试铁律、不脱敏
- **攻击链自动续跳**（`chain.go`）：高危漏洞入库后按维度自动派「继续打穿」意图
- **意图维度去重**（`dimension.go`）：11 个维度 + 中英文别名
- **派发节奏背压**（`pacing.go`）：按「积压 vs worker 数」约束本轮新增
- **无增量自动收场**（`idlestop.go`）：判据是产出率而非时长
- **误拒答自愈**（`refusal.go`）：只在回复开头出现明确拒绝时触发，默认最多重试 2 次
- **流空闲看门狗**（`stream_watchdog.go`）：180s 无事件主动断开
- **机验探针**（`agent/validators/`）：XSS/SSRF/RCE/云/Browser 五类
- **SimHash 变体分析**（`variant.go`）：同 root_domain 下同模式端点自动派变体验证
- **playbook 经验层**：成功链沉淀，同类目标开局注入 Top3 先例

### 4.3 三张工具清单已同步

`WorkerTools` / `PlannerTools` / `MainAgentTools` 全部注册，`AllDomainTools` 自动去重合并。

---

## 五、server 层（新增 35 个文件）

| 能力 | 文件 |
|---|---|
| 自主推进（Autopilot） | `autopilot.go` / `autopilot_extend.go` / `auto_finish.go` |
| 统一收尾 | `auto_settle.go`（settleTaskWithReason + 目标达成判定） |
| 诊断包 | `diagnostics.go` / `diagnostics_collect.go` / `traffic/diagnostics.go` |
| 代理池 | `proxypool_api.go` / `_health` / `_local` / `_mihomo` / `_subscription` |
| 漏洞情报 | `vulnintel_api.go` / `vulnintel_sync.go` / `vulnintel_link.go` |
| 证据附件 | `artifacts.go` / `artifact_preview.go` / `artifact_autobind.go` / `artifact_data_preview.go` |
| 认证 | `auth_revoke.go`（JWT 吊销）/ `authcheck.go`（登录凭据自检） |
| 覆盖率/深度提示 | `coverage_nudge.go` / `depth_nudge.go` |
| 引擎守卫 | `engine_guard.go`（停滞判定） |
| 成本估算 | `cost.go`（内置参考价，单任务口径） |
| LLM 分诊 | `llm_models.go`（模型列表探测 + 失败分类成人话）/ `llm_presets_api.go` |
| 宿主环境 | `hostenv_api.go` / `listeners_api.go` / `egress_api.go` / `c2_relay.go` / `tools_api.go` |
| 其他 | `report_recovery.go`（空报告巡检）/ `input_validation.go` / `mcp_failure_cache.go` / `settings_helpers.go` / `http_names.go` / `engine_extra.go`（Snapshot） |

### 新增路由（40 条）

诊断包、成本、会话吊销、任务认证自检、代理池（含 mihomo）、漏洞情报、SSH 跳板、宿主环境、回连接收器、C2、LLM 预置与分诊、证据附件（8 条）、Word 导出（2 条）。

---

## 六、report 层：Word 交付件

**这是对你最有直接价值的一块**。

| 文件 | 行数 | 作用 |
|---|---|---|
| `docx.go` | 597 | OOXML 底层写手（zip + XML，零第三方依赖） |
| `docx_build.go` | 752 | 任务总报告 + 单漏洞报告两套版式 |
| `docx_image.go` | 86 | 图片按 GB/T 9704 版心等比缩放嵌入 |
| `docx_fonts.go` | 60 | **改动**：字体改运行期读取，不 embed |
| `sanitize.go` / `goals.go` / `findings.go` / `report.go` | — | 文本清洗 / 目标达成节 / 原有两个文件升级 |

**字体处理的关键改动**：上游把三个公文字体（仿宋_GB2312 / 楷体_GB2312 / 方正小标宋_GBK，共 20MB）`go:embed` 进二进制。本地改成**运行期从 `<数据目录>/fonts/` 读取** —— 二进制因此从 50MB 降到 44MB，字体缺失时优雅降级为「只引用字体名」（接收方装了字体仍能正确渲染）。

字体已放在 `data/fonts/`（20MB）。可用环境变量 `ARTEX_FONT_DIR` 指定其他位置。

**实测验证**：生成了一份带封面/正文/表格的单漏洞 Word，11.3MB，`word/fonts/font1-3.odttf` 三个字体部件齐全，Word 可正常渲染。

---

## 七、traffic 层

- `idscan.go` + `idscan_agg.go` + `idscan_lexicon.go` + `idscan_match.go` + `idscan_redact.go` — 离线流量身份识别扫描（在抓包里找账号/凭据/敏感字段）
- `pool.go` — 代理池：per-request 轮换、连败熔断、sticky_host 策略
- `diagnostics.go` — 流量诊断统计

`Traffic` 结构新增 `pool` / `lastPick` / `strictEgress` / `directRecordFallback`。严格出口模式下池全部熔断时返回哨兵地址 `127.0.0.1:1`（必然失败），避免直连泄露真实 IP。

---

## 八、vulnintel：把「猜 CVE」变成「查库」

14 个文件，纯标准库 + 本地 db：

| 文件 | 作用 |
|---|---|
| `intel.go` | 门面：CVE upsert、SearchVulns、GetVuln、VersionInRange、同步水位 |
| `nvd.go` | NVD CVE API 2.0（匿名 5 req/30s，带 key 50 req/30s，处理 429） |
| `kev.go` | CISA KEV 在野利用清单 |
| `ghsa.go` / `ghsa_range.go` / `ghsa_store.go` | GitHub Advisory 第二来源（自带 semver 区间比较） |
| `poc.go` | GitHub code search + exploit-db CSV |
| `nuclei.go` | 模板树 git clone/pull + 命令组装 |
| `sync.go` / `fastlane.go` | 主同步（120 天窗口 + 分页续跑）/ 近期高危快通道 |
| `ratelimit.go` | 进程级令牌桶（主同步与快通道共享额度） |
| `fallback_transport.go` | 代理失败自动回退真直连 |
| `link.go` | CVE 的 CPE product ↔ 资产技术栈指纹反查 |
| `status.go` | 状态聚合 |

**为什么值得**：KEV 排序 = 优先打已在野利用的；结构化版本区间 = 判「我这版到底中不中」；`version_undetermined` 显式提示「不代表不受影响」；nuclei 模板按 CVE 精确投递。

**配置**：`vulnintel_enabled`（默认开）、`nvd_api_key`（可选）、`ghsa_token`（可选）、`vulnintel_proxy`。无 key 也能跑，首次全量回填约 22 分钟；带 key 约 3 分钟。

---

## 九、保留的关键决策

| 决策 | 理由 |
|---|---|
| 浏览器执行断言用桩实现 | chromedp 会带一串传递依赖；桩保留完全相同的对外契约（恒 `Skipped=true`），XSS 退化为反射确认（warn），不会误判成已执行。要恢复完整能力只需引入 chromedp 并替换 `validators_browser_stub.go` |
| 桌面预览走本地 `previewDir` | `docpreview` 子系统已搬，但 LibreOffice 链未接线；调用方据此判断预览不存在并跳过嵌图 |
| `settleDrainGrace` 保持 90s | 上游是 300s。这是你的既有参数，不动 |
| 字体运行期加载 | 见第六节 |
| `task_scope_guard.go` 无调用方 | 上游同样没有调用方（它给调用方 SQL 拼接用），照原样搬入备用 |

---

## 十、新增文件清单

### 模块目录（11 个）
`vulnintel/` `vault/` `egress/` `mihomo/` `proxyprobe/` `hosttools/` `hostd/` `llmpresets/` `docpreview/` `llmguard/` `listener/`

### agent 层（21 个新文件 + validators 子包）
`chain.go` `dimension.go` `pacing.go` `verification_depth.go` `idlestop.go` `poc_scaffold.go` `stream_watchdog.go` `refusal.go` `variant.go` `hygiene.go` `goal_gate.go` `autopilot.go` `tools_http.go` `tools_auth.go` `login_breaker.go` `tools_ua.go` `tools_jobs.go` `tools_script.go` `tools_probe.go` `tools_jsaudit.go` `tools_diff.go` `tools_contract.go` `tools_validate.go` `tools_evidence.go` `tools_artifacts.go` `tools_listener.go` `tools_readoutput.go` `tools_retire.go` `tools_vulnintel.go` `jobs_cleanup.go` `job_proc_*.go` `ops_tails.go` `toollog.go` `tool_outputs.go` `envcaps.go` `job_proxy_env.go` `engine_extra.go` `agent/validators/`（7 个）

### server 层（35 个新文件）
见第五节表格

### 其他
`traffic/` 7 个、`db/` 12 个、`report/` 6 个、`selfupdate/` 2 个更新

---

## 十一、验证

```bash
# 编译
go build -o /tmp/artex ./cmd/artex      # → 44MB, exit 0

# 静态检查
go vet ./agent/ ./server/ ./db/ ./traffic/ ./vulnintel/ ./report/   # exit 0

# 测试
go test ./agent/ ./db/ ./traffic/ ./intercept/ -count=1             # 全绿

# skills 加载
go run /tmp/ck.go                                                    # 23 个

# Word 导出实测
go run /tmp/docxcheck/main.go                                        # 11.3MB, 三字体已嵌入

# 数据库表
grep -c "CREATE TABLE IF NOT EXISTS" db/schema.sql                   # 61
```

---

## 十二、回滚

```bash
# 全量回滚
git checkout -- agent/ server/ db/ report/ traffic/ skills/ selfupdate/
rm -rf vulnintel vault egress mihomo proxyprobe hosttools hostd llmpresets docpreview llmguard listener

# 恢复你的手改
cp .backup-manual/*.go agent/ server/ 2>/dev/null
cp .backup-manual/schema.sql.bak db/schema.sql
```

数据库层面：新增的表和列都是 `IF NOT EXISTS`，回滚代码后它们留在库里不碍事（不删数据）。

---

## 十三、注意事项

1. **首次启动会跑一次 schema 迁移**：幂等，但会新增 12 张表和若干列。老库升级无需手工操作。
2. **vulnintel 同步延迟 90 秒起跑**，之后每 6 小时一轮。不想跑就在设置里关 `vulnintel_enabled`。
3. **字体占 20MB**（`data/fonts/`）。不需要 Word 导出可以删掉，导出会自动降级。
4. **回连接收器绑定端口无需特权**（1024+），但会开监听端口——防火墙/安全组需要注意。
5. **SSH 跳板凭据加密存储**，主密钥在 `data/vault.key`，别丢（丢了已存凭据解不开）。
6. **`ARTEX_INSTALL_PROXY`** 环境变量用于维护类出网（装工具/同步情报/拉模板），Docker 部署时通过 compose 传。
---

## 十四、老库迁移实测（2026-11-23）

在真实的 `artex` 库（8 个任务 / 3507 个资产 / 262 个漏洞 / 6986 个节点）上实测迁移，
**数据零丢失**。

### 步骤与结果

| 步骤 | 结果 |
|---|---|
| 迁移前备份 | `pg_dump -Fc` → `.backup-manual/artex-before-migration.dump`（765MB）|
| 执行 `psql -f db/schema.sql` | 退出码 0，无错误 |
| 表数量 | 51 → **63** |
| 11 张新表 | 全部创建成功（含 `task_artifacts`）|
| 增量列 | `assets.simhash` / `tasks.autopilot` / `tasks.paused_at` / `tasks.auth_config` / `intercept_rules.tool_scope` / `llm_profiles.user_agent` 全部就位 |
| 既有数据 | tasks=8、assets=3507、findings=262、exploration_nodes=6986，**与迁移前一致** |
| `intercept_rules.action` 约束 | 成功放开到 `('allow','deny','ask','judge')` |

### 服务启动实测

用工程目录下的二进制启动（`./artex -addr 127.0.0.1:18788`）：

```
[manager] reloaded 8 task(s) from PG
[engine] task 27/21/19/17 重置残留 running 意图为 open
[config] skill 目录: /Users/a77/Downloads/ARTEX-main/skills
ARTEX dev backend listening on 127.0.0.1:18788 (data=.../data, workers=50)
```

| 验证项 | 结果 |
|---|---|
| 健康检查 `/api/health` | 200 `{"ok":true}` |
| 前端页面 `/` | 200 |
| 任务恢复 | 8 个任务全部 load，残留 running 意图重置为 open |
| 内置拦截规则 | 迁移后 12 deny + 12 judge + 1 allow（judge 来自新规则集）|
| 任务模板种子 | 4 条 |
| 工具注册 | 79 个，其中 16 个新工具全部在库（http_request / session_login / validate_finding / search_vulns / get_vuln / job_start / save_evidence / retire_intent / poc_scaffold / js_audit / diff_responses / api_contract / http_probe / evidence_check / listener_start / scan_with_nuclei）|
| 新增路由 | 12 条抽样全部注册成功（返回 401 需认证而非 404）|

### 发现并修复的问题

1. **`task_artifacts` 不在 schema.sql 里** —— 上游在 Go 代码（`EnsureTaskArtifactsTable`）建表，
   裸 `psql < schema.sql` 初始化会缺这张表。已把 DDL 补进 schema.sql（两处都幂等）。
2. **`llm_profiles.user_agent` 漏了** —— 移植 `db/config.go` 的 UserAgent 字段时忘了加列。
   已补进 schema.sql 并手动 ALTER 到位。

### 回滚

```bash
# 数据回滚（会丢弃迁移新增的表/列，但保留所有业务数据）
pg_restore -h 127.0.0.1 -U artex -d artex --clean --if-exists \
  .backup-manual/artex-before-migration.dump
```

注意：`--clean` 会先删表再重建，请在业务空闲时段做。

---

## 十五、前端同步（2026-11-23 补充）

后端移植完成后，前端 `web/` 目录仍是旧版，导致侧边栏没有新功能入口。本节记录前端同步。

### 同步方式

以 Pojun 前端为主体整体同步 `web/src/`，同时保留本地独有的组件：

| 类别 | 数量 | 处理 |
|---|---|---|
| 同名文件（内容有差异） | 75 | 用 Pojun 版覆盖 |
| 同名文件（内容相同） | 88 | 无需处理 |
| **仅 Pojun 有** | 18 | 全部新增 |
| **仅本地有** | 25 | **保留不删** |

本地独有的 25 个文件主要是 shadcn/ui 基础组件（accordion / calendar / carousel / context-menu / menubar / navigation-menu / slider 等）和旧侧边栏辅助组件。Pojun 侧边栏重构后不再引用它们，保留不影响构建。

### 新增页面（6 个）

| 路由 | 页面 |
|---|---|
| `/system/vulnintel` | 漏洞情报库（同步状态、手动触发、配置） |
| `/system/proxypool` | 代理池（批量导入、健康检查、订阅拉取） |
| `/system/proxypool/clash` | Clash 节点管理（mihomo 内核） |
| `/system/egress` | SSH 跳板出口 |
| `/system/hostenv` | 宿主环境体检与一键装工具 |
| `/system/c2` | 监听器 / C2 |

### 侧边栏入口

`web/src/navigation/sidebar/sidebar-items.ts` 已包含全部新条目：
漏洞情报、代理池、Clash 节点管理（badge: new）、SSH 跳板、宿主环境、监听器 / C2。

### 构建与嵌入

```bash
cd web && npx tsc --noEmit          # 类型检查：0 错误
cd web && NEXT_EXPORT=1 npx next build   # 静态导出 → web/out（11MB，33 个页面）
cp -r web/out server/webui/dist      # 复制到内嵌目录
go build -tags embedui -o artex ./cmd/artex   # 关键：必须带 embedui tag
```

**踩坑提醒**：不带 `-tags embedui` 编译出来的是 stub 二进制，页面会报「前端未内嵌」。`build.sh` 里本来就是带这个 tag 的，手工编译时别忘。

二进制从 44MB 增至 52MB（多了 11MB 前端资源）。

### 验证结果

| 项目 | 结果 |
|---|---|
| TypeScript 类型检查 | 0 错误 |
| Next 静态导出 | 33 个页面全部生成 |
| 新增页面 HTTP 状态 | 6 个页面全部 200 |
| 侧边栏条目 | 已打进 JS chunk |
| 服务启动 | 2 秒，健康检查 200 |

---

## 十六、前端排障记录（2026-11-23）

### 现象

登录后进入 `/function/tasks/` 报 `NotFoundError: removeChild`，整页白屏，看起来像「任务全没了」。

### 真正原因（两个独立问题）

**1. 浏览器加载了旧 chunk**

前后替换了两次二进制（15:52 / 16:01），两次构建的 chunk 哈希不同。浏览器里还挂着 15:52 那版 HTML 引用的旧 chunk，而磁盘上的 chunk 已经换新——引用与实际内容对不上，React 卸载组件时 `removeChild` 找不到自己的节点，于是抛错。

这不是代码 bug，是**构建产物替换后必须强刷**。验证：用 Playwright 无头 Chrome 打开同一页面，任务列表完整渲染、零 JS 错误、停留 30 秒并打开分类管理弹窗（挂载 DndContext）也正常。

**2. 前端登录用户名写死成 POJUN**

`web/src/app/(auth)/login/page.tsx` 里 `api.login("POJUN", password)`，而后端 `server/auth.go` 只接受 `"ARTEX"`。这是同步 Pojun 前端时带进来的——后端移植时改了模块名，前端硬编码的字面量没跟着改。

curl 直接传 `ARTEX` 一直是对的，所以后端测试掩盖了这个问题，只有浏览器登录会失败。

已改为 `api.login("ARTEX", password)`。

### 顺手修的不一致

| 位置 | 问题 | 处理 |
|---|---|---|
| `server/hostenv_api.go` | 读 `POJUN_INSTALL_PROXY` | 统一为 `ARTEX_INSTALL_PROXY` |
| `update-card.tsx` | 文案写「启动 POJUN」「pojun 本体」 | 改为 ARTEX |
| `update-card.tsx` / `hostenv/page.tsx` / `lib/types.ts` | 提示里写 `POJUN_INSTALL_PROXY` | 改为 `ARTEX_INSTALL_PROXY` |
| `GET /api/version` | **漏注册**，返回 404（更新卡片轮询它会失败） | 补上路由 + handler |

保留未改：localStorage 的 `pojun_token` / `pojun.chat.*` 等 key。改了会让已登录 token 和用户偏好失效，而它们对用户不可见。

### 全页面验证

用 Playwright + 系统 Chrome 逐页扫描 29 个页面：

```
/function/tasks /function/tasks/detail /function/assets /function/findings
/function/findings/detail /function/traffic /function/commands /function/workspace
/function/llm-records /function/sync /dashboard /chat
/system/llm /system/agents /system/mcp /system/skills /system/tools
/system/notify /system/intercept /system/intercept/approvals /system/intercept/assets
/system/logs /system/settings /system/vulnintel /system/proxypool
/system/proxypool/clash /system/egress /system/hostenv /system/c2
```

**29 个全部 OK**，零 CRASH、零 pageerror。

### 数据完整性

任务数据从未受影响：

```sql
SELECT count(*) FROM tasks WHERE deleted_at IS NULL;  -- 8
```

白屏纯粹是前端渲染挂了，数据库里的 8 个任务、3507 个资产、262 个漏洞、6986 个节点一直都在。

### 结论：替换构建产物后必须强刷

这是静态导出的固有特性——chunk 文件名是内容哈希，构建一次换一批。二进制换新后，浏览器里旧 HTML 引用的旧 chunk 就成了孤本。**Cmd+Shift+R** 即可。

后续如果再做前后端更新，建议：
1. 停服务 → 换二进制 → 起服务 → 强刷浏览器，四步一起做；
2. 或在反代/服务端给 `_next/static` 加短缓存策略，避免长缓存旧 chunk。

---

## 十七、全功能验证（2026-11-23）

### 验证方法

三层验证，全部自动化：

1. **路由层**：从 `server.go` 抽出全部 124 个 GET 路由，带 token 逐个真实请求
2. **功能层**：35 个核心功能点用真实 id 验证（不是占位符）
3. **页面层**：Playwright + 系统 Chrome 逐页渲染 29 个页面，捕获 pageerror

### 结果

| 层级 | 结果 |
|---|---|
| 路由探测 | 124 个 GET → **95 个 2xx/3xx**、26 个 4xx（占位符假 id 导致）、3 个 5xx（子系统未配置） |
| 功能验证 | **35 / 35 全部通过** |
| 页面渲染 | **29 / 29 全部 OK，零 pageerror** |

### 本轮发现并修复的 bug（5 个）

前面几轮只验证了「能编译 + 能启动」，这轮做了真实调用，又挖出 5 个：

| # | 问题 | 影响 | 修复 |
|---|---|---|---|
| 1 | `findings` 表缺 5 列（`fingerprint` / `root_cause_key` / `merge_count` / `merged_into_id` / `last_merged_at`） | **诊断包 findings.json 返回 null**（SQL 报 `column does not exist`），多键去重功能完全不可用 | 补进 schema.sql + 执行 ALTER |
| 2 | `vuln_cves.cwes` 列缺失 | **NVD 同步全部失败**（`column "cwes" does not exist`），情报库只有 KEV 那一路的 1790 条 | 补进 schema.sql |
| 3 | `vuln_cpe_products` 缺 4 个版本区间列、`vuln_sync_state` 缺 `page_cursor` | CPE 版本判定不可用、大窗口同步无法续跑 | 补进 schema.sql |
| 4 | `mihomo` 管理器未初始化 | 代理池的 Clash 内核接口全部 503「管理器未初始化」 | `manager.go` 的 `&Manager{...}` 构造里加 `mihomo: mihomo.New(dir)` |
| 5 | `cmd/artex-hostd`、`cmd/artex-maint` **整个漏搬** | 宿主一键装工具、维护工具根本不存在 | 搬入两个入口 + 补 `db.AuditAutoScope` |

### 命名统一

hostd 相关全部从 `pojun` 改成 `artex`：

| 项 | 改前 | 改后 |
|---|---|---|
| socket 路径 | `/run/pojun/hostd.sock` | `/run/artex/hostd.sock` |
| 二进制名 | `pojun-hostd` | `artex-hostd` |
| HOME | `/var/lib/pojun-hostd` | `/var/lib/artex-hostd` |
| 提示文案 | 「未安装 pojun-hostd」 | 「未安装 artex-hostd」 |

### 三个二进制

```bash
go build -tags embedui -o artex       ./cmd/artex        # 52MB 主服务（含前端）
go build              -o artex-hostd  ./cmd/artex-hostd  # 9.7MB 特权助手
go build              -o artex-maint  ./cmd/artex-maint  # 21MB 维护工具
```

### 实测数据

**漏洞情报库已经跑起来了**：

```
CVE 入库 28731 条（NVD 主同步 + KEV 在野利用标记）
nuclei 模板 14382 个
```

**Word 导出实测**：

```
单漏洞报告  11.0MB，Microsoft Word 2007+，三字体 odttf 齐全
任务总报告  11.6MB
```

**业务数据零影响**：

```
任务=8  资产=3507  漏洞=262  节点=7073
```

### 仍是「未配置」而非「坏掉」的 3 项

| 接口 | 返回 | 说明 |
|---|---|---|
| `/api/hostenv/jobs/{id}` | 503 | 需要安装 `artex-hostd` 特权助手（需 root） |
| `/api/sync/scopesentry/*` | 502 | 需要在设置里配置 ScopeSentry MCP 的 URL |
| `/api/proxypool/mihomo` | 现在正常返回空状态 | 内核未安装，页面可一键装 |

这三项是**按设计失败**——功能本身在，只是外部依赖没配。配好就能用。

### 局限说明

- 本轮没有测试**真实的 LLM 调度**（会消耗大量 token 且影响你正在跑的任务），只验证了 LLM 配置读取、预置列表、连通分诊接口正常
- 没有测试**拖拽改分类**的真实交互（只在 Playwright 里确认了弹窗能打开）
- `@dnd-kit/core` 6.3.1 + React 19 是已知兼容隐患，目前实测正常，但如果拖拽出异常优先怀疑这里

---

## 十八、性能优化：多任务并发下的页面卡顿（2026-11-23）

### 症状

3 个任务并发、50 worker 时，前端页面切换与滚动明显卡顿，任务详情页尤其严重。

### 诊断方法与实测数据

用 Playwright 驱动无头 Chrome，监控每个页面 30 秒内的 **API 请求数**、**传输字节** 与 **各接口耗时**：

| 页面 | 优化前 30s 请求数 | 优化前 30s 传输 |
|---|---|---|
| Dashboard | 76 次 | ~0.5MB |
| 任务详情 | 57 次 / 20s | **5.09 MB** |

关键发现（不是猜测，逐项实测）：

| 问题 | 实测数据 |
|---|---|
| `/api/stats` 用 `ListByKind(KindIntent, 100000)` 全表搬行再循环数 running | 首次 0.79s，库里有 2600+ 条意图 |
| `/api/exploration/intents` 每次返回全量 payload | **578 KB / 次**（300 条 × 完整意图正文） |
| `/api/tasks/{id}/intent-assets` 全量返回意图×资产对 | **426 KB / 次**（1780 对，跨 290 个意图） |
| `/api/intercept/task/{id}` 返回全部历史审批记录 | **167 KB / 次**（其中 `tool_input` 占 117KB），而前端只用来数 pending |
| 概览页每 3 秒并发 4 个请求 | 其中 intents 单次 60KB+ |
| `chat/status` 每 2 秒、`intercept/task` 每 2.5 秒 | 两个高频轮询叠加 |

### 后端优化

| 改动 | 效果 |
|---|---|
| `/api/stats` 改用 SQL 聚合（新增 `CountIntentsByState` / `CountGoals`） | **0.79s → 0.008s（快 90 倍）** |
| `intents` 默认返回瘦身 payload（新增 `taskNodeDTOsCompact`，只留 summary/dimension/hypothesis 等，summary 截 400 字） | **578KB → 66KB（-88%）**，0.36s → 0.038s |
| 分页分支同样瘦身（`?full=1` 保留全量） | 会话页滚动加载不再传全量正文 |
| `intent-assets` 支持 `?limit=N` / `?intents=1,2,3` | **426KB → 158KB（-63%）**，0.146s → 0.010s |
| `intercept/task` 支持 `?counts=1` 只回状态计数 | 轮询从 167KB → 几十字节 |

### 前端优化

| 改动 | 前 → 后 |
|---|---|
| 侧边栏审批徽标轮询 | 5s → **10s**，且页面不可见时暂停 |
| Dashboard 任务列表 | 5s → **10s** |
| Dashboard 快组（原 8 个请求一起 5s） | 拆档：轻量 5s，重量（activity/tokens）**15s** |
| 任务详情外壳的审批计数轮询 | 5s → **10s** |
| 会话页 `chat/status` | **2s → 5s** |
| 会话页 `intercept/task` | 5s → **10s**，且先查 counts 再决定是否拉全量 |
| 会话页 `intent-assets` | 5s → **30s** |
| 漏洞 Tab | 3s → **10s** |
| 概览页快组 | **3s → 10s** |
| 任务归档列表 | **2s → 10s** |
| 漏洞详情页 | 4s → **10s** |
| 侧边问答题 | 2s → **3s** |

所有轮询统一加了 `document.hidden` 判断——切到后台标签页不再继续请求。

### 优化结果

| 指标 | 优化前 | 优化后 | 改善 |
|---|---|---|---|
| 任务详情 30s 传输 | **5.09 MB** | **1.08 MB** | **-79%** |
| 任务详情 20s 请求数 | 57 | 42 | -26% |
| Dashboard 30s 请求数 | 76 | 40 | **-47%** |
| `/api/stats` 响应 | 0.79s | 0.008s | **-99%** |
| `intents` 载荷 | 578KB | 66KB | **-88%** |
| `intent-assets` 载荷 | 426KB | 158KB | -63% |
| `intercept/task` 载荷（轮询） | 167KB | ~0.1KB | **-99.9%** |

页面切换本身不慢（实测 69–216ms），卡顿来自页面内的持续轮询压满带宽与主线程。

### 回归验证

优化后重跑全部验证：

- **功能验证 35 / 35 通过**
- **页面渲染 29 / 29 OK，零 pageerror**

### 数据量说明

这些优化能生效的前提是理解真实数据规模：

```
activity        454,168 行
exploration_nodes 7,075 行（其中意图 2000+）
llm_usage       202,253 行
intent_assets   1,780 对（跨 290 个意图）
流量记录        16 GB
```

在这些规模下，任何「全量搬行 + Go 侧循环」或「每 3 秒一拉」都会直接变成用户可感知的卡顿。
