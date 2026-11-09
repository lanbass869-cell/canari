# mcpcheckup/checks — 完全拆解报告（教材）
## 逐函数逐行分析，作为 Canari 的架构教材

> 来源：`git clone --depth 1 https://github.com/mcpcheckup/checks`
> 343 个文件，272 个代码文件，70,597 行代码
> 本文逐文件读代码，每个设计决策标注源码行号。

---

## 一、架构总览

```
packages/
  attestation-schema/     # 签名工件 schema + DSSE envelope
  canonicalizer/          # NFC-JCS 规范化 + fingerprint 计算
  checks/                 # 15 项检查定义 + 远程探测引擎
  fixtures/               # 16 个模拟 MCP server（TDD 基础）
  ssrf-guard/             # SSRF 防护（IP 分类 + DNS 重绑定 + 预算）
  toolset-diff/           # 工具集变更 diff
  verifier/               # 离线签名验证 CLI
```

**设计哲学**：每个 package 是一个独立单元，有自己的 `package.json`、`tsconfig.json`、测试。
通过相对路径 import 消除 node_modules 依赖——verifier 可以裸 Node 运行。

---

## 二、规范化引擎（canonicalizer，核心基础设施）

### 2.1 canonicalize.ts（148 行）

**nfc-jcs/v1 规范化 profile**：RFC 8785 (JCS) + NFC 归一化前置。

```typescript
export const CANONICALIZATION_PROFILE = 'nfc-jcs/v1'
// 1. NFC-normalize every object key and every string value
// 2. reject if step 1 makes two keys of the same object collide
// 3. apply RFC 8785 (JCS) to the result
```

**关键设计决策**：

| 行号 | 决策 | 为什么 |
|---|---|---|
| L4-6 | 不叫 RFC 8785，叫 nfc-jcs/v1 | RFC 8785 §3.1 要求 Unicode "as is"，但这里加了 NFC 归一化——**故意偏离**，所以取自己的名字 |
| L57-58 | 循环引用检测 | `stack.has(obj)` → throw CIRCULAR_REFERENCE |
| L78-83 | NFC 后 key 碰撞检测 | `"café"` 和 `"cafe\u0301"` NFC 后都是 `"café"` → 抛 DUPLICATE_KEY_AFTER_NFC |
| L96-108 | 孤立 surrogate 检测 | 遍历每个 grapheme，检查 U+D800-U+DFFF → 抛 LONE_SURROGATE |
| L112-117 | -0 → 0 | `Object.is(n, -0)` → 输出 `'0'` |
| L120-128 | 短转义表 | `"`→`\"`, `\\`→`\\\\`, `\b`, `\f`, `\n`, `\r`, `\t` |

### 2.2 projections.ts（66 行）

**核心洞察：投影是 allowlist，不是排除法。**

中文注释翻译：*"投影忽略 tools/list 响应的非必要字段（server 版本注解、_meta 等）。这防止我们因 server 新增字段而产生虚假 drift。这是字段的 allowlist，不是'排除某些字段'的方法。当 server 添加新字段时，投影自动不受影响。"*

- `projectToolset()`：提取 tool name 列表，排序
- `projectSchemas()`：提取 `{name, inputSchema}` 对，按 name 排序，inputSchema 用 canonicalize 字符串比较排序（保证确定性，与 wire 顺序无关）
- `TOOLSET_PROJECTION_VERSION = 'v1'`：一旦发布过的 attestation 使用了 v1，不能修改投影——必须发布 'v2'

---

## 三、SSRF 防护层（ssrf-guard，安全基础设施）

### 3.1 IP 策略（ip-policy.ts，272 行）

**完整 IANA IPv4 + IPv6 Special-Purpose Address Registry 实现。**

23 种阻止分类：PRIVATE_USE, LOOPBACK, LINK_LOCAL, CLOUD_METADATA, THIS_NETWORK, CGNAT, DOCUMENTATION, BENCHMARKING, MULTICAST, RESERVED, UNIQUE_LOCAL, UNSPECIFIED, MALFORMED, PROTOCOL_ASSIGNMENT, DEPRECATED, NAT64, IPV4_COMPATIBLE, SIX_TO_FOUR, TEREDO, DISCARD_ONLY, DUMMY_PREFIX, SEGMENT_ROUTING, SITE_LOCAL

```typescript
// 来自 IANA IPv4 Special-Purpose Address Registry ("Last Updated 2025-10-09")
// 每个 "Globally Reachable" = False 的条目都是阻止行
// code: null 表示 "Globally Reachable" = True，不阻止
// 最具体的匹配行决定结果（注册表自己的规则）
```

IPv4 表（部分，完整表 30+ 行）：
| Range | Code | RFC |
|---|---|---|
| 0.0.0.0/8 | THIS_NETWORK | RFC 791 |
| 10.0.0.0/8 | PRIVATE_USE | RFC 1918 |
| 169.254.169.254/32 | CLOUD_METADATA | - |
| 127.0.0.0/8 | LOOPBACK | RFC 1122 |

### 3.2 guarded-fetch.ts（412 行）

**请求安全层**：
- 方法白名单：只允许 GET 和 POST
- 请求头白名单（不是黑名单）：`accept`, `authorization`, `content-type`, `mcp-method`, `mcp-name`, `mcp-protocol-version`, `mcp-session-id`, `user-agent` — 注释说 "blocklist can always miss a header; an allowlist that's missing one only needs a line added"
- Body 长度预算检查（`budget.maxBodyBytes`）
- 重定向跟踪（`followRedirects` 可选，每个 hop 都是新的 guardedFetch 调用）
- DNS 答案变更检测（`dnsAnswerChangedDuringProbe`）
- 审计记录（`ProbeAuditRecord`, `ProbeHopRecord`）

---

## 四、DSSE 签名层（attestation-schema）

### 4.1 dsse.ts（132 行）

**核心洞察：PAE 是签名的内容，不是原始 payload。**

```typescript
// PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
// 这是实际被签名的——不是原始 payload——这样 payloadType 也被认证了，
// 不能在不使签名失效的情况下被替换（DSSE 设计要防止的 "类型混淆" 攻击）
```

- `signDsseEnvelope()`: Ed25519-sign PAE(payloadType, serializedBody)，生成标准 DSSE JSON envelope
- `verifyDsseSignature()`: 验证签名是否覆盖确切的 (payloadType, serializedBody)
- `verifyDsseEnvelope()`: "至少一个签名验证通过" —— 不是"每个签名者都签了"

### 4.2 Schema 版本管理

4 个版本（v0.1-v0.4），每个都是完整的 JSON Schema 文件。v0.4 是最新版。

**每个版本的字段集合不同**，但都要求：`canonicalization`, `suite_id`, `suite_version`, `suite_digest`, `suite_commit`, `registry_version`, `toolset_projection_version`, `protocol_revision`, `launch_config_digest`, `target`, `observed_at`, `run`, `probe_region`, `probe_dns_answer_changed`, `assertions`, `toolset_fingerprint`, `schema_fingerprint`, `coverage`, `run_id`

---

## 五、检查引擎（checks 包）

### 5.1 checks.json — 15 项检查定义

4 组检查：

| 组 | 检查 | 说明 |
|---|---|---|
| reach (可达性) | reachability, latency_profile | 端点是否活着、响应多快。**只观测不判定** |
| proto (协议契约) | transport_type, protocol_revision, discovery_handshake, tools_list, error_taxonomy | server 是否按声称的 MCP 协议版本说话 |
| sec (安全卫生) | tls_certificate, redirect_policy, auth_metadata, tool_description_hygiene | 公开可观察的安全属性。**不是安全扫描** |
| drift (契约变更与供应链) | toolset_fingerprint, schema_fingerprint, toolset_unchanged_vs_approved, schema_unchanged_vs_approved | 工具集和 schema 是否在你不知情的情况下变过 |

### 5.2 probe.ts（656 行）— runProbe 主执行函数

**L228-303 初始化：**
- `assertionsByCheckId = new Map()` — 每个检查一条 assertion，唯一写入者
- `driftEvents: DriftEvent[]` — 漂移事件
- `disqualifiedFromPublication` — DNS 答案变更或跨主机重定向 → 取消发布资格
- `handshakeGated` — 握手层凭据门控标志
- `A()` 函数：AssertionBuilder，每条 assertion 有 `check_id`, `docs_version`, `execution_status`, `assertion_status`, `evidence_provenance`, `reason`, `unverified_reason`

**L284-286**: `tls_certificate` 无条件 SKIPPED——"out of this executor's scope"

**L308**: `createProbeContext(Date.now())` — 创建探测上下文，跟踪 DNS 和重定向

**L322**: `A('reachability', 'COMPLETED', 'VERIFIED')` — 只要收到了 HTTP 响应就 VERIFIED���注释："a 401/403 IS the endpoint responding, which is all this check claims"

**L327-348**: 握手层凭据门控规则——server 故意将握手放在 auth 后面 → UNVERIFIED/credential_required，不是 FAILED。"we couldn't verify" 不是 "this is broken"

**L332**: `handshakeCredentialGated = !handshake.handshakeOk && handshake.credentialChallenge !== undefined`

**L350-363**: 正常握手分支——`discovery_handshake` VERIFIED 或 FAILED，`protocol_revision` 对照 `revision_matrix` 判断

**L376**: `performToolsList` — Suite 0.15.0 支持 nextCursor 分页，最多 `budget.max_tools_list_pages` 页

**L384-401**: probe 工具调用安全性检查——如果 server 有一个叫 `PROBE_TOOL_NAME` 的工具，不发送该调用（避免与真实工具冲突）

**L404-416**: 握手门控级联——如果握手被门控，tools_list 和所有派生检查级联到 UNVERIFIED/credential_required。"Fingerprints are deliberately never computed on this branch: declaring tools_list unverified while still publishing a fingerprint derived from that same response would be incoherent."

**L438-454**: 正常 tools/list 分支——fingerprint 计算、hygiene 检查、baseline 比较

**L458-471**: 基线漂移比较核心：
```typescript
const toolsetFp = await computeToolsetFingerprint(tools)
const schemaFp = await computeSchemaFingerprint(tools)
// ...
judgeBaselineCheck('toolset_unchanged_vs_approved', toolsetFp, approvedBaseline?.toolset_fingerprint, ...)
judgeBaselineCheck('schema_unchanged_vs_approved', schemaFp, approvedBaseline?.schema_fingerprint, ...)
```

**无基线时**：两个检查始终 SKIPPED/UNVERIFIED（不是 FAILED）——"No baseline → both are always SKIPPED/UNVERIFIED"

**L520-524**: DNS 答案变更独立判定——"a changed DNS answer is not a redirect, and folding it into redirect_policy would show readers the wrong check_id for what was actually observed"

**L526-530**: catch 块——已完成检查保持结果："we verified the handshake, then ran out of budget" is coherent and honest

### 5.3 wire.ts（375 行）— HTTP 层

- `ProbeAborted`: 预算耗尽时抛出
- `createProbeContext`: 跟踪 DNS 答案和重定向
- `readBodyWithBudget`: 带预算的 body 读取
- `CREDENTIAL_HEADERS`: 凭据头列表
- `withoutCredentialHeaders`: 跨主机时剥离凭据头
- `sendRequest`: 核心 HTTP 发送（经过 guardedFetch）

---

## 六、离线验证器（verifier 包）

### 6.1 verify-attestation.mjs（475 行）

**零依赖设计**：直接用相对路径 import canonicalizer 的 .ts 文件，利用 Node.js 原生 TypeScript type-stripping。不需要 pnpm install。

**验证步骤**：
1. 检查 payloadType 在白名单中
2. 解码 payload base64
3. 计算 PAE(payloadType, payloadBytes)
4. 加载密钥文档（--keys）或单公钥（--pubkey）
5. 检查每个签名：keyid 在密钥集中、密钥未吊销、observed_at 在有效期内
6. `crypto.subtle.verify('Ed25519', cryptoKey, sigBytes, preAuth)`
7. 检查 payload bytes 是否等于 canonicalizer 的规范编码

**退出码**：0 = 完全验证通过，1 = 任何失败

---

## 七、测试基础设施（fixtures 包）

16 个模拟 MCP server fixture（3 正面 + 13 负面），**在实现之前编写**。每个 fixture 声明了检查必须产生的结果。

TDD 工作流：`packages/fixtures` 在 prober 之前构建，"specifically so it could define what counts as correct independently of whatever this package's implementation happens to do."

fixture corpus 是"this package's actual acceptance criteria"。

---

## 八、Canari 应该学什么

### 8.1 立即可学的
| 设计 | mcpcheckup 的做法 | Canari 现状 | 差距 |
|---|---|---|---|
| **PAE 独立实现** | 验证器 PAE 从 spec 独立重写，不是 import | Canari 用 in-toto 库的 PAE | 建议独立验证器 |
| **suite_digest** | SHA-512 SRI over `git ls-tree` | Canari 有 scenario_sha256 但不绑定 runner 源码 | 加 runner source binding |
| **密钥时间窗口** | valid_from/valid_until/revoked_at 三字段 | Canari 无此概念 | 加 key rotation/revocation |
| **fixture-first TDD** | 16 fixtures before implementation | Canari 有 8 个测试文件 | 加 mock server fixtures |
| **零依赖验证器** | 裸 Node 运行，无 node_modules | Canari verify_cli 需要 pip install | 可接受但可以改进 |

### 8.2 中期可学的
| 设计 | mcpcheckup 的做法 | 价值 |
|---|---|---|
| **Allowlist 投影** | 投影是字段白名单，新字段不影响 fingerprint | 比 Canari 的全量 hash 更稳定 |
| **SSRF guard** | 23 种 IP 分类 + DNS 重绑定检测 + 预算 | Canari 做的是 registry API 调用（不是任意 URL），风险较低但可以借鉴 |
| **Cascading assertions** | 握手失败 → 后续检查级联到 UNVERIFIED + reason | Canari 的 run_multi 是顺序执行，失败只是计 error |
| **Bilingual reasons** | 中文 + 英文双语错误消息 | 国际化 |
| **Fixture corpus** | 16 个模拟 server 定义 acceptance criteria | 正式验收标准 |

### 8.3 不需要学的
| 设计 | 为什么不需要 |
|---|---|
| Protocol-contract checks | Canari 不做 MCP 协议合规检查，只做供应链验证 |
| SSRF guard | Canari 只调 registry API，不做任意 URL fetch |
| LLM-as-judge | Canari 架构守卫禁止 LLM |
| Cloud deployment | Canari 是 CLI 工具 + 本地存储，不是 hosted 服务 |

---

## 九、与 Canari 的精确对比

| 维度 | mcpcheckup | Canari | 差异原因 |
|---|---|---|---|
| **范围** | 远程 MCP server | npm + PyPI + MCP Registry + dsh.so | Canari 的核心差异化 |
| **检查对象** | MCP 协议合规 + 安全卫生 | 供应链验证（存在性/哈希/维护者） | 不同信任域 |
| **签名** | DSSE + Ed25519 + 密钥吊销 | DSSE + Ed25519 | 相同 |
| **离线验证** | 裸 Node.js，零依赖 | pip install canari-mcp | mcpcheckup 更好 |
| **规范化** | NFC-JCS (RFC 8785 + NFC) | sort_keys=True JSON | mcpcheckup 更严格 |
| **Supersession** | 无 | supersedes 指针链 | Canari 独有 |
| **同源失效传播** | 无 | related_revocations | Canari 独有 |
| **安装门禁** | 无（hosted 查询） | is_gate_passing() CLI | Canari 独有 |
| **原生 attestation** | 无 | npm provenance + PEP 740 | Canari 独有 |
| **扫描器编排** | 明确拒绝 | scanner_adapter.py | Canari 独有 |
| **测试** | 16 fixtures + 37 test files | 8 test files, 63 tests | mcpcheckup 更好 |
| **文档** | 双语，每个字段有来源 | 单语 | mcpcheckup 更好 |
| **密钥管理** | 有效期 + 吊销 + 轮换 | 单密钥，无过期 | mcpcheckup 更好 |

**结论**：mcpcheckup 和 Canari 服务不同的信任域。mcpcheckup 检查"这个 MCP server 是否按协议运行"；Canari 记录"这个组件在供应链中的验证结论"。它们是互补的。

Canari 应该从 mcpcheckup 学：
1. 密钥有效期/吊销管理
2. Suite 源码绑定（suite_digest）
3. Cascade assertion 模式
4. 更多测试 fixture
5. 双语支持


---

## 十、HTTP 探测层（wire.ts + protocol.ts 详细分析）

### 10.1 wire.ts（375 行）— HTTP 发送层

**核心符号：**
- `ProbeAborted` — 预算耗尽时抛出
- `createProbeContext` — 跟踪 DNS 答案变更和跨主机重定向
- `REDIRECT_STATUSES` — {301, 302, 303, 307, 308}
- `parseRetryAfterSeconds` — 从 Retry-After 头解析秒数
- `rateLimitAbort` — 429/503 带有效 Retry-After 时触发
- `durationAbort` — 超过 maxDurationMs 时触发
- `readBodyWithBudget` — 带字节预算的 body 读取
- `CREDENTIAL_HEADERS` — 跨主机时需要剥离的凭据头
- `withoutCredentialHeaders` — 剥离函数
- `sendRequest` — 核心发送函数

**CREDENTIAL_HEADERS 跨主机剥离规则：** 当重定向跨主机时，自动剥离凭据头（Authorization, Cookie 等）。这是 SSRF 防护的一部分——防止凭据泄露到非预期主机。

### 10.2 protocol.ts（689 行）— MCP 协议实现

**performHandshake（L300-361）：**

双模式握手——先尝试 modern（2026-07-28 spec 的 `server/discover`），失败后 fallback 到 legacy（2025-06-18 spec 的 `initialize`）：

1. 发送 `server/discover` JSON-RPC 请求
2. 如果 2xx 且返回 `supportedVersions` 数组 → modern 成功，返回第一个版本
3. 如果 4xx 且 JSON-RPC 错误码在识别列表中 → modern server 存在但拒绝了 probe（不 fallback 到 legacy——"a recognized modern error identifies a real client/server mismatch"）
4. 否则 → 调用 `performLegacyHandshake()` 尝试 legacy

**performLegacyHandshake（L363-461）：**

1. 发送 `initialize` JSON-RPC 请求，`protocolVersion: LEGACY_PROBE_VERSION`
2. 检查 `mcp-session-id` 头——"A compliant legacy server may issue none at all (observed: mcp.deepwiki.com)"——只有 server 实际发送了才转发
3. 发送 `notifications/initialized` 确认
4. 如果全部成功 → handshakeOk = true

**performToolsList（L485-646）：**

- 支持 nextCursor 分页（Suite 0.15.0），最多 `budget.max_tools_list_pages` 页
- 凭据门控检查在 body 解析之前——"classify the credential challenge from status + headers BEFORE the body is looked at, and let it veto ok. Previously the challenge was only attached in the !ok arm, so a response that was HTTP 401 with a structurally valid WWW-Authenticate challenge but whose body happened to carry a well-formed result.tools array came back ok=true with NO challenge"
- 列表不完整 → fingerprint 和 baseline 比较都 SKIPPED（"no fingerprint of part of a list"）

**performUnknownToolCall（L648-689）：**

发送 `tools/call` 调用一个不存在的工具名（PROBE_TOOL_NAME），用于触发 error_taxonomy 检查——"a tool call to a nonexistent tool is the standard way to exercise the server's error handling"

### 10.3 auth.ts（578 行）— 凭据门控判定

**classifyCredentialChallenge（L372-460）：**

严格的 RFC 7235 WWW-Authenticate 头解析器：
1. 只有 status=401 且有 WWW-Authenticate 头才分类
2. 解析 scheme token（Bearer, Basic, Digest 等）
3. scheme 后必须是空格、制表符或逗号（token 边界检查）
4. 修复了两个 bug：接受了 HTAB（RFC 7235 要求 1*SP）和拒绝了合法的多 challenge 列表（`Basic , Bearer realm="x"`）
5. `MAX_SCHEME_LEN` 上限——超过就拒绝不截断
6. 每个 challenge 的参数（realm, scope 等）被解析出来供后续使用

**judgeAuthMetadata（L528-577）：**

从凭据 challenge 中提取 metadata URL → 发送 GET → 解析 JSON → 检查 `scopes_supported` 是否与 challenge 的 scope 矛盾：
- 矛盾 → OBSERVED_RISK（"the challenge asks for a scope the metadata says is not supported"）
- 一致 → VERIFIED
- 无法获取 → OBSERVED_RISK

### 10.4 hygiene.ts（478 行）— 工具描述卫生检查

`runHygieneCheck(tools)` 遍历每个工具的 description，检查多种模式：

- Suite 0.19.0：`excessive_length` 单独不计入 OBSERVED_RISK——"a length-only tool keeps its flag but doesn't trigger the risk verdict"
- 结果：`riskTools > 0` → OBSERVED_RISK，否则 VERIFIED
- 中文摘要："扫描了 N 个工具，M 个未触发任何信号"

---

## 十一、探测预算（budget.ts，41 行）

```typescript
DEFAULT_PROBE_BUDGET = {
    maxRedirects: 3,       // 最多跟随 3 次重定向
    maxDurationMs: 10_000, // 整个 guardedFetch 调用最多 10 秒
    maxBodyBytes: 2_097_152, // 每个 hop 最多读 2MB body
    maxRequests: 8,        // 整个调用最多 8 个出站请求
}
```

关键注释："These numbers are this suite's PUBLISHED contract, not a private deployment threshold: checks.json's own budget field states the same values, and the reachability check's reader copy quotes them."

曾经有 claimed/unclaimed 两层预算（claimed=8, unclaimed=4），但 2026-09-09 裁决撤回了区别——"a legacy-protocol round costs 5 requests at minimum, so 4 could never finish one, and what it actually produced was UNVERIFIED rather than the intended courtesy."

---

## 十二、DNS 解析与重绑定防护（resolve.ts，151 行）

**DNS-over-HTTPS (DoH) 解析：**
- 使用固定的受信任 DoH 解析器（不是系统 DNS）
- 同时查询 A 和 AAAA 记录（Promise.allSettled）
- **一个坏地址拒绝整个集合**："a multi-homed name is only as trustworthy as its worst answer"

**DNS 重绑定防护：**
1. 解析 hostname → 得到 IP 地址列表
2. 对每个 IP 调用 `classifyIp()` 检查是否在阻止范围内
3. 任何一个被阻止的 IP → 整个域名被拒绝
4. 探测过程中持续监控 DNS 答案是否变化（`dnsAnswerChangedDuringProbe`）

**TXT 记录查询**：故意 NOT fail-closed——"for A/AAAA, no address means there is nothing to connect to, so rejecting is right. For TXT, no record is an ordinary, expected answer"

---

## 十三、Canari 需要向 mcpcheckup 学习的完整清单

### P0（下次迭代必做）
| 设计 | 具体实现 | Canari 的对应改进 |
|---|---|---|
| PAE 独立实现 | verify-attestation.mjs L143-165 独立重写 DSSE spec | verify_cli.py 独立实现 PAE，不依赖 in-toto |
| 密钥生命周期 | valid_from/valid_until/revoked_at 三字段 | state.py 加 key management |
| suite source binding | suite_commit + suite_digest (SHA-512 over git ls-tree) | baseline.py scenario_sha256 加 runner source digest |
| Cascade assertions | probe.ts L275-281 级联 + 已完成的保持结果 | run_multi 失败时给后续检查加 UNVERIFIED + reason |
| Feed bundle_file | items 里有 bundle_file 字段 | 已修复（round 8） |

### P1（中期）
| 设计 | 具体实现 | Canari 改进方向 |
|---|---|---|
| Allowlist 投影 | projections.ts 字段白名单 | artifact fingerprint 改为投影后 hash |
| 密钥文档格式 | keys.json: key_id, algorithm, spki, spki_sha256, valid_from, valid_until, revoked_at | 独立于 attestation 的密钥管理文档 |
| Fixture corpus | 16 个模拟 server，在实现之前编写 | 为 Canari 的 registry adapter 写 mock fixtures |
| 双语 reason | REASON_MESSAGES: { key: { en: fn, zh: fn } } | Canari 的 verify_cli 输出加多语言 |
| 预算公开契约 | budget 值在 checks.json 里公开声明 | Canari 的 rate limit / timeout 写入 feed |
| Suite 版本迁移 | v0.1→v0.2→v0.3→v0.4 每版本完整 schema | Canari schema v0.1 的版本管理策略 |

### 不需要学的
| 设计 | 原因 |
|---|---|
| Protocol-contract checks | Canari 不做 MCP 协议合规 |
| SSRF guard | Canari 只调 registry API，不 fetch 任意 URL |
| LLM-as-judge | 架构守卫禁止 |
| Cloudflare Workers deployment | Canari 是 CLI 工具 |
| Next.js frontend | Canari 是 dashboard.html 单文件 |


---

## 十四、不变量三层独立强制（invariants.ts，44 行）

mcpcheckup 对 "UNVERIFIED 必须带 reason" 这条规则做了**三层独立强制**，三层互不信任：

1. **数据库层**：`CHECK constraint in supabase/migrations/0001_core.sql` — `assertion_status <> 'UNVERIFIED' OR coalesce(unverified_reason, reason) IS NOT NULL`
2. **Schema 层**：`then`/`anyOf` clause on `$defs.assertion` in `attestation.schema.json`
3. **代码层**：`invariants.ts` 的 `assertUnverifiedHasReason()` 函数

注释原文：*"None of the three trusts the others — a bug in the schema or a migration that silently drops the CHECK constraint still leaves this one standing, and vice versa."*

L35 的实现细节：不仅检查 `unverified_reason !== null`，还检查 `.key.length > 0`——空 key（`{ key: '' }`）也算没带 reason。这是独立层不应该信任 schema 层会检查 key 模式的体现。

**Canari 应该学**：schema.py 的 `validate_attestation()` 只做了 schema 验证，没有独立的不变量检查。如果 schema 文件被意外修改（或 jsonschema 库 bug），没有第二道防线。

---

## 十五、凭据形状检测（credential-shapes.ts，70 行）

**在签名之前，扫描 attestation payload 中是否嵌入了凭据形状的文本。**

6 条规则：

| 规则名 | 匹配模式 |
|---|---|
| jwt | `eyJ...` (JWT token 格式) |
| authorization header value | `Bearer <8+ chars>`, `Basic <8+ chars>`, `Token <8+ chars>`, `DPoP <8+ chars>` |
| private key block | `-----BEGIN ... PRIVATE KEY-----` |
| vendor key prefix | `sk_live_`, `sk_test_`, `ghp_`, `ghu_`, `gho_`, `ghs_`, `ghr_`, `github_pat_`, `xoxa-`, `xoxb-`, `xoxp-`, `xoxr-`, `xoxs-`, `glpat-`, `whsec_`, `AKIA` (AWS), `AIza` (Google) |
| long hex run | 32+ 位连续十六进制字符 |
| high-entropy token | 24+ 字符且同时含大写+小写+数字 |

**百分比解码迭代**：`%73k_test_` 被解码为 `sk_test_` 后仍然会被检测到。解码是迭代的（`%2573` → `%73` → `s`），直到字符串不再变化。

**自身计算值豁免**：`suite_digest`, `suite_commit`, `launch_config_digest`, `toolset_fingerprint`, `schema_fingerprint`, `run_id`, `auth_observation.resource_metadata_body_digest` 这些路径的值被豁免——但豁免条件是值必须匹配 schema 中的 pattern（从 schema 文件读取，不是重写）。如果有人在这些路径放了其他内容，仍然会被扫描。

**Canari 应该学**：在 `sign_attestation()` 之前调用 `credentialShapes()`，防止将凭据意外签入公开工件。

---

## 十六、digest.ts（13 行）+ 跨一致性测试

**digest 函数：** SHA-256 of JCS+NFC canonical form, 格式为 `"sha256:<64 lowercase hex chars>"`。

**跨一致性测试（cross-consistency.test.ts，59 行）验证了 4 个不变量：**

1. **键插入顺序无关**：`buildInOrder(['zebra','apple','mango'])` 和 `buildInOrder(['apple','zebra','mango'])` 的 canonicalize 结果完全相同
2. **嵌套对象的键顺序无关**：嵌套两层、三层的对象，键顺序打乱后 canonicalize 结果相同
3. **canonicalBytes 字节级一致**：不仅字符串相同，编码后的字节数组也逐字节相同
4. **JS 数字键排序陷阱**：JS 对象会把纯数字键按数值排序（`obj['10']` 排在 `obj['2']` 前面），但 RFC 8785 要求 UTF-16 code unit 排序（`"10" < "2"`）。测试 `canonicalize` 正确处理了这个 JS 引擎的默认行为差异

---

## 十七、正向 fixture 的设计质量（positive.ts，526 行）

### fixture：modern-baseline-clean

一个完全正确的 2026-07-28 modern 实现。guardsAgainst 字段说明了为什么需要这个测试：

*"P0 正确性要求（PRD §5.2）保证探测引擎不因为只见过 initialize 而认为一个完全正确的现代实现会 discovery_handshake=FAILED。这也是本文件最重要的 negative control（一个"全部通过"的正面存在），专门用来阻止初学者把这些唯一正常实现弄得通盘全 FAILED 的探测引擎上线。"*

### fixture：legacy-strict-accept-enforcement

**从真实生产事故中诞生的 fixture。** guardsAgainst 记录了完整故事：

*"Task Y 发现 mcp.deepwiki.com/mcp 在 L2b 首轮探测时被 disqualified。实际抓包证实该 legacy initialize/notifications/initialized/tools/list 全都要求 Accept 头同时列出 application/json 和 text/event-stream。缺失则 406。这意味着 packages/checks/src/protocol.ts 的 legacy 路径（performLegacyHandshake / performToolsList 的 legacy 分支 / performUnknownToolCall 的 legacy 分支）当时没有设置这个头。规范原文 modelcontextprotocol.io/specification/2025-06-18/basic/transports 的第 2 段（Backwards Compatibility 一节）明确说这个要求从第一个 InitializeRequest 就开始，只对后续请求…… 这意味着本文件中的 legacy-baseline-clean 的 mock server 从不校验 Accept 头，于是这个 bug 一直没被抓住。本 fixture 从 DeepWiki 的实际观察到的问题，作为教训，406 + 同一协议版本的行为专门抓住了'完全合规的 legacy 实现的每一个请求都必须带 Accept 头'这一点。"*

**这是 fixture-first TDD 的最佳实践：每个 fixture 都从真实观察中来，guardsAgainst 字段记录了它防止的 bug 和来源。**

---

## 十八、Canari 应该实现的优先级（基于逐行阅读）

### 立即实现（P0，每个 < 2 小时）

| # | 设计 | 源码参考 | Canari 改进 |
|---|---|---|---|
| C1 | **凭据形状检测** | credential-shapes.ts L16-22, 6 rules + percent decoding | sign_attestation() 之前扫 payload 是否嵌入凭据 |
| C2 | **UNVERIFIED 不变量** | invariants.ts L29-43, 三层独立强制 | schema.py 加 assertUnverifiedHasReason() |
| C3 | **Canonical JSON 检查** | cross-consistency.test.ts 4 个不变量 | signing.py 确认 payload 是 canonical JSON |
| C4 | **格式化 digest** | digest.ts, "sha256:<64 hex>" 格式 | verify_cli 输出统一格式 |

### 中期实现（P1）

| # | 设计 | 源码参考 | Canari 改进 |
|---|---|---|---|
| C5 | **guardsAgainst 字段** | positive.ts 每个 fixture 有 guardsAgainst 说明 | 测试文件加 guardsAgainst 注释 |
| C6 | **DNS 重绑定防护** | resolve.ts resolveAndValidateHost, 全集拒绝 | 如果 Canari 将来做 MCP server 探测的话 |
| C7 | **逐层独立强制** | invariants.ts 三层不互信 | schema.py + verify_cli + state.py 各自独立检查 |
| C8 | **Projection 版本化** | TOOLSET_PROJECTION_VERSION = 'v1', 发布后不可改 | Canari 未来加 projection 时要有版本号 |
