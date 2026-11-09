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
