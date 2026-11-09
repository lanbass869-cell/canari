# mcpcheckup/checks 拆解教材：设计决策的完整分析
## 每个模块逐行读，每个决策标注源码行号，每个模式说明为什么这样做
## 作为 Canari 的架构教材

---

## 第 1 章：签名架构（attestation-schema 包）

### 1.1 DSSE PAE 的安全意义

**源码：** `dsse.ts` L24-46

PAE（Pre-Authentication Encoding）是 DSSE 的核心安全机制。它不是对 payload 直接签名——而是对 `"DSSEv1" + 长度 + payloadType + 长度 + payload` 签名。

**为什么必须包含 payloadType：**

```
// PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
// 这是实际被签名的——不是原始 payload——这样 payloadType 也被认证了，
// 不能在不使签名失效的情况下被替换（DSSE 设计要防止的 "类型混淆" 攻击）
```

如果只签 payload 不签 payloadType，攻击者可以把一个 `{ code: 0, message: "ok" }` 的
attestation envelope 换成 `{ code: -32700, message: "parse error" }` 的 error envelope——
payload 完全相同但含义完全不同。

**mcpcheckup 的双层 PAE 实现：**

| 层 | 文件 | 用途 |
|---|---|---|
| 签名层 | attestation-schema/dsse.ts L31-46 | 签名时计算 PAE |
| 验证层 | verifier/verify-attestation.mjs L143-165 | 独立重写 PAE，不是 import |

**为什么验证层要独立重写：** verify-attestation.mjs L64-71 的注释：

```
// Relative path, not the bare `@mcpcheckup/canonicalizer` specifier —
// deliberately, even though this package has its own package.json. A third
// party who has cloned this repository must be able to run
// `node packages/verifier/verify-attestation.mjs` directly, with no `pnpm
// install` and no node_modules of any kind
```

"Both implement the same public spec, so they must compute identical bytes for
identical input by construction; that fact is exactly what makes this a
meaningful independent check instead of a formality."

**Canari 的启示：** Canari 的 verify_cli.py 依赖 in-toto 库做签名验证。如果 in-toto
库有 bug（或者被供应链攻击），verify_cli 无法检测。应该加一个独立实现的 PAE
计算 + canonical JSON 检查。**A1 已实现**（commit e0b3c4a）。

### 1.2 DSSE 测试覆盖（dsse.test.ts，195 行，16 个测试）

**测试向量来自官方规范：**

```
// 官方 test vector：secure-systems-lab/dsse protocol.md Test Vectors
// PAYLOAD_TYPE = "http://example.com/HelloWorld" (29 bytes UTF-8)
// SERIALIZED_BODY = "hello world" (11 bytes UTF-8)
// 期望 PAE: "DSSEv1 29 http://example.com/HelloWorld 11 hello world"
// 期望 base64: "aGVsbG8gd29ybGQ="
```

**16 个测试覆盖的边界条件：**

| 测试 | 验证什么 |
|---|---|
| 官方 test vector | PAE 输出与规范逐字节匹配 |
| LEN() 十进制无前导零 | 空字符串 → `"DSSEv1 0  0 "`（两个空格，两个 "0"） |
| payloadType UTF-8 长度 | `类型` 的字节长度 ≠ JS 字符串 `.length` |
| body 是不透明字节 | body 不需要是合法 UTF-8——只要字节精确匹配 PAE 语法 |
| base64 round-trip | encode → decode → 逐字节相同 |
| 非标准 base64（+ / vs - _） | base64url 字符不报错但语义不保证 |
| sign + verify roundtrip | 合法签名验证通过 |
| envelope 形状 | 标准 JSON envelope 结构 |
| keyid 可选 | 有了就传给 envelope，没有就不传 |
| 篡改 payload 一个字节 | 签名失败 |
| 篡改 payloadType | 签名失败（PAE 包含 payloadType） |
| 错误密钥签名 | 失败 |
| 多签名 envelope | 至少一个签名通过即 OK |
| 不合法 base64 payload | verifyDsseEnvelope 返回 false（不 throw） |
| 一个签名不合法 base64 | 不影响其他合法签名的验证 |
| verifyDsseSignature 底层原子 | 直接对 (type, body, sig, key) 验证 |

**关键设计：** `verifyDsseEnvelope` 的文档说 "Never throws: this is meant to run
against envelopes from an untrusted source, and a caller of a Promise<boolean>
reasonably writes `if (await verifyDsseEnvelope(...))` with no try/catch."

**Canari 的启示：** Canari 的 `verify_signed()` 也遵循了"never throw"模式（返回
`tuple[bool, payload_or_None, error_or_None]`），这是正确的。

### 1.3 Schema 版本演进（v0.1 → v0.4）

| 版本 | 字段数 | 新增 | 变化原因 |
|---|---|---|---|
| v0.1 | 16 | — | 基础：canonicalization, suite_id, suite_version, suite_digest, registry_version, toolset_projection_version, protocol_revision, launch_config_digest, target, observed_at, run, probe_region, probe_dns_answer_changed, assertions, toolset_fingerprint, schema_fingerprint |
| v0.2 | 16 | — | 无字段变化，约束收紧（fixtures 和 schema sync 测试） |
| v0.3 | 17 | +suite_commit | 增加检查套件源码的 git commit 绑定 |
| v0.4 | 20 | +coverage, +run_id, +auth_observation | coverage 区分 full/auth_gated，run_id 唯一标识运行，auth_observation 记录凭据门控观察 |

**关键：v0.3 加了 suite_commit。** 这不只是"哪个版本的代码"——它是对 `git ls-tree -r --full-tree <commit> -- packages/checks` 的 SHA-512 引用。任何人都可以用这个 commit 重建出完全相同的检查套件源码。

**Canari 的现状：** scenario_sha256 只包含检查列表定义（JSON），不包含 runner 源码。A3 已修复（commit e0b3c4a）。

---

## 第 2 章：指纹架构（canonicalizer 包）

### 2.1 NFC-JCS 规范化（canonicalize.ts，148 行）

**为什么不用纯 RFC 8785：**

L4-7 注释：*"RFC 8785 §3.1 requires JCS-compliant components to preserve Unicode
string data 'as is'. Normalizing to NFC first, as this package does, is a
deliberate deviation from that MUST, so it gets its own name."*

**为什么要 NFC 归一化：** `"café"` 可以用两种 Unicode 序列表示：
- `caf\u00e9`（预组合）→ NFC 后不变
- `cafe\u0301`（分解）→ NFC 后变为 `caf\u00e9`

如果 server A 用预组合、server B 用分解，纯 JCS 会认为它们的 description 不同——
产生虚假 drift。NFC 前置消除了这个问题。

**NFC 后 key 碰撞检测（L78-83）：** 如果归一化后两个 key 相同（一个是预组合、
另一个是分解），规范化器**拒绝**而不是选一个——因为选择哪个原始 key 是有损的。

**JS 数字键排序陷阱（cross-consistency.test.ts L38-54）：**

JavaScript 对象对纯数字键有特殊排序行为：`obj['10']` 在 `obj['2']` 之前枚举
（因为 10 < 2 数值上）。但 RFC 8785 要求 UTF-16 code unit 排序：`"10" < "2"`。
测试 `canonicalize({d:3, '10':2, '2':1})` 确认输出为 `{"10":2,"2":1,"d":3}`。

**Canari 的现状：** `json.dumps(att, sort_keys=True, ensure_ascii=False)` 没有 NFC
归一化。如果 npm 包描述包含分解 Unicode 字符，两次扫描可能产生不同的 hash。

### 2.2 digest.ts（13 行）

```typescript
export async function digest(value: unknown): Promise<string> {
    const bytes = canonicalBytes(value)
    const hashBuffer = await crypto.subtle.digest('SHA-256', bytes)
    return 'sha256:' + toHex(hashBuffer)
}
```

输出格式：`"sha256:<64 lowercase hex>"`。**带前缀**的格式让消费者可以识别 hash
算法而不需要猜测。

**Canari 的现状：** verify_cli.py 输出 `payload sha256: <hex>`——没有 `sha256:` 前缀。

---

## 第 3 章：检查引擎（checks 包）

### 3.1 15 项检查的设计哲学

checks.json 中的设计：

**reach 组**（2 checks）：
- `reachability` — "endpoint 是否活着" → 只要收到 HTTP 响应就是 VERIFIED（包括 401/403）
- `latency_profile` — "响应多快" → 只观测不判定（"we don't define how many milliseconds counts as slow"）

**proto 组**（5 checks）：
- 检查 MCP 协议合规——transport_type, protocol_revision, discovery_handshake, tools_list, error_taxonomy
- design: "most 'the agent suddenly stopped working' failures live at this layer, not the security layer"

**sec 组**（4 checks）：
- "Publicly observable baseline security properties. **This is not a security scan**"
- tls_certificate 总是 SKIPPED（"out of scope for this fetch-based prober"）
- tool_description_hygiene 检查工具描述是否可疑（不检查恶意）

**drift 组**（4 checks）：
- "Whether the toolset or schema changed without your knowledge. **A change is only
  judged 'failed' after you've approved a baseline**; before that, it's just a recorded fact."

### 3.2 runProbe 的控制流（probe.ts，656 行）

**函数签名（L228-229）：**
```typescript
export async function runProbe(input: ProbeInput): Promise<ProbeResult>
```

**执行顺序（L308-524）：**

```
1. createProbeContext(Date.now())          → 跟踪 DNS 和重定向
2. performHandshake(...)                    → modern (discover) 或 legacy (initialize)
3. A('reachability', ...)                   → 有响应就 VERIFIED
4. A('discovery_handshake', ...)            → OK/FAILED/UNVERIFIED(credential_required)
5. A('protocol_revision', ...)              → 对照 revision_matrix
6. A('transport_type', ...)                 → 无条件 VERIFIED
7. performToolsList(...)                    → 分页，credential gate 检查
8. A('tools_list', ...)                     → OK/FAILED/UNVERIFIED
9. computeToolsetFingerprint(tools)         → NFC-JCS 投影 + SHA-256
10. computeSchemaFingerprint(tools)         → NFC-JCS 投影 + SHA-256
11. runHygieneCheck(tools)                  → 工具描述卫生
12. judgeBaselineCheck(toolset_fingerprint, approvedBaseline, ...) → 漂移对比
13. judgeBaselineCheck(schema_fingerprint, approvedBaseline, ...)
14. performUnknownToolCall(...)             → 发送 tools/call 调用不存在的工具
15. judgeErrorTaxonomy(callResult)          → server 的错误处理是否合规
16. judgeAuthMetadata(...)                  → auth 元数据是否与 challenge 一致
17. redirect_policy 判定                    → 跨主机重定向 → OBSERVED_RISK
```

**Cascade 语义（L275-281）：**

```typescript
const cascadeRemaining = (execution_status: ExecutionStatus, reason: Reason) => {
    for (const def of registry.checks) {
        if (assertionsByCheckId.has(def.check_id)) continue  // 已完成的保持结果
        if (def.check_id === 'latency_profile') continue       // finalize() 写
        A(def.check_id, execution_status, 'UNVERIFIED', reason)
    }
}
```

关键：已完成的检查保持结果。"we verified the handshake, then ran out of budget"
is coherent and honest——这不是全有全无。

**凭据门控的三层：**

| 层 | 触发条件 | 结果 |
|---|---|---|
| 握手层 | `!handshakeOk && credentialChallenge !== undefined` | discovery_handshake + protocol_revision → UNVERIFIED |
| tools/list 层 | handshakeOk 但 tools/list 返回 401+challenge | tools_list → UNVERIFIED，握手结果保持 |
| tools/call 层 | tools/list 正常但 tools/call 返回 401 | error_taxonomy → UNVERIFIED |

每层只影响自己的范围——"a gate on tools/list alone leaves the handshake's real
verdicts in place"。

**探测工具调用的安全检查（L384-401）：**

```typescript
let probeCallWithheld: Reason =
    !toolsList.ok ? null
    : toolsList.tools!.some(tool => tool.name === PROBE_TOOL_NAME)
      ? { key: 'probe_tool_name_collision' }
    : listIncomplete
      ? { key: 'probe_tool_name_unverifiable' }
    : null
```

如果 server 有一个叫 `PROBE_TOOL_NAME` 的工具，不发送调用——避免与真实工具冲突。
如果列表不完整，也不发送——"the name could be on a page we did not read, so the
call could reach a real tool"。

### 3.3 错误分类学（error-taxonomy.ts，148 行）

**judgeErrorTaxonomy(callResult):**

发送一个不存在的工具的 `tools/call` 调用，检查 server 的错误处理是否符合规范：

- 401/403 → UNVERIFIED（"HTTP-layer auth rejection says nothing about whether the
  server's protocol-level error shape is conformant"）
- JSON-RPC error → VERIFIED（正确的协议错误响应）
- 其他 → OBSERVED_RISK + 分类为 7 种之一：
  - `empty_body`, `event_stream_no_data`, `result_is_error`, `result_ok`,
    `jsonrpc_malformed`, `not_jsonrpc`, `not_json`

**为什么 result_ok 是 OBSERVED_RISK 而不是 FAILED：** 如果 server 对不存在的工具
返回了成功结果（`result.isError: false`），说明这个 server 的错误处理不符合 MCP
规范——但这可能只是一个奇特的 server 实现，不是恶意行为。OBSERVED_RISK 是诚实
的判定。

### 3.4 延迟测量（latency.ts，80 行）

**设计决策：**

- 只计算协议请求（POST to endpoint）的延迟
- "The one GET this package sends, auth.ts's fetch of the challenge's metadata
  document, is deliberately not counted: it is a metadata fetch, not a protocol
  interaction."
- 使用 **nearest-rank percentile**（p50, p95）——不是平均值（"an average is
  dominated by the slowest request"）
- `timed_to` 参数记录了测量粒度（毫秒）

---

## 第 4 章：安全层（ssrf-guard 包）

### 4.1 IP 分类（ip-policy.ts，272 行）

**完整 IANA IPv4 + IPv6 Special-Purpose Address Registry 实现。**

23 种阻止代码。每种都有 RFC 引用：

```typescript
{ base: '169.254.169.254', prefix: 32, code: 'CLOUD_METADATA', ... }
```

**关键设计：**

1. **最具体匹配行决定结果**（IANA 自己的规则："unless allowed by a more specific
   allocation"）——排序为 prefix 降序，第一个匹配的行决定
2. `code: null` 的行不阻止（"Globally Reachable" = True）
3. IPv6 只在 `2000::/3`（global unicast）内判断——outside it, a row can only
   choose the code an address is blocked with, never allow it
4. `parseIpv4()` 是严格解析——只接受标准点分十进制。"we produced ourselves"
   ——不做 hex/octal 处理（"URL.hostname already normalizes"）
5. IPv4 表有 30+ 行，包括很少人知道的 `192.0.0.8/32`（dummy address, RFC 7600）
   和 `192.0.0.170/32`（NAT64/DNS64 discovery, RFC 8880）

### 4.2 DNS 重绑定防护（resolve.ts，151 行）

**resolveAndValidateHost() 的流程：**

1. `resolveHost()` — 通过 **DoH**（DNS-over-HTTPS）解析 A 和 AAAA 记录
   - 使用固定的受信任 DoH 解析器，不是系统 DNS
   - `Promise.allSettled` 并行查询 A 和 AAAA
   - 空地址集 → `SsrfBlocked('RESOLUTION_FAILED')`
2. `validateAddresses()` — 对每个 IP 调用 `classifyIp()`
   - **任何一个被阻止的 IP → 整个域名被拒绝**
   - 注释："a multi-homed name is only as trustworthy as its worst answer"
3. 探测过程中持续监控 DNS 答案是否变化
   - `dnsAnswerChangedDuringProbe` → `disqualifiedFromPublication`

**DoH vs 系统 DNS：** 使用 DoH 是为了防止 DNS 级别的劫持——系统 DNS 可能被
ISP 或恶意网络修改。DoH 用 HTTPS 加密，更难篡改��

**TXT 记录特殊处理：** 故意 NOT fail-closed。"For A/AAAA, 'no address' means
there is nothing to connect to, so rejecting is right. For TXT, 'no record' is
an ordinary, expected answer — the record simply has not been published yet."

### 4.3 请求预算（budget.ts，41 行）

```typescript
DEFAULT_PROBE_BUDGET = {
    maxRedirects: 3,
    maxDurationMs: 10_000,
    maxBodyBytes: 2_097_152,  // 2MB
    maxRequests: 8,
}
```

**关键注释：** "These numbers are this suite's PUBLISHED contract, not a private
deployment threshold: checks.json's own budget field states the same values,
and the reachability check's reader copy quotes them."

**曾经有 claimed/unclaimed 两层预算（claimed=8, unclaimed=4），2026-09-09 裁决撤回：**
"a legacy-protocol round costs 5 requests at minimum (server/discover → initialize
→ notifications/initialized → tools/list → tools/call), so 4 could never finish
one, and what it actually produced was UNVERIFIED rather than the intended courtesy."

---

## 第 5 章：凭据形状检测（credential-shapes.ts，70 行）

### 5.1 六条规则

| 规则 | 检测什么 |
|---|---|
| jwt | `eyJ...` 开头的 JWT token |
| authorization header | `Bearer <8+ chars>`, `Basic <8+ chars>`, `Token <8+>`, `DPoP <8+>` |
| private key block | `-----BEGIN ... PRIVATE KEY-----` |
| vendor key prefix | `sk_live_`, `sk_test_`, `ghp_`, `ghu_`, `gho_`, `ghs_`, `ghr_`, `github_pat_`, `xoxa-`, `xoxb-`, `xoxp-`, `xoxr-`, `xoxs-`, `glpat-`, `whsec_`, `AKIA<16>`, `AIza<20>` |
| long hex run | 32+ 位连续 hex |
| high-entropy token | 24+ 字符且含大写+小写+数字 |

### 5.2 百���比迭代解码

```typescript
// %73k_test_ → sk_test_ → 被检测到
// %2573 → %73 → s → 如果 sk_test_ 则被检测到
export function percentDecoded(s: string): string {
    let out = s
    for (let next = decodeOnce(out); next !== out; next = decodeOnce(out)) out = next
    return out
}
```

迭代直到字符串不再变化——`%2573` 先变成 `%73` 再变成 `s`。

### 5.3 自身计算值豁免

`suite_digest`, `suite_commit`, `launch_config_digest`, `toolset_fingerprint`,
`schema_fingerprint`, `run_id`, `auth_observation.resource_metadata_body_digest`
这些路径的值被豁免。

**豁免条件是值必须匹配 schema 中的 pattern。** Pattern 从 schema 文件读取，
不是重写——"so anything else placed there is still scanned."

**Canari 已实现（commit b7c78c9）。** `_OWN_HASH_FIELDS` 集合 + 6 条规则 +
percent decoding。与 mcpcheckup 的差异：Canari 用 Python `re` 模块（mcpcheckup
用 JS 正则），逻辑相同。

---

## 第 6 章：不变量三层强制（invariants.ts，44 行）

**一条规则，三层独立实现：**

```
规则：assertion_status == 'UNVERIFIED' → 必须有 reason（非空 key）

层 1：数据库 CHECK constraint
    supabase/migrations/0001_core.sql
    CHECK (assertion_status <> 'UNVERIFIED' OR coalesce(unverified_reason, reason) IS NOT NULL)

层 2：JSON Schema anyOf/then
    schema/attestation.schema.json $defs.assertion

层 3：TypeScript 函数
    invariants.ts assertUnverifiedHasReason()
```

**注释：** "None of the three trusts the others — a bug in the schema or a
migration that silently drops the CHECK constraint still leaves this one
standing, and vice versa."

**实现细节（L35-36）：** 不仅检查 `!== null`，还检查 `.key.length > 0`。
空 key（`{ key: '' }`）也算没带 reason。这一层不信任 schema 层的 key
pattern 检查。

**Canari 已实现部分（commit b7c78c9）：** schema.py 加了 `assert_unverified_has_reason()`。
但 Canari 用的是 `"unsupported"` 而不是 `"UNVERIFIED"`，且暂时是 pass-through
（Canari 的 schema 不强制这个规则）。未来 schema v0.2 应该硬性要求。

---

## 第 7 章：fixture-first TDD（fixtures 包）

### 7.1 设计原则

fixtures 在实现之前编写："specifically so it could define what counts as
correct independently of whatever this package's implementation happens to do."

16 个 fixture（3 正面 + 13 负面），每个 fixture 是一个 `FetchHandler`——
模拟 MCP server 的 HTTP 响应行为。

**fixture corpus 是 acceptance criteria，不是 unit test input。**

### 7.2 从真实生产事故诞生的 fixture

**legacy-strict-accept-enforcement fixture**（positive.ts L48-70）：

guardsAgainst 字段记录了完整的故事：

> Task Y 发现 mcp.deepwiki.com/mcp 在探测时被 disqualified。
> 实际抓包证实该 legacy 实现的每一个请求都要求 Accept 头同时列出
> application/json 和 text/event-stream。缺失则 406。
> 
> 但 packages/checks/src/protocol.ts 的 legacy 路径没有设置这个头。
> 规范原文 modelcontextprotocol.io 的 Backwards Compatibility 一节
> 明确说这个要求从第一个 InitializeRequest 就开始。
> 
> 本文件中的 legacy-baseline-clean 的 mock server 从不校验 Accept 头，
> 于是这个 bug 一直没被抓住。本 fixture 从 DeepWiki 的实际观察到的问题
> 作为教训。

**这告诉我们：** 每个负面的生产体验都应该变成一个 fixture。fixture 不是
"理想的输入"——它是"上次让我犯错的输入"。

### 7.3 fixture 的结构

```typescript
interface Fixture {
    id: string                    // 唯一标识
    description: string           // 中文描述
    protocolRevision: string      // '2026-07-28' 或 '2025-06-18'
    kind: 'positive' | 'negative'
    guardsAgainst: string         // 这个 fixture 防止什么 bug
    tools: ToolDefinition[]       // 模拟 server 的工具列表
    createHandler: () => FetchHandler  // 模拟 HTTP 响应
    sampleRun: (handler) => ...   // 如何用这个 fixture 跑探测
    expectedAssertions: ExpectedAssertion[]  // 每个检查的期望结果
}
```

**expectedAssertions 是核心：** 每个检查的期望 status 和 reason key。测试运行
probe 对 fixture，然后逐条对比实际 assertion 和期望 assertion。

---

## 第 8 章：Canari 应该实现的具体功能

### 8.1 从 mcpcheckup 学的（已完成 + 待做）

| 已完成 | commit | 内容 |
|---|---|---|
| A1 PAE 独立交叉验证 | e0b3c4a | `_independent_pae()` + `_independent_verify()` |
| A2 密钥生命周期 | e0b3c4a | `create_key_registry_entry()` + `revoke_key()` + `is_key_valid()` |
| A3 suite source binding | e0b3c4a | `_runner_source_digest()` → scenario_sha256 |
| A4 cascade error attestations | e0b3c4a | npm 失败包产出 error attestation |
| B1 密钥接入 pipeline | 3733b3b | key_registry.json 创建/加载/验证 |
| C1 凭据形状检测 | b7c78c9 | 6 规则 + 百分比解码 + hash 豁免 |
| C2 UNVERIFIED 不变量 | b7c78c9 | `assert_unverified_has_reason()` |

| 待做 | 设计 | 价值 |
|---|---|---|
| NFC 归一化 | `unicodedata.normalize('NFC', s)` 在 hash 之前 | 消除 Unicode 归一化差异导致的假 drift |
| digest 前缀格式 | `"sha256:<64 hex>"` | 消费者可识别算法 |
| guardsAgainst 字段 | 每个测试注明防止的 bug | 测试不只是验证，也是文档 |
| 攻击语料 | benign.json + malicious.json 语料 | 量化规则质量（FP rate, FN rate） |
| toolset-diff | 逐工具对比，canonical form | 更精细的 drift 检测 |
| 密钥文档格式 | keys.json 独立于 attestation | 消费者可离线读取密钥信息 |

---

## 第 9 章：Canari 和 mcpcheckup 的架构差异总结

| 维度 | mcpcheckup | Canari | 为什么不同 |
|---|---|---|---|
| **检查对象** | 远程 MCP server 的协议行为 | npm/PyPI/MCP/dsh 包的供应链属性 | 不同信任域 |
| **检查深度** | 15 项协议合规检查 | L1-L2 meta + 原生 attestation 摄入 | mcpcheckup 更深（但领域不同）|
| **签名** | DSSE + Ed25519 + 密钥吊销 | DSSE + Ed25519（同）| — |
| **离线验证** | 裸 Node.js 零依赖 | pip install canari-mcp | mcpcheckup 更好 |
| **规范化** | NFC-JCS v1（RFC 8785 + NFC）| sort_keys JSON（无 NFC）| mcpcheckup 更严格 |
| **凭据检测** | 6 rules + percent decode + schema exemption | 6 rules + percent decode + hash exemption | 相同 |
| **不变量** | 3 层独立强制 | 2 层（schema + placeholder）| mcpcheckup 更严格 |
| **Supersession** | 无 | supersedes 指针链 | Canari 独有 |
| **失效传播** | 无 | related_revocations | Canari 独有 |
| **安装门禁** | 无 | is_gate_passing() CLI | Canari 独有 |
| **原生 attestation** | 无 | npm Sigstore + PEP 740 | Canari 独有 |
| **跨 registry** | 无 | npm+PyPI+MCP+dsh | Canari 独有 |
| **测试** | 37 test files + 16 fixtures | 10 test files, 71 tests | mcpcheckup 更好 |
| **文档** | 每个字段有中英文来源注释 | 单语 | mcpcheckup 更好 |

**结论：** mcpcheckup 在"深度"上赢（协议检查、安全工程、测试基础设施）。
Canari 在"广度"上赢（跨 registry、supersession、传播、门禁、原生 attestation）。
两者互补而非竞争。Canari 应该学它的深度，同时保持自己的广度优势。


---

## 二十、61 项探测测试（probe.test.ts，1,513 行）

**这是主探测引擎的完整测试文件。61 个测试覆盖的边界条件：**

### 预算耗尽的级联语义

- `response-exceeds-budget`：tools/list 响应超过 2MB → 已完成的检查（reachability, discovery_handshake, protocol_revision, transport_type）**保持 COMPLETED/VERIFIED**。未跑到的检查 → SKIPPED/UNVERIFIED + `probe_budget_exhausted_body`。
- 注释（guardsAgainst）："超预算必须是 execution_status=ERROR + assertion_status=UNVERIFIED，绝不能是 FAILED。超时/超量不等于'这个 server 坏了'——也可能是我们这边的探测节点或网络问题。"

### 凭据门控的边界

- `credential-gated-tools-list-with-tools-body`：tools/list 返回 401 + 合法 challenge，**但 body 里带着结构完好的 tools 数组**。tools_list 记 COMPLETED/UNVERIFIED（因为被门控了），**不计算 fingerprint**——" declaring tools_list unverified while still publishing a fingerprint derived from that same response would be incoherent"
- 对照测试：同一个 handler，只把 401 换成 200（body 逐字节不变）→ fingerprint 被正常计算。**证明上面的行为是因为门控，不是因为数据问题**
- `credential-challenge-htab-separator-not-exempted`：scheme 与 realm 之间是 HTAB（不是 1*SP）→ 不豁免，记 FAILED
- `credential-challenge-qdtext-control-char-not-exempted`：realm 的 quoted-string 里夹了 %x01 控制字符 → 不豁免，记 FAILED

### 探测工具名碰撞（T86）

- 红证 a：第一页有逐字同名的工具 → 不发 tools/call
- 红证 b：第一页无同名但带 nextCursor → 读第二页发现同名 → 不发 tools/call
- 红证 c：tools/list 失败 → 也不知道有没有同名 → 不发 tools/call
- 门控下的 T86b：握手和 tools/list 都被 401 挡了 → 不发 tools/call，error_taxonomy 和 auth_metadata 都 SKIPPED

### 限流判定

- 429 无 Retry-After → 不是限流（继续跑完整轮）
- 429 有 Retry-After → 是限流，rateLimited 字段带 Retry-After 秒数
- 503 无 Retry-After → 不是限流（继续跑完整轮）
- 503 有 Retry-After → 是限流
- 对照：同一个 503，只多一个 Retry-After 头 → 行为相反。**证明判据在头上，不在状态码上**

### 延迟测量的边界

- 正常运行 → latency_profile = SKIPPED/UNVERIFIED/latency_not_recorded（因为 sendRequest 没有计时间）
- 凭据门控运行 → 同样 latency_not_recorded
- 级联中止 → 永远不被 cascade 覆盖
- stdio 目标 → latency_not_recorded（不是 stdio_out_of_scope）
- **每个 corpus fixture 都恰好有一条 latency_profile 行**

### 请求计数的有区分力验证

- "这张表有区分力（否则它是一张恒真的表）：legacy 两条在 maxRequests=4 与 maxRequests=8 下的请求数必须不同，modern 两条必须相同"
- 这意味着他们不仅测试了行为，还测试了**测试本身的区分力**——如果减少请求数不改变结果，说明测试是恒真的

---

## 二十一、38 个负面 fixture 的完整清单（protocol-negatives.ts，1,265 行）

每个 fixture 是一个模拟 MCP server 的 HTTP handler，返回构造好的恶意/异常响应：

| fixture | 模拟的攻击/异常 |
|---|---|
| staleProtocolVersion | 返回旧版本号 |
| toolsListIllegalStructure | tools/list 返回非数组 |
| legacyEverythingRequiresAuthStillFails | 所有请求都要 auth，但 credentials 也不通过 |
| errorResponseNonconformantShape | JSON-RPC 错误格式不合规 |
| noCredentialsUnverifiableAuth | 401 但无 WWW-Authenticate 头 |
| responseExceedsBudget | 2MB 超大响应 |
| redirectCrossHost | 302 跳转到不同主机 |
| forbidden403NotCredentialGated | 403 但没有 challenge → 不是凭据门控 |
| credentialChallengeEmptyHeader | WWW-Authenticate 头为空 |
| credentialChallengeMalformedHeader | WWW-Authenticate 格式不合法 |
| credentialChallengeHtabSeparator | scheme 和 realm 之间用 HTAB |
| credentialChallengeQdtextControlChar | realm 里夹控制字符 |
| credentialChallengeMalformedRemainder | challenge 参数格式不合法 |
| recognizedModernErrorCodeUnchanged | 已识别的 modern 错误码 |
| recognizedModernErrorCodeAt401NotExempted | 401 + 已识别错误码 → 不豁免 |
| rateLimited429NoRetryAfter | 429 无 Retry-After |
| rateLimited429WithRetryAfter | 429 有 Retry-After |
| rateLimited503WithRetryAfter | 503 有 Retry-After |
| serviceUnavailable503NoRetryAfter | 503 无 Retry-After |
| errorTaxonomyResultIsErrorJson | 错误以 JSON result 返回（isError=true）|
| errorTaxonomyResultIsErrorSse | 错误以 SSE event-stream 返回 |
| errorTaxonomyResultOk | 不存在的工具返回成功结果 |
| errorTaxonomyNotJsonrpc | 响应不是 JSON-RPC |
| errorTaxonomyJsonrpcMalformed | JSON-RPC 格式畸形 |
| errorTaxonomyEventStreamNoData | SSE 无数据 |
| errorTaxonomyEmptyBody | 空响应体 |
| handshakeAckHttpError | 初始化确认 HTTP 错误 |
| protocolRevisionMissing | 无协议版本 |
| protocolRevisionUnknown | 未知协议版本 |
| fingerprintToolMissingName | 工具没有 name |
| fingerprintCanonicalizeFailed | 工具 schema 无法 canonicalize |
| probeToolNameCollision | 探测工具名与真实工具名冲突 |
| probeToolNameCollisionSecondPage | 碰撞在第二页 |
| probeToolNameUnverifiable | 列表不完整，无法判断 |
| probeToolNameCollisionGatedHandshake | 碰撞 + 门控 |
| probeToolNameUnverifiableGated | 不完整 + 门控 |
| probeToolNameRegisteredToolsListGated | 已注册 + tools/list 门控 |
| probeToolNameRegisteredHandshakeGated | 已注册 + 握手门控 |

---

## 二十二、51 项 Schema 测试（schema.test.ts，617 行）

**每个 Schema 版本互相拒绝对方的样例：**

- v0.1 样例（裸字符串 reason）被 v0.2 schema 拒绝
- v0.2 样例（{key} 对象 reason）被 v0.1 schema 拒绝
- v0.2 样例被 v0.3 拒绝（缺 suite_commit）
- v0.3 样例被 v0.2 拒绝（suite_commit 是未声明字段）

**关键边界条件：**

| 测试 | 验证什么 |
|---|---|
| 月 13、日 40 | 日期格式正确但日历上不存在 → 拒绝 |
| transport=remote 但 launch_config_digest 非 null | remote 和 stdio 的字段互斥 |
| transport=stdio 但 probe_dns_answer_changed=false | stdio 不做 DNS，字段必须为 null |
| target.name 大写字母 | slug 格式拒绝大写 |
| UNVERIFIED 且 reason 只有空白字符 | 光靠 minLength 挡不住三空格 |
| assertion.reason 是裸字符串 | v0.2 起拒绝（v0.1 允许）|
| suite_commit 39 位截断 | 差一位都拒绝 |
| suite_commit 64 位 SHA-256 | 错误的对象名格式 |
| suite_commit 大写 | 必须全小写十六进制 |
| observed_at 格式合法但写法不唯一 | 固定精度 + 固定 Z 后缀是唯一写法 |
| assertions 空数组 | 至少一条 |
| 顶层出现未声明字段 | additionalProperties:false 在每一层都验证 |

---

## 二十三、37 项验证器测试（verify-attestation.test.mjs，562 行）

**安全攻击场景：**

| 测试 | 攻击场景 |
|---|---|
| 翻转 payload 一个字节 | 签名不再覆盖新字节 |
| 翻转签名一个字节 | 签名本身被篡改 |
| 改 payloadType 但不重新签名 | **PAE 类型混淆防护验证**——证明类型包含在签名内 |
| 合法 JSON 但非规范编码 | 第 6 步（canonical form check）单独起作用 |
| 不在白名单的 payloadType | **在任何验签动作之前**就失败 |
| keyid 与公钥不符 | keyid 是 key 的指纹，不匹配就拒绝 |
| 两个签名，一个 keyid 对、一个不对 | **整体失败**——每个签名的 keyid 都要对 |
| 已吊销的钥 | 一律失败，不论 observed_at |
| valid_until 边界（毫秒精度） | observed_at == valid_until 通过；晚 1ms 失败 |
| observed_at 无小数位 vs 有小数位 | 按毫秒的 RFC 3339 瞬间比较，不按字符串 |
| payload 没有 observed_at | 失败（valid_from 一定有值） |
| 两个签名，一个吊销、一个有效 | **整体失败**（不静默跳过） |
| 两个签名，一个有效、一个 keyid 不在文档 | **整体失败**（未知 keyid 不能被有效签名掩盖） |

**最重要的测试：**
- "改成另一个被允许的 payloadType 但不重新签名 → exit 非 0（证明 PAE 的类型混淆防护真的在起作用，不是被白名单顶替）"
- 这证明 PAE 的类型混淆防护不是碰巧生效的——即使 payloadType 在白名单内，如果不重新签名，仍然失败

**双向 schema 兼容性测试：**
- "verifier 的 ALLOWED_PAYLOAD_TYPES 与 attestation-schema 自己列出的 payloadType 逐项相同（含顺序）"
- "schema 包的每个 payloadType，verifier 实际都接受（行为一致，而不只是文本一致）"
- "--help 列出的 payloadType 与 attestation-schema 的列表逐项相同"

---

## 二十四、差分测试架构（19 个文件，584KB）

**设计：同一个输入，跑过新旧两个版本的实现，断言结果差异恰好是预期的新增功能。**

### frozen 目录

16 个历史版本（suite-0.6.0 到 suite-0.19.1），每个包含该版本所有模块的完整源码。

### differential-shard.ts（110 行）

分片系统：
- 大文件（probe-tool-name-differential 1,167 行 / failed-reasons-differential 1,345 行 / guard-error-classification 660 行）的输入空间分片并行
- 环境变量：SHARD_INDEX, SHARD_COUNT, SHARD_MODE ('run'|'merge'), SHARD_OUT_FILE, SHARD_IN_FILES
- 全集断言（如"每个 oracle 分支都被到达"）只在 merge 进程中运行——"a whole-set assertion is a property of the FULL input space. Splitting it across two shards would make it a coin flip"

### failed-reasons-differential.test.ts（1,345 行）

**三方对比，互不共享代码：**
1. **当前实现** — runProbe end-to-end
2. **FROZEN_PRE_T73b** — 从 `git show 70618ee:…` 提取的修改前代码，逐字节复制。注释说 "DO NOT 'update' this copy to match a later implementation — its only job is to be the pre-T73b behaviour"
3. **ORACLE** — 完全独立的预测器，不 import 任何实现代码，自己实现 SSE 解析、JSON-RPC 验证、规范化检查

**输入空间：** 13 个 HTTP 状态码 × 12 种 Content-Type × 63 种 body = 9,828 个输入

**五个断言（对每个输入）：**
a) 每个检查的 assertion_status 三方一致
b) 直接调用的结果与 FROZEN 深度相等（除了新增字段）
c) FAILED ⇒ reason 等于 ORACLE 的预测；UNVERIFIED ⇒ 不是 T73b key
d) params 只含允许的字段名，status 只在 7 个 key 上出现，无空 params
e) 每个渲染的 reason 在 en 和 zh 中都无禁止词、无 canary 泄漏、无 8 字符 body 窗口泄漏

### Canary 安全检查

```typescript
const CANARY = 'CANARYq7Zx'
```

嵌入在测试 body 中的金丝雀字符串。检查渲染后的 reason 消息：
- 不包含 canary 本身
- 不包含输入 body 的任何 8 字符子串（防止 server 控制的文本泄漏到签名 attestation）
- 如果 reason 是从固定 key 渲染的（不是从 server 响应构建的），不可能包含 body 的子串

---

## 二十五、mcpcheckup 的工程文化总结

1. **三方对比测试**：实现 + frozen 旧版 + 独立 oracle，三方必须一致。不共享代码。
2. **差分测试验证"没有改变不该改变的"**：不只是测试新功能，还测试旧行为没变。
3. **边界用毫秒精度验证**：valid_until 边界精确到 1ms。
4. **安全边界用 canary 检查**：渲染输出不能泄漏输入内容。
5. **测试区分力自证**：测试会验证自己的区分力（"legacy 两条在 4 和 8 下的请求数必须不同"）。
6. **fixture 从生产事故中来**：每个负面 fixture 的 guardsAgainst 字段记录了它防止的真实 bug 和来源。
7. **零依赖哲学贯穿始终**：verifier 不需要 node_modules，甚至不需要 pnpm install。
8. **中英双语文档**：每个字段、每个 reason、每条注释都有中英文。
9. **16 个历史版本保留完整源码**：不是为了回滚——是为了差分测试。
10. **每条注释都是一段设计论证**：不是"这段代码做了什么"，而是"为什么这样做而不是那样做"。
