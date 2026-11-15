# 深度调研报告：无客户前提下如何建立技术壁垒

日期：2026-11-15
取证方式：GitHub 官方接口逐文件读源码与草案；子 agent 完成 MCP registry Go 源码审计；不接受二手转述。

## 0. 结论

**能做，但壁垒不在"加密算法难"，而在"离线可验证 + 唯一运营者 + 时间语料 + 一致性证明"。**
调研中最硬的一条：MCP 官方注册表在代码层面**没有任何定时重新校验**，且**完全不校验签名**；最接近我们的竞品 Anchor 的验证路径**必须调用 cosign、必须联网**。这两条同时成立，说明"离线可验证的追加日志"这个位置是真的空着。

## 1. 六条硬事实（附取证位置）

### 事实一：官方注册表没有任何定时重校验（代码级）

审计 `modelcontextprotocol/registry` main@`115f852`：
- 全 `internal/`、`cmd/` 非测试代码中无 `time.NewTicker` / `time.Tick` / cron；`cmd/registry/main.go:145` 只有 HTTP server goroutine 与信号处理。
- `.github/workflows/sync-schema.yml:5-7` 的每日 cron 被注释（`TODO: Add daily schedule later`）。
- 部署里的 CronJob 只有数据库备份与 staging restore。
- 结论：**条目发布时校验一次，之后除非发布者编辑，永不复查**。这与 issue #1715 的结论一致，且该结论在代码上仍然成立。

### 事实二：注册表完全不校验签名，且有一个可放任意 JSON 的扩展位

- `npm.go` 只解码 `mcpName` 一个字段；`pypi.go` 只解码 `info.description`。npm provenance、PyPI 签名、OCI cosign、MCPB 签名一律不读。
- `pkg/api/v0/types.go` 的 `ServerMeta` 只有一个合法子键 `io.modelcontextprotocol.registry/publisher-provided`，类型是 `map[string]interface{}`。
- 实测：该子键下任意嵌套 JSON 都能通过 Huma 校验；其它 key 一律 422。
- 约束：4KB 上限**只在发布路径**检查（`validators.go` `validatePublisherExtensions`），编辑路径不检查。
- 结论：**这就是放"第三方签名验证结论"的现成插槽**，无需改数据库（整份 `ServerJSON` 存 JSONB）。

### 事实三：MCPB 只查 URL 可达，不校验文件内容哈希

`validators/registries/mcpb.go`：`fileSha256` 只校验格式（64 位 hex），随后对 URL 发 HEAD，接受 200 或 3xx；**不下载、不比对哈希**；`serverName` 参数完全未使用，所以 MCPB 没有 npm/PyPI 那种所有权校验。

### 事实四：最接近的竞品 Anchor 的验证路径必须联网

代码级证据（`intelligent-ears/Anchor` @`1b8c7e0`）：
- `internal/signer/signer.go` `AttestStatement()`：`exec.LookPath("cosign")`，shell 调 `cosign attest-blob`，走 Sigstore 无密钥 OIDC 流程。
- `VerifyBundle()`：shell 调 `cosign verify-blob-attestation --certificate-identity-regexp .* --certificate-oidc-issuer-regexp .*`，注释明确它验证"Fulcio 证书链 + Rekor 包含证明"。
- 该包内**没有任何自建 Merkle 树**；日志能力全部外包给 Rekor。
- README 的 Known limitations 自述：不支持基于密钥的签名、不支持自建日志、**不支持离线/气隙验证**；且记录了一个硬伤——Rekor 的 dsse 条目只存哈希不存载荷，所以"仅靠公开日志重建历史"走不通。
- 结论：**它的可信度依赖 Sigstore 的在线基础设施，且没有树头/一致性证明概念**。

### 事实五：SCITT 已有标准框架，但没有 AI 组件的位置

IETF SCITT 工作组 7 个仓库：架构草案、SCRAPI（Transparency Service REST API）、CCF 收据 profile、use-cases、examples，2026-10 仍有提交。
- 有架构、有 API、有收据格式。
- **没有 AI/ML/MCP 相关 profile**；`draft-ietf-scitt-software-use-cases` 停在 2023 年且无人维护。
- 结论：标准位空着，但框架已定，我们应当**对齐**而不是另造。

### 事实六：组件级 attestation 的标准位其实已被 CycloneDX 占了

CycloneDX 1.6/1.7 schema 里已有 `declarations` 块，含 `assessors` / `attestations` / `claims` / `evidence`，并有 `valid-attestation-1.6.json`、`1.7` 的合规样例。
- 说明"第三方对组件下结论"这件事，标准组织已经建模。
- 结论：**不要再发明 record 格式**；应把自己的记录表达成 CycloneDX declarations，或至少可双向转换。

## 2. 竞争格局对比

| 项目 | 做什么 | 规模 | 我们的相对位置 |
|---|---|---|---|
| NVIDIA SkillSpector | 技能扫描 + 签名 + 自有目录 | 25945★ | 检测深度远超我们；但它只覆盖 NVIDIA 自家目录 |
| 腾讯 AI-Infra-Guard | 红队平台（含 MCP/skill 扫描） | 7502★ | 同上，平台化 |
| Snyk agent-scan | 扫描器 | 3239★ | 同上 |
| Anchor | MCP 工具 schema 透明日志（Rekor） | 12★ | 最近的竞品；**不能离线验证、无树头** |
| smallprint / HISTOR / CrawlCheck | 每日工具指纹 + 哈希链 + 签名 | 数十星 | 做工具面；小print 已有 Ed25519 + 哈希链 |
| mcpcost / ProtocolProbe | 每日本地证据导出 | 未公开星数 | 只发布数据，**不签名** |
| chainloop | 企业级 attestation（Sigstore/in-toto） | 614★ | 企业向、重部署 |
| IETF SCITT | 标准 | — | **无 AI profile** |
| CycloneDX | BOM + declarations 标准 | 578★ | 已有 attestation 建模 |

## 3. 三条候选路径的评估

### 路径 A：做一个更深的扫描器
- 技术难度：中高（规则、AST、污点分析）。
- 被替代风险：**极高**（NVIDIA/腾讯/Snyk 已占）。
- 无客户也能牛吗：不能，扫描器靠覆盖率和误报率，需要真实语料。
- 判定：**不做**。

### 路径 B：做 AI 组件的 SCITT profile（标准位）
- 技术难度：低（写作 + 对齐），但需要持续参与标准讨论。
- 被替代风险：中（若被大厂抢先则归零）。
- 无客户也能牛吗：能，标准文本本身就是产出。
- 判定：**做，但作为第二条腿**。风险是"写了没人理"。

### 路径 C：离线可验证的追加日志（唯一运营者 + 时间语料）
- 技术难度：中（Merkle 包含/一致性证明实现正确性）。
- 被替代风险：低到中（Anchor 受制 Rekor 条目类型；换实现成本高）。
- 无客户也能牛吗：能，且可自证——树头序列、测试向量、第三方留档。
- 判定：**主攻**。

## 4. 推荐方案（主攻 C，辅以 B）

### 4.1 核心：一个"只增不改"的证据日志

- 每条记录 = 一次事实（今日某数据源的发布、或某组件的一次结论）。
- 组织成 RFC 9162 风格的 Merkle 树：叶子哈希 `0x00 || data`，内部节点 `0x01 || left || right`。
- 每日产出签名树头（tree head）：size + root hash + timestamp。
- 提供两类证明：
  - **包含证明**：某条记录确实在这棵树里；
  - **一致性证明**：新树头是老树头的严格扩展（历史未被改写）。
- 验证只需：公钥 + 记录包 + 证明，**全程离线**。

### 4.2 为什么这能立住（逐条对应事实）

- 事实一（注册表不重校验）→ 我们的每日追加正好补上"时间维度"，且不需要注册表配合。
- 事实二（有 4KB 扩展插槽）→ 我们的签名结论可以原样塞进 `publisher-provided`，零改动接入。
- 事实四（Anchor 必须联网）→ 离线验证是我们唯一的硬差异。
- 事实五/六（标准已定，无 AI profile）→ 我们只做 profile 与实现，不另造标准。
- 事实三（MCPB 不校验内容哈希）→ 我们可以是第一个真的把 `fileSha256` 与内容比对并签名记录的一方。

### 4.3 具体交付物

1. `canari/merkle.py`：叶子/节点域分离、包含证明、一致性证明、树头签名。
2. `canari/logstore.py`：只追加存储 + 每日封树 + 树头历史。
3. `canari/verify_offline.py`：只依赖公钥与记录包的三步验证器。
4. `docs/spec/`：记录格式（对齐 CycloneDX declarations）+ 测试向量（JSON）。
5. 每日 cron：拉取外部证据 → 存证 → 追加 → 出树头 → 公开。

### 4.4 无客户也能证明自己（自证清单）

- 树头历史公开可查，第 N 天的树头无法事后伪造。
- 反向测试：篡改任一叶、用缩短的树头冒充，验证器必须拒绝。
- 跨实现：第二套独立实现跑同一组向量，根哈希逐字节一致。
- 外部留档：请数据源维护者保存我们的树头，形成 gossip 起点。

## 5. 反证条件（预先写死）

1. 若 SCITT 半年内推出 AI/ML profile 且由大厂主导 → 路径 B 归零。
2. 若 Anchor 改成自建日志并支持离线 → 路径 C 的差异消失。
3. 若两家每日证据源停更 → 语料断流。
4. 若我们连续 30 天无法追加 → 时间壁垒自己断掉。

## 6. 第一周交付

1. Merkle 核心 + 对抗性测试（空树、单叶、奇数提升、路径篡改、非前缀树头）。
2. 测试向量 JSON（供第二实现对齐）。
3. 离线验证器原型。
4. 每日追加脚本 + 第一份签名树头。