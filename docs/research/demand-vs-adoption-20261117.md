# MCP 安全品类：需求是真的，但我们不在"能被信任"的那一档

（2026-11-17 实测。承接 `F-awesome-list-channel.md`：上一份结论是"渠道无效"，这一份修正为"渠道不是主因"。）

## 0. 结论先行

**品类是活的，需求是真的，但 adopt 的速度由"你背后站着谁"决定，不由渠道决定。**

| 账号类型 | n | star 中位数 | star 合计 |
|---|---|---|---|
| **机构账号**（NVIDIA / Tencent / Snyk / Cisco / Stacklok / Pantheon / splx-ai / Agent-Threat-Rule / getagentseal） | 9 | **1,119** | 43,628 |
| **个人账号** | 6 | 82.5 | 1,579 |
| 个人账号，**剔除唯一成功案例后** | 5 | **12.5** | 165 |

个人账号里唯一冲出来的 `affaan-m/agentshield`（1,414★ / 312 fork），拆开看**并不是"个人靠推广成功"**：

- 首页直接挂 **Claude Code Hackathon（Cerebral Valley × Anthropic, 2026-02）**
- README 自己写明：「Part of the **Everything Claude Code** ecosystem (**42K+ stars**)」——而 `affaan-m/ECC` 实测是 **304,751★**，同一个作者
- 分发形态是 CLI + GitHub Action + **GitHub App**（有真实应用商店入口）

也就是说：它靠的是**已有的 30 万星受众 + 官方赛事背书**，不是渠道。

## 1. 我在上一轮说错的地方

`F-awesome-list-channel.md` 里我推断"这个品类没人有用户"。**错了。** 实测前 15 个 MCP 安全工具：

| repo | owner 类型 | stars |
|---|---|---|
| NVIDIA/SkillSpector | Organization | 26,485 |
| Tencent/AI-Infra-Guard | Organization | 7,529 |
| snyk/agent-scan | Organization | 3,246 |
| stacklok/toolhive | Organization | 2,342 |
| affaan-m/agentshield | User | 1,414 |
| cisco-ai-defense/mcp-scanner | Organization | 1,119 |
| splx-ai/agentic-radar | Organization | 1,070 |
| Pantheon-Security/medusa | Organization | 1,022 |
| Agent-Threat-Rule/agent-threat-rules | Organization | 431 |
| getagentseal/agentseal | Organization | 384 |
| makalin/SecureMCP | User | 140 |
| sahiloj/MCPScan | User | 25 |
| bl014h/atpp | User | 0 |
| emmanuelorta/crawlcheck-core | User | 0 |
| lanbass869-cell/canari | User | 0 |

品类的天花板是 2.6 万星，中位 1,119。**不是没人要，是我们不在那一档。**

## 2. 需求有明确出处，而且是被官方邀请的

`modelcontextprotocol/registry#82`（open，31 条评论，assigned to goncalossilva，maintainer tadasant 开）：

> "we could have `server.json` submitters list out all the possible tools their server may ever invoke, fingerprint them, and store those fingerprints for MCP client consumption. **A third party vendor could scan and approve these fingerprints** as devoid of security risks, like tool poisoning attacks."

**这是维护者明确邀请第三方来做这件事。** 需求不是我们猜的，是官方点名的。

## 3. 但这个缺口已经被两组人占了，而且他们互相验证

同一线程里：

| 项目 | 做了什么 | 证据 |
|---|---|---|
| **CrawlCheck** | `mcp-tool-set-digest/1` 规范；带 `tool_set_digest` 的签名 lockfile；npm+PyPI 双 SDK；73/73 测试向量 | 评论 6861222120 |
| **HISTOR** | ~186,000 条公开观测；与 CrawlCheck 对 30 台服务器做交叉比对，29/29 摘要一致 | 评论 6872254022 |

两家都是个人账号、0 star，但**已经有书面的互操作规范和互相验证**。这是真实工程进展，不是喊口号。

## 4. 三个事实叠起来的真实含义

1. 品类有需求（天花板 2.6 万星）
2. 需求有官方点名（#82 维护者原话）
3. 但真正拿到用户的，是**机构背书**或**已有庞大受众**的项目

所以「推广」不是瓶颈。瓶颈是：**在一个"安全"品类里，用户买的是信任，而信任不能靠刷渠道获得。**

## 5. 唯一还剩的杠杆

既然不能造假背书，那就只能**不要求用户信任我们**：

| 做法 | 为什么可能有效 |
|---|---|
| **让验证离线可做**（已有：Ed25519 + Merkle + 浏览器验证器） | 用户不需要相信 Canari，只需相信数学。这是机构也给不了的 |
| **挂进用户已经在用的东西**（`canari-mcp-gate` 已实现） | 不要求用户"去找"我们 |
| **把工作推进上游代码**（PR #1861 已开） | 不要求用户"选"我们，直接成为流程的一部分 |

前两条我们做了，第三条在等 review。

## 6. 限制

- 15 个仓库是人工挑的"最可能相关"集合，不是全量普查；可能漏掉中小项目。
- owner type 是 GitHub 的账号类型，不等于"有没有商业背书"（个人账号也可能有公司支持）。
- star 是当前值，不是时间序列；无法排除"先有 star 后被收录"。
- 本节所有数字均为 2026-11-17 抓取。

## 7. 数据文件

`_owner.txt`（15 个仓库的 owner 类型/star/创建时间）、`_as.json`（AgentShield 详情与 README）。
