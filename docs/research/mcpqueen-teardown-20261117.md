# MCP Queen 拆解（2026-11-17）

唯一拿到维护者互动的同位置竞品。全部数据实测，标注来源与抓取时间。

## 0. 一句话

**它是一个"做过产品化"的站点，不是仓库。** 免费 API + 可嵌 badge + 自己就是 MCP server + 定期生态报告 + 商用 pilot 漏斗，**而 GitHub 只有 1 star**。

## 1. 身份与规模（2026-11-17 抓取）

| 项 | 值 | 来源 |
|---|---|---|
| 站点 | mcpqueen.com | 首页 |
| 自述规模 | **18,849 servers indexed / 9,326 graded live** | 首页文案 |
| 全量探测周期 | ≈ **3 天**一轮 | `/api` 页 |
| GitHub 仓库 | `mcpqueen/mcpqueen` | 首页外链 |
| **仓库 star** | **1**（0 fork，created 2026-07-12，last push 2026-09-13，2 open issues） | GitHub API |
| 运营方账号 | `healthai-hq`，**User 类型**，2 个仓库 / 2 关注 | GitHub API |
| 背后实体 | 首页写 "An experiment by **Health AI** — the people behind Constat & Clarity" | 首页 |
| 自有服务器 | `com.healthai/clarity` 等在官方 registry 里活着（dogfooding） | 首页 + `/s/com.healthai/clarity` |

**注意**：它的 GitHub 账号是 User 不是 Organization，仓库只有 1 star。所以它在 `registry#1484` 拿到的互动**不是靠体量**，见第 4 节。

## 2. 机制清单（每一条都实测过）

| 机制 | 证据 |
|---|---|
| **免费公开 API，不要 key，CORS 开放** | `/api`：`GET /api/grades.json`（top 500）、`/api/history/{name}.json`（最近 200 次探测）、`/api/changes.json`（最近 100 次评分跃迁）、`/api/trust/{name}.json`；限流 60/min、500/day；**数据 CC BY 4.0**；每个响应自带 attribution/license/methodology 字段 |
| **可嵌 badge（自传播回路）** | `/badge/{name}.svg`，README 里贴 `[![MCP Queen grade](https://mcpqueen.com/badge/<registry-name>.svg)](https://mcpqueen.com/s/<registry-name>)`。badge 锚在 **Registry 身份**上而不是仓库 URL，所以仓库改名后 badge 链接不断 |
| **自己就是一个 MCP server** | 一行接入：`claude mcp add --transport http mcpqueen https://mcpqueen.com/mcp`；7 个工具、**无鉴权**；也给裸 JSON-RPC 的 curl 例子 |
| **定期生态报告（内容营销）** | `/reports/mcp-repository-mobility-2026-08`（2026-08-05 更新），标题是**给维护者的行动指南**（"仓库搬家后怎么保持用户和证据连着"），不是产品推销 |
| **把搜索当需求信号采集** | 原文："Registry searches are counted as aggregate demand signals." |
| **claim 纪律（每句都设边界）** | "An operational grade is not a security certification."；"Concern identifies a boundary requiring review, not a confirmed exploit."；"**Unaudited means there is insufficient evidence — never a pass.**"；"It does not claim that metadata inspection proves a server safe." |
| **商用漏斗** | 首页与多处挂 `/pilot`（"Free 7-day Scout + Guard stack check"） |
| **给机器读的入口** | `/llms.txt`、`/api`、`/for-agents` |

## 3. 我们 vs 它（2026-11-17）

| 机制 | MCP Queen | Canari |
|---|---|---|
| 免费公开 API | ✅ 4 个 REST 端点 + 限流 | ❌ 无 |
| MCP 端点、无鉴权 | ✅ `mcpqueen.com/mcp` 7 工具 | ⚠️ 有 `canari-mcp`（3 工具）但需要本地 store，线上无托管端点 |
| README badge | ✅ `/badge/<name>.svg` | ❌ 无 |
| 生态报告页 | ✅ `/reports/<slug>` | ⚠️ `docs/research/*.md` 存在但 **`/research/` 线上 404（无 index）** |
| claim 纪律 | ✅ 到处设边界 | ✅ 已有（"exact 是字符串关系，不证明同一组织"等） |
| 自证式 dogfooding | ✅ 自家服务器在 registry 里 | ⚠️ Canari 自己在 registry 里 |
| 商用漏斗 | ✅ `/pilot` | ❌ 无 |
| **GitHub star** | **1** | **0** |

我方 Pages 现状（实测）：`/verify/` 200、`/scan/` 200、`/log/` 200、**`/` 404**、**`/research/` 404**。Pages 根就是 `docs/`，文件级可达（`/research/papers/xxx.html` 200），只是目录没有 index。

## 4. 它在 #1484 靠什么拿到互动

不是体量，是**帖子的形式**：

1. **一个可复算的审计**：`38 / 398` 个高分级条目的 `repository.url` 指向改名或转移过的仓库（9.5%）
2. **附带全部 38 条的对照表**（server → 注册仓库 → 现状），任何人可以逐条核
3. **三条具体修法**（发布时解析 URL 并拒/警；定期重解析；暴露 `repository_verified_at`）
4. **主动说"happy to help"**
5. 并且明说 **0 个硬 404**——不夸大

对照我们在同仓库的 #1860：也是测量，但落点是"我们缺三样东西"，不是"这里有 38 条，这是它们的清单，你可以这样修"。

**差别是：审计格式 vs 提案格式。** 审计格式给维护者的是**可以直接派活的工作项**。

## 5. 诚实的反面结论

MCP Queen 把上面所有机制都做了——免费 API、badge、MCP 端点、报告、claim 纪律、dogfooding——**运营 4 个月，GitHub 1 star。**

所以：
- **社区 star 不是这个品类的成功指标。** 它的商业化路线是 B2B pilot（`/pilot`），不是社区。
- badge 的价值在于**被嵌**，而嵌的前提是维护者想要那个 badge。给一个没人知道的评分挂 badge，没有 pull。
- 这条对我们是坏消息也是好消息：坏消息是照抄不会带来 star；好消息是**这条路本来就不是 star 路线，可以不用 star 衡量**。

## 6. 可迁移性排序（按 杠杆 ÷ 成本）

| # | 机制 | 成本 | 我们能不能做 | 判断 |
|---|---|---|---|---|
| 1 | **审计格式发帖**（给工作项，不给提案） | 0 | ✅ 立刻 | **应该做**，且我们已经有料（#1860 的普查 + 卡片 0/54） |
| 2 | **把已有测量做成持久报告页** | 极低（静态站已有） | ✅ | **应该做**，`docs/research/` 只差一个 index |
| 3 | claim 纪律 | 0 | ✅ 已做 | 保持 |
| 4 | badge | 低 | ⚠️ 需要一个生成器 | **先不做**：没有 pull，容易变成自我感动 |
| 5 | 免费公开 API | 中（要托管） | ❌ 当前无托管 | 不做，除非先有需求 |
| 6 | 商用 pilot 漏斗 | 高 | ❌ 无商业主体 | 不做 |

## 7. 下一步（本报告的直接产出）

做 #1 和 #2：

- `docs/research/index.html`：把已有研究（含本轮三项测量）变成**可点开的持久页**，让每次发帖能引用一个 URL 而不是贴一大段
- 之后所有对外发帖改成**审计格式**：`N / M 有问题` + 完整清单 + 具体修法

不做 badge、不做 API、不做 pilot。
