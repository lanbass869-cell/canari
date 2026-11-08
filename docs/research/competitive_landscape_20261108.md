# Canari 竞品深度调研报告（2026-11-08）

> Codex 线独立调研，基于 GitHub API / PyPI / npm / dsh.so 实时数据。
> 目的：回答「Canari 的定位是否成立」「竞争格局是否变了」「该扫多少」三个问题。

---

## 一、竞品全景（按与 Canari 的重叠度分级）

### 1.1 直接竞争（重叠度 HIGH）

| 项目 | 星数 | 做什么 | 与 Canari 重叠 | 不重叠（Canari 空位） |
|---|---|---|---|---|
| **NVIDIA SkillSpector** | 24,820 | AI agent skill 安全扫描器，71 个漏洞模式，静态+LLM 双阶段 | 都做「agent 组件安全」 | 它是**单次扫描器**，结论不出工具；不做周监测、不做签名存档、不做跨宿主通报。**是 Canari 的上游扫描器而非竞品** |
| **Tencent AI-Infra-Guard** | 7,426 | 全栈 AI 红队平台：Agent Scan + Skills Scan + MCP Scan + 基础设施扫描 | 都做「agent 安全」 | 它是**红队平台**（找漏洞），不是**账本**（记录变化）。定位完全不同 |
| **Snyk Agent Scan** | 3,224 | MCP server + skill 安全扫描（原 mcp-scan） | 都做「agent 组件安全」 | 同 SkillSpector，**单次扫描器**，CLI 输出 schema 标 experimental。是上游不是竞品 |
| **Cisco MCP Scanner** | 1,113 | MCP server 安全扫描 | 都做「MCP 安全」 | 同上，单次扫描 |
| **VibeTensor Attestix** | 685 | AI agent 身份签名凭据（DID、ed25519、可移植治理证据） | **HIGH**——都做「签名凭据」 | 它做的是**agent 身份**（谁发的），不是**组件验真**（这个包安不安全）。不重叠，但用了同样的 DSSE/ed25519 技术栈 |
| **garagon Aguara** | 93 | AI agent + 供应链信任安全引擎（Go），扫 npm/PyPI/prompt injection | **HIGH**——都做「agent 供应链 + npm/PyPI」 | 它是**单次审计工具**（CI 里跑一次），不做周监测、不做签名存档、不做漂移对比。但覆盖面重叠最大 |

### 1.2 部分重叠（重叠度 MEDIUM）

| 项目 | 星数 | 做什么 | 关系 |
|---|---|---|---|
| **agentregistry-dev** | 538 | 集中式 AI agent registry | 它是**注册表**，不是**验真账本**。可以作为上游数据源 |
| **getagentseal agentseal** | 382 | agent 安全工具包（扫本机危险 skill/MCP 配置 + 监测供应链攻击） | 它做**本机侧检测**，Canari 做**生态侧账本** |
| **opena2a ai-trust** | 4 | 「AI 包的 VirusTotal」，查 npm/PyPI 包的信任分 | 它有**社区扫描贡献 + 信任分**，最接近 Canari 的理念。但 4 星 = 早期，且它**没有签名存档、没有周监测、没有历史** |
| **YugantM hvtracker** | 6 | 1.3K+ AI agent/MCP server 的信任排名 | 它做**信任排名**（OSSF Scorecard），不做安全验真凭据。**数据源可以互补** |

### 1.3 非竞争（上下游 / 基础设施）

| 项目 | 星数 | 做什么 | 关系 |
|---|---|---|---|
| semgrep/mcp | 687 | 用 Semgrep 扫代码漏洞的 MCP server | 上游工具 |
| pipelab pipelock | 987 | AI agent 防火墙（MCP 安全 + 出口控制） | 不同层（运行时防护 vs 供应链监测） |
| PrismorSec prismor | 480 | 运行时控制平面 | 不同层 |
| Brain0 brain0 | 294 | AI 写的代码的决策图 | 不同域 |

---

## 二、关键发现

### 2.1 「每周盯 + 签名存档 + 漂移对比」仍然是空白

搜索了 MCP weekly monitoring（13 结果）、MCP longitudinal（20 结果）、gent component drift（17 结果）、MCP cross-host notification（2 结果）——**没有找到任何项目在做「每周自动扫描 + 签名 attestation + supersession 链 + 漂移窗口量化」。**

最接近的是：
- **opena2a ai-trust**（4 星）：有社区扫描贡献 + 信任分，但没有签名、没有周监测、没有历史。是理想的信息源而非竞品
- **HVTracker**（6 星）：有 90 天历史数据（但只做信任排名，不做安全验真）
- **Attestix**（685 星）：有 DSSE 签名（但做 agent 身份，不做组件验真）

**结论：Canari 的定位「跨组件验真 + 签名存档 + 周监测 + 跨宿主通报��在 2026-11-08 仍然是空位。**

### 2.2 扫描器赛道的爆发意味着「上游采集器」策略更可行了

NVIDIA（24K 星）、腾讯（7K）、Snyk（3K）、Cisco（1K）全部在做单次扫描器。**它们不会做签名存档**——因为它们的商业模式是「用完我们的工具再付钱」。它们扫描完的结论消失在工具里。

Canari 应该做的：**把这些扫描器的输出灌进统一凭据格式**。sentinel 输出 SARIF JSON、Snyk 输出 experimental JSON、SkillSpector 输出 SARIF——全部可以变成 checks[] 里的一个条目。这正是方案 5.2 说的「可插拔扫描器」设计。

### 2.3 DSH 生态数据（实测）

| 指标 | 值 |
|---|---|
| 市场插件总数 | **10,183** |
| 独立作者 | **6,415** |
| 安装验证覆盖（抽样 30） | **87%**（26/30 有 L1-L5 结论） |
| 验证等级 | 全部 L5（smoke test passed） |
| 数据许可 | **CC-BY-4.0**，CORS 开放，append-only JSON |
| API 路径 | dsh.so/data/install/@author/name.json + dsh.so/artifact/@author/name-security.json |
| 头部作者 | uckkk（1,269 个插件）、xby-skill（112）、PerryLink（96） |

**注意**：10,183 个插件里 uckkk 一个作者占了 1,269 个（12.5%）——这是典型的**刷量/模板批量注册**信号。Canari 的「同作者异常检测」在这里直接有用。

### 2.4 npm + PyPI MCP 生态规模

| Registry | MCP 相关包数 | 来源 |
|---|---|---|
| npm keywords:mcp-server | 11,177 | npm search API |
| npm keywords:model-context-protocol | 43,191 | 同上（大量重叠） |
| npm 估算独立数 | **~3,000-5,000** | 三查询去重后 |
| PyPI mcp-server-* | **6,854** | Simple API 全量清单 |
| DSH 插件 | **10,183** | dsh.so market index |
| **总可枚举** | **~20,000+** | 跨 registry |

---

## 三、竞争格局变化 vs WorkBuddy 线三轮调研（2026-11-07）

### 新出现的竞争者（11-07 调研未覆盖）

| 项目 | 星数 | 为什么重要 |
|---|---|---|
| NVIDIA SkillSpector | 24,820 | NVIDIA 下场了。但它是扫描器不是账本。**实际上增强了 Canari 的价值**（多了一个上游扫描器可对接） |
| Tencent AI-Infra-Guard | 7,426 | 同上，红队平台 |
| Attestix | 685 | DSSE + agent identity + portable governance。**技术栈与 Canari 高度重叠**。需要仔细区分：它做身份，我们做组件验真 |
| Aguara | 93 | Go 语言，覆盖 npm/PyPI agent 安全审计。**最接近的直接竞品**，但没有签名、没有周监测、没有历史 |
| opena2a ai-trust | 4 | 「VirusTotal for AI」的理念与 Canari 最接近，但极早期（4 星） |

### 已确认的竞品死亡/转向

| 项目 | 状态 |
|---|---|
| Phylum | 被 Veracode 收购（第三轮调研已确认） |
| Suborbital | 被收购（平台模式死） |
| mcp-scan | 更名为 snyk-agent-scan（被 Snyk 收购） |

---

## 四、对 Canari 定位的修正建议

### 4.1 定位仍然成立，但需要更精确的边界

Canari **不是**又一个扫描器（这条赛道太挤了）。Canari 是：

**「agent 组件供应链的公证处」——不管结论是谁出的（sentinel/Snyk/SkillSpector/dsh.so），只要格式能解析，就灌进统一签名凭据，做漂移对比、历史追溯、跨宿主通报。**

### 4.2 不要全量扫描，做���层

| 层 | 覆盖 | 做什么 | 成本 |
|---|---|---|---|
| **深度层** | npm Top 200 + PyPI Top 100 | 下载 tarball + sha256 + 完整 attestation | 每周 ~30 min |
| **引用层** | 全量（npm ~5K + PyPI ~7K + DSH ~10K = ~22K） | 只记 registry 元数据（名称/版本/作者/maintainer 变更），不下载不扫 | API 调用，零带宽 |
| **DSH 引用** | 全量 10K | dsh.so 已有 L1-L5，直接引用灌入凭据 | 只拉 index.json + 逐包 JSON（CORS 开放） |

**总账本覆盖 ~22K 组件，深度验证 ~300/周。** 账本覆盖全生态，深度验证覆盖高价值目标。

### 4.3 与 Attestix 的区分（这是最需要说清楚的）

| | Attestix | Canari |
|---|---|---|
| 签什么 | **Agent 的身份**（我是谁、我代表谁） | **组件的安全结论**（这个包在时间 T 的扫描结果） |
| DSSE 用途 | DID 文档签名 | 扫描结论签名 |
| 消费者 | 宿主想知道「这个 agent 可信吗」 | 宿主想知道「这个插件安全吗」 |
| 重叠点 | 都用 ed25519 + DSSE + 离线验证 | |
| 合作可能 | Attestix 签 agent 身份 → Canari 签组件结论 → 同一个 agent 生态里两层信任 | |

### 4.4 PyPI 包名最终确认

- canari 被 Maltego 框架占（安全圈外不冲突）
- canari-mcp **FREE** ← 用这个
- mcp-drift FREE（备选）

---

## 五、推荐行动（按优先级）

1. **立即**：把 run_multi 改成两层模式（deep_scan + metadata_scan），npm 限 Top 200 深扫，PyPI/DSH 走引用层
2. **本周**：接入 dsh.so 的 10K 插件作为引用层数据（API 已探明，install/security JSON 都能拿到）
3. **下周**：接 MCP Registry API（一个 REST GET）+ PyPI metadata scan
4. **两周内**：实现同源失效传播的完整逻辑（retraction propagation 代码已有框架）
5. **M1 达标后**：NLnet 申请（逢单月 3 日截止，下一个窗口 2027-01-03）

---

*报告完 · 2026-11-08 · 数据来源：GitHub API（实时搜索）、npm Registry API、PyPI Simple API、dsh.so CDN、dsh.so data API。所有星数为查询时点数据。*
