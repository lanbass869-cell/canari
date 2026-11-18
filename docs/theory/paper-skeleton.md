# 测量论文骨架（Canari）

定位：**测量 + 系统**论文。不含任何理论贡献声明（见 `docs/theory/why-no-gap.md`）。

## 候选标题

1. **A 404 in the Spec: How Agent-Component Registries Fail Their Own Contracts**
2. Measuring Trust Assumptions in the MCP Component Supply Chain
3. Names, Not Identities: Cross-Ecosystem Component Ambiguity in Agent Registries

推荐 1 或 3，取决于主贡献取舍。

## 一句话论点

agent 组件生态的**规范层与身份层同时失效**：规范强制字段指向不存在的 URL，而注册表里的
"名字"根本无法标识一个组件——两者都有实测数字，且都有可复现的产物。

## 贡献（每条都带口径，数字已在本仓可复现）

| # | 贡献 | 数字 | 证据 |
|---|---|---|---|
| C1 | 规范自伤：强制 `$schema` 指向 404，实现照抄 | **45/54** 张真卡照抄了一个 404 的 schema URL；机制上线第 41 天 | `experiments/server_card_adoption/` |
| C2 | 名字 ≠ 身份：跨生态同名不同组件 | 134 个裸名同时存在于 npm 与 PyPI；可解析的 101 个里 **61 同仓库 / 40 不同仓库 / 33 不同 owner** | `experiments/identity_conflict/` |
| C3 | 身份链接的覆盖率上限 | npm **188/200 (94.0%)**；PyPI **65/200 (32.5%)**，PEP 740 provenance 再补 15 → **80/200 (40.0%)** | 同上 + `pypi_provenance_gap.json` |
| C4 | 客户端零防御 | 9 个开源 MCP 客户端/SDK、**10,158 个源文件**，**没有一个**能识别"换了主机的同名服务器" | `experiments/client_census/` |
| C5 | 注册表里的事实失效 | **274/22,526 (1.22%)** 的包引用指向装不上的版本；676 条被腐化根影响的证据模型见 C6 的仿真（**须标为仿真**） | `docs/research/package-existence-audit-20261117.md` |
| C6 | （可选）腐化单源的追溯损伤 | 偏斜使用下 **44.9%**；补一个见证后 **0.03%**。**合成仿真，不是真实生态测量** | `experiments/online_admission/` |

**C6 若用，必须明确标为 simulation，且不得表述为理论贡献。** 否则审稿人会一击命中。

## 需要的图（4 张）

1. **规范自伤时间线**：卡出现 → 抄 404 的速率 → 修复
2. **同名碰撞分布**：134 个名字的 3 类桶（同仓/不同仓/无仓库）
3. **身份覆盖率对比**：npm 94% vs PyPI 32.5%→40%，带分母
4. **客户端防御矩阵**：9 个仓 × 5 类能力，全 0 的视觉呈现

## 目标场地

| 场地 | 适配 | 截止 |
|---|---|---|
| **FSE 2027 IVR**（4 页 + 1 页参考文献） | 最优：明写"评估结果非必需" | **2027-02-12 AoE** |
| MSR 2027 Data & Tool Showcase | 已过 | 2026-11-10（已错过） |
| 其它（可选） | 需先确认 track 接受 measurement | — |

## 审稿人最可能的三个攻击，与预案

1. **"你测的是没准备好的规范"**（Server Card 扩展自称 Experimental）
   → 把结论限定为"规范自伤的传播机制"，不声称"生态拒绝采用"。这个限制写进 Abstract。
2. **"样本太小"**（134 个名字 / 200 个候选）
   → 每条数字给分母与快照日期；把"这是上限证据、不是总体估计"写进 Limitations。
3. **"与 2609.34245 有什么区别"**
   → 明确：他们给认证器的理论；我们测生态里证据/身份的**实际可用性**（94% vs 40%）。
     两者互补，不竞争。

## 明确不写的东西

- 任何"新算法""新理论""定理"字样
- 任何未被本仓复现的数字
- 任何把仿真结果当作生态测量的表述
- 任何对竞品的贬损性比较

## 下一步（论文线）

1. 补第一次时间序列重探（12 月中）：889 个 gap host + 54 张卡的 `$schema`
2. 第二次重探（1 月中）
3. 写 4 页正文，跑一次内部 mock review（用 `paper-audit` / `nature-reviewer` 技能）
4. 2027-02-12 前投出
