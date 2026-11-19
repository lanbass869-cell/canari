# Canari 从零到现在：完整说明

日期：2026-11-19。本文回答一个问题：**这个项目到底是什么，从 11-08 到今天做了哪些事，现在处于什么水平。**

所有数字都标了口径和快照日期。凡是没核实过的，文中直接写"没查"。

---

## 零、一句话

**Canari 是一个"AI agent 组件结论账本"**：每周扫描 npm / PyPI / MCP 官方 Registry / dsh.so 四个生态，
对每个组件产出一份**签名、可离线验证、带替代历史（supersession）的结论**，
并提供一个**安装前的 gate**，让别的程序可以按这些结论决定"放行 / 拦下 / 待审"。

它不是：不是一个扫描器（不自研检测引擎）、不是一个平台（没有账号/社区）、不是 LLM 产品、不是云服务。

---

## 一、起源与命名

- **2026-11-08** 项目开工，最初叫 `agentcheck`（第一个 commit `1e054f9` 仍在）
- 同日改名 **Canari**（金丝雀预警意象，commit `770654c`）
  - 命名前做过撞名扫描：Watchtower 撞 Docker 24.5k 星项目 + 博世 + fzn0x 三个同赛道项目且 PyPI 名被占；
    Canari 裸名被 Maltego 框架占，但该框架在威胁情报圈，与 agent 供应链无交集
  - schema 的 `_type` URI 保留 `agentcheck.dev` 未改——**schema 是真相源**，改名不改已签发的记录格式

## 二、四层结构（这是理解项目的地基）

| 层 | 做什么 | 代码位置 |
|---|---|---|
| **写入** | 扫四个生态，产出签名 attestation | `canari/baseline.py`（主扫描器） |
| **存档** | DSSE/Ed25519 信封 + in-toto Statement v1 + 链式 supersedes | `canari/signing.py`、`canari/attestation-v0.1.json` |
| **读取** | 离线验证、消费端 gate、漂移对比、身份聚类 | `verify_cli.py`、`gate.py`、`drift.py`、`identity.py` |
| **公开** | GitHub Pages 上的日志 / 浏览器验证器 / 周审计 | `docs/verify/`、`.github/workflows/` |

关键设计约束（多次被审计倒逼出来的）：

1. **签名覆盖的才是真的**——bundle 里 payload 存了两份，只有 `envelope.payload` 那份被 DSSE 签名覆盖。
   2026-11-11 的 BUG-102 就是消费方读了未签名的便利副本，等于签名完全失效
2. **不确定就说不知道**——五档 verdict：`pass` / `pass-with-findings` / `unsupported` / `fail` / `error`。
   "没跑到"必须是 `unsupported`，不许写成 `pass`
3. **不删历史**——纠正靠新记录 supersede 旧记录，旧记录永远留着

## 三、时间线：11 天，266 个 commit

| 日期 | commit | 干了什么 |
|---|---:|---|
| 11-08 | 38 | M0 骨架（schema + 验签 CLI）→ 改名 → M1 周管线（文件锁/状态 diff/限速重试/计划任务）→ M2 扩到 PyPI/MCP Registry/dsh.so → 两层扫描（深扫 300 个下载 tarball 算 sha256；元数据扫 22K 全量）→ 首批竞品调研 |
| 11-09 | 38 | 12 轮审计（BUG-1 到 BUG-62）→ 逐行拆解 3 个竞品（mcpcheckup / trustcheck / repo-forensics）写成 9 章教材 → 凭证检测（100 条语料，FP 0% / FN 4%）→ gate 策略引擎 → H1-H3 三个启发式（发布节奏/元数据异常/仿冒名）→ arXiv 论文初稿 |
| 11-10 | 22 | BUG-63~99，其中 BUG-97 是**数据丢失级**（凭证规则误判 sigstore 里的 commit SHA，把已验证的包从账本里抹掉）→ PyPI 首发 0.1.0 → 一键发布管线（build→签名→GitHub release→PyPI）→ 开放数据集 + MANIFEST（每文件 sha256） |
| 11-11 | 3 | BUG-100/101/102/103，其中 BUG-102 是**签名绕过级** |
| 11-12 | 4 | 换成真正的 in-toto Statement v1（之前是自定义 JSON 塞进 DSSE）→ wheel 内置快照 → 上 MCP 官方 Registry → HuggingFace dataset card |
| 11-13 | 6 | 全量扫描快照（5170 attestations / 1417 组件 / 1335 链）→ 0.1.2 / 0.1.3 |
| 11-14 | 9 | 外部扫描器接入（SARIF / bandit）→ fail-closed gate → Glama 索引 |
| 11-15 | 33 | **仅追加签名日志**（RFC 9162 Merkle + 包含证明 + 一致性证明）→ OpenTimestamps 锚定到比特币 → 浏览器零安装验证器 → c2sp.org 签名 notes（可被第三方 witness 联签）→ SCITT measurement capsule 第二实现 |
| 11-16 | 20 | 全量普查推翻自己的 84% 数字，正确值 94.78%（抽样伪影）→ server card 采纳率普查 → 语料依赖性研究（同一个包在不同语料下结论不同）→ 客户端侧普查 |
| 11-17 | 17 | 身份线开工：跨注册表同名不是同一个包 → `canari-mcp-gate`（启动前 gate 一个 MCP server）→ 包存在性审计首轮（274/22526 装不上） |
| 11-18 | 49 | 理论线总攻：读 21 篇全文 → **结论：没有理论空位** → 身份聚类 + 可离线验证的身份声明 → 发现并公开披露 false pass（66.6% 的 npm+PyPI 记录声称跑了没跑的检查）→ 端点监听前身 |
| 11-19 | 27 | 包存在性研究写成论文（4 页，FSE 2027 IVR）→ 上游 PR ×3 → **端点迟滞判定**（本文最后一节） |

**代码量**（2026-11-19 实测）：`canari/` 41 个模块 8,896 行；`tests/` 78 个文件 9,615 行；`scripts/` 2,919 行。
**测试注意**：测试代码比源码多，这是刻意的——这个项目的主要风险是"结论错了但没人发现"。

## 四、现在有什么（可核验的产物）

### 4.1 数据

| 产物 | 数字 | 口径 |
|---|---|---|
| 已签 attestation | **5,170**（dataset/，CC-BY-4.0） | 2026-11-13 快照 |
| 覆盖组件 | **1,417** 个 `(registry, name)` 对 / **1,415** 个去重名字 | dataset/，2026-11-13 快照；`canari-verify --chain dataset/attestations` 打印的是后者 |
| 本地完整 store | 6,887 bundles | 2026-11-19 实测 |
| 分生态（记录数） | pypi 2,051 / dsh 1,590 / npm 1,064 / mcp-registry 465 | 同上，合计 5,170 |
| verdict 分布 | pass 2,823 / pass-with-findings 1,803 / unsupported 480 / fail 56 / error 8 | 同上 |
| 文件清单 | 5,196 条每文件 sha256 | dataset/MANIFEST.json |

**怎么自己验**：`canari-verify --chain dataset/attestations` → 0 error。

浏览器里能验的是**另一件事**：<https://lanbass869-cell.github.io/canari/verify/> 验的是
仅追加日志的**包含证明包**（`canari-inclusion-bundle/v1`）——树头签名、条目在该树内、
后一个树头仍包含前一个。零安装、零上传、零网络。页面自己写明了它**不**证明记录内容为真。

### 4.2 命令（12 个入口，全部随 wheel 发布）

`canari-verify` / `canari-baseline` / `canari-gate` / `canari-drift` / `canari-mcp` / `canari-guard` /
`canari-mcp-gate` / `canari-registry-audit` / `canari-identity` / `canari-ingest-sarif` / `canari-log` /
`canari-monitor`

### 4.3 质量门（一条命令 = CI 的全部检查）

`python scripts/quality_gate.py` 依次跑：

1. lint（ruff，与 CI 同一套规则）
2. 测试 + 覆盖率 ≥ 85%
3. 论文数字与原始 JSON 一致（实测 **17 项检查**：数值溯源 + 拒绝已废弃值 + 同一量一致性 + 两条算术恒等式）
4. 变异测试 kill rate ≥ 90%

**2026-11-19 实测**：989 条测试通过，总覆盖率 **86.87%**，52 个变异体 kill rate **100%**。

## 五、已经踩过并公开的坑（这部分最能说明项目水平）

### 5.1 自己抓到自己四次"数字与产物漂移"

| 漂移 | 影响 | 怎么发现的 |
|---|---|---|
| PEP 440 归一化 | PyPI 32 条"版本缺失"里 7 条是误报 | 用真实安装复验时对不上 |
| npm 墓碑 | 68 条被归成"版本缺失"，实际是"整包消失" | 读 npm 真实响应发现 `time.unpublished` 是**对象**不是字符串 |
| 下载中位数 49 vs 49.5 | 论文数字往上取整 | 脚本抓出来的原始值是 49.5 |
| 总数 268 vs 267 | 摘要和结论写 268，正文写 267 | **检查器没抓到**（见下） |

第四次特别值得记：检查器只问"这个数字出现过吗"，所以 268 和 267 并存时它全绿。
现在改成三条：拒绝已废弃值（268/151/123）+ 同一量的所有表述必须收敛到一个值（跨行匹配）
+ 算术恒等式（`274-7==267`、`219+48==267`）。用"把 268 改回去"反向验证过：两条检查同时报红。

### 5.2 抽样伪影（最贵的一次教训）

2026-11-16 我报"84% 的 MCP registry 名字绑定到真实域名"。
全量普查（654 页 65,340 条）后正确值是 **94.78%**（reverse-DNS 命名空间内），`io.github.*` 因结构原因只有 0.06%。

根因：`/v0/servers` 按名字排序，前 800 条正好全是 `ac./ad./ae./ai.` 开头的 reverse-DNS 名。
**样本与目标总体系统性错配**，且我没做分组检查就下了全网结论。

修正已写回 `experiments/mcp_witness/README.md`（commit `5d258cd`）。

### 5.3 自己公开披露 false pass

2026-11-18 发现：verdict 的算法是 `"pass" if sha else "fail"`，**只要 tarball 下载成功就记 pass**，
不管里面那些启发式到底跑没跑。受影响记录：

| registry | 记录数 | 会被重分类 | 占比 |
|---|---:|---:|---:|
| pypi | 2,763 | 2,233 | **80.8%** |
| npm | 1,464 | 584 | **39.9%** |
| 合计 | 4,227 | 2,817 | **66.6%** |

**没有改写已签名记录**——一个会修改自己历史的日志毫无价值。
披露文档：`docs/DISCLOSURE-false-pass-20261118.md`，README 里也写了。

### 5.4 理论线：查完 21 篇全文，结论是"没有空位"

这是项目里最"不讨好"的一段。用户反复问"有没有新算法/新理论"，我的处理是去读全文然后**承认没有**。

六条候选逐一关闭：

| 候选 | 死因 |
|---|---|
| A 扣留攻击（withholding） | 承诺时机是 transparency log 的 folklore；实测我们日志滞后中位仅 2 条 |
| B 数据依赖下注 | E-value 的 optional continuation；事后挑选 = selective inference |
| C 去随机化 | 2008 年至今无人做（说明这条路没人认为值得） |
| D 竞争比 ε 间隙 | HZZ24 等顶尖团队在争 |
| E1 移动拜占庭 | Bo Pan / Potop-Butucaru 2025–2026 连续出紧界 |
| F 能力 vs 攻击 | 一行算术（比值对均匀缩放不变） |

自评结论写在 `docs/theory/why-no-gap.md`：**已做的那些叫"变装"，不叫新理论。**

其中 Proposition 1 第一版是**错的**，当天更正（`fbbb4b9` 错版 → `1291cb2` 修正版）。
错因：原表述"每个被准入组件引用 at most r 个根"→ 引用更少的组件会拉低总数，鸽笼平均推不出下界。
正确假设必须是 exactly r。修正后反而得到有价值的推论（盈余见证），但它也只是 Byzantine quorum 的 masking 性质，90 年代就有。

## 六、今天的增项：端点迟滞判定

### 6.1 为什么做

MCP Registry 全量快照（2026-11-18，66,509 条记录）里有 46,665 个 remote 端点。此前的做法（以及所有竞品的做法）是**单次探测**：
探一次，失败就算死。

但 registry 自己的 issue #1692 统计过：**52 个失败过的主机里，27 个（51.9%）后来又活了**。
该 issue 明确写道：阈值应该是"n 次连续失败、且按时间分隔"，不是一次。

**这要求提出来了，但没人实现。** 我做了。

### 6.2 规则（`canari/endpoint_history.py`，295 行）

| 规则 | 为什么 |
|---|---|
| 默认需 **2 次**确认 | 一次是采样，不是判决 |
| 确认之间至少隔 **6 小时** | 一分钟内连打 5 次 = 1 次观察，不是 5 次 |
| 成功**重置** streak | down/down/up = 今天是好的 |
| `auth`/`5xx`/`unsupported`/`partial` 记 neutral | "我们看不到"不等于"它坏了"，既不累加也不打断 |
| 两类失败**分开** | 答了但不是 MCP → 声明错；完全没答 → 可用性问题 |
| 混合类**不累加** | not_mcp + unreachable ≠ 2 次确认 |
| 既有成功又有失败但确认不足 → **FLAPPING** | 不许四舍五入成"坏了" |

### 6.3 实跑数据（2026-11-19，唯一一次有效采样）

`canari-monitor --limit 600 --max-probe 60`：

| 判定 | 数量 |
|---|---:|
| CONSISTENT | 38 |
| NEUTRAL_ONLY（401/5xx，无证据） | 20 |
| FLAPPING | 1 |
| INSUFFICIENT_EVIDENCE | 1 |
| **确认的 findings** | **0** |

两个非 CONSISTENT 的样本逐条核对过：

```
https://plantguide.ae/mcp
  07:14:23  alive        (10 分钟前那轮)
  07:24:23  unreachable  (TimeoutError)
→ FLAPPING，不进 findings

https://69ai.ai/mcp
  07:25:58  unreachable  (SSL EOF)
→ INSUFFICIENT_EVIDENCE，不进 findings
```

**单次判定会把这两个都报成"挂了"。** 这就是迟滞的价值，而且第一天就有真实样本证明它有效。

### 6.4 实跑抓到的真 bug

第一次跑 `--limit 600` 直接崩：`HTTP Error 422`。
原因：registry API 单页上限 100（limit=100 → 200，limit=101 → 422），而我一次要了 600。

**所有单测都用小 fixture，全部通过，测不出来。** 修成游标分页，并补了 3 条针对性测试：
150 条必须发 2 次请求且每页 ≤100、游标耗尽要停、服务器永远返游标要被 max_pages 停住。

### 6.5 已接进周任务

`run_weekly.py` 在 drift 之后调 `weekly_step`，计划任务 `CanariWeeklyScan`
（实测：Last Result 0，Next Run 2026-11-23 06:00）。

**注意**：一次运行永远不会确认任何事（需要两次间隔 6h+ 的观察）。
所以接下来几周报"0 findings"是机制在正常工作，不是没检测到。

## 七、上游贡献（PR 状态）

| PR | 内容 | CI | Review |
|---|---|---|---|
| [#1868](https://github.com/modelcontextprotocol/registry/pull/1868) | npm 墓碑分类错误（整包消失被当成版本缺失） | ✅ 全绿 | 0 |
| [#1869](https://github.com/modelcontextprotocol/registry/pull/1869) | 200 + 空 body 被当成成功取到公钥（跳过重试） | ✅ 全绿 | 0 |
| [#1861](https://github.com/modelcontextprotocol/registry/pull/1861) | 可选 `serverCard` 字段 | 旧提交红（正是 #1869 修的那个 flake） | 0 |

#1869 是我在审查 #1861 的 CI 失败时定位到的**上游真实生产 bug**，不是防御性小补丁。
确定性复现：服务端返回 200 空 body → `count=1 key="" err=<nil>`，一次都不重试。

另外给上游 issue 补了两次基于全量数据的更正：

- #1692：三条"永远解析不了"里有一条是**判错的**（braintrust 的 `{region}` 是已声明变量，`choices: ["", "-eu"]`）
- #1805：全量审计出 11 对大小写碰撞，并指出 `is_latest=true` 会留在已删除记录上，让部分唯一索引失效

## 八、论文（与项目的关系）

`docs/paper/main.tex` — 4 页（正文 3 + 参考文献 1），投 FSE 2027 IVR（截止 2027-02-12，APC USD 500/750）。

主题：**发出去了但装不上的注册表条目。**

| 指标 | 值 | 口径 |
|---|---|---|
| 真实安装失败率 | **39/40 = 97.5%**（Wilson 95% CI 87.1–99.6%） | 等间隔抽样，两组各 20 |
| 坏条目年龄 | 中位 **218 天**，最长 435 天，83.3% > 90 天 | 311 条目 join 快照 |
| 受影响包使用量 | 中位 **49.5 次/月**，47 个 ≥100 | 140 个包拿到下载统计 |
| 修正后分类 | **267** = 219 包消失 + 48 版本缺失（1.19%） | 274 首轮 → 两次更正后 |

**诚实的话**：论文里没有新算法、没有新理论。它是一篇测量论文。
审稿人问"这有什么理论贡献"时，答案是"没有，这是一个可复现的测量 + 一个廉价修复建议"。

## 九、外部指标（截至 2026-11-19）

| 指标 | 值 |
|---|---|
| GitHub star | **0** |
| fork | 0 |
| PyPI 最新版 | 0.1.4（2026-11-17），5 个版本 |
| PyPI 近 30 天下载 | **629**（pypistats，2026-11-19 查） |
| PyPI 近 7 天 | 493 |
| MCP 官方 Registry | 已收录（0.1.1，status=active） |
| Glama | 已索引，评级 B |
| 外部 review / 用户反馈 | **0** |

## 十、诚实的水平评估

### 做对了的

1. **工程纪律是真的**：989 条测试、87% 覆盖率、变异测试 100%、质量门一条命令
2. **敢公开自己的错误**：四次数字漂移、一次 66.6% 的 false pass、一次抽样伪影，全部写进 repo
3. **识别并拒绝自我欺骗**：理论线读 21 篇全文后承认"没有空位"，而不是硬造一个新理论
4. **实跑抓 bug**：分页 422 只有真跑才暴露
5. **上游贡献的是真 bug**：#1869 是别人 CI 挂掉的根因

### 没做到的

1. **零外部认可**：0 star、0 review、0 用户。所有"这个做得好"的判断都来自我自己
2. **没有技术壁垒**：迟滞判定是好设计，但任何人读一遍 #1692 都能写出来
3. **端点是唯一有效数据**：只有 1 天采样，任何比率都还不能报
4. **论文没有理论贡献**，且 APC 500–750 美元需要真金白银
5. **参数未经校准**："2 次、6 小时"是推出来的，不是测出来的

### 一句话定位

**这是一个工程质量高于市场验证阶段的测量型开源项目。**
说"垃圾"不公平（989 条测试、变异测试、公开披露都是真的）；说"牛逼"也不诚实（0 用户 0 review 0 star）。

它现在最像的东西是：**一份做得非常认真的技术作品集**，加上**一条可能长成真基础设施的路**（公开日志 + 迟滞判定），
但这条路能否成立，取决于接下来 3 周它能不能跑出真实的、非零的 findings。

## 十一、关键文件索引

```
E:\Temp\tbdig\canari\
  README.md                                  总入口（含诚实限制章节）
  docs/PROJECT-STORY-20261119.md             本文
  docs/DISCLOSURE-false-pass-20261118.md     66.6% false pass 的公开披露
  docs/theory/why-no-gap.md                  21 篇全文后的"没有空位"结论
  docs/paper/main.tex / main.pdf             4 页论文
  docs/verify/index.html                     浏览器零安装验证器（验的是日志包含证明，不是 attestation）
  docs/log/log.jsonl                         仅追加签名日志（49 条）
  dataset/                                   5,170 已签 attestation + MANIFEST
  canari/baseline.py                         主扫描器
  canari/endpoint_history.py                 迟滞判定核心（本题新增）
  canari/monitor_cli.py                      端点监听 CLI
  scripts/quality_gate.py                    lint→测试→覆盖率→论文数字→变异
  scripts/check_paper_numbers.py             论文数字溯源（17 项，实测）
  experiments/package_existence_repro/       论文全部原始数据
```

---

**本文所有数字均可用文中给出的命令或文件复核。若发现不一致，以产物为准，本文作废。**
