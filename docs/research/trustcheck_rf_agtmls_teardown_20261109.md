# 竞品深度拆解：trustcheck / repo-forensics / agtmls
## 逐函数逐行分析（2026-11-09）

> 三个项目，每一个都打开源码逐行读了。所有结论标注源码行号。

---

## 一、trustcheck — 安装门禁 + 恶意评分 + SLSA 分析

**77,528 行，52 个 Python 模块。PyPI 2.2.3，月下载 231 次。**

### 1.1 策略引擎（policy.py，664 行）— Canari install gate 的参考实现

**8 个内置策略配置**（L55-104）：

| 策略名 | require_provenance | metadata_only | vuln_mode | fail_on_severity | 用途 |
|---|---|---|---|---|---|
| default | none | yes | ignore | none | 宽松默认 |
| strict | all | no | any | high | 严格模式 |
| regulated | all | no | any | medium | 受监管行业 |
| startup | none | yes | fixable | high | 创业公司 |
| release-gate | all | no | fixable | medium | 发布门禁 |
| enterprise-private-index | none | yes | kev | high | 企业私有索引 |
| open-source-maintainer | none | yes | critical | high | 开源维护者 |
| internal-metadata | none | yes | ignore | none | 内部元数据 |

**evaluate_policy() 函数（L138-335）的检查顺序：**

1. `require_verified_provenance` — 如果策略要求 "all"：
   - 没有文件 → violation "verified_provenance_required" (high)
   - 有文件但未全部验证 → violation，带覆盖率数字

2. `require_expected_repository_match` — 如果策略要求匹配：
   - 没有 expected_repository → violation "expected_repository_required" (high)
   - 有但代码在 `expected_repository_invalid/mismatch/unverified` 中 → violation

3. `allowed_publisher_organizations` — 如果策略限制了发布者组织：
   - 没有已验证的 publisher → violation "publisher_organization_unverified" (high)
   - 有但不在允许列表中 → violation "publisher_organization_not_allowed" (high)，列出不匹配的身份

4. `vulnerability_mode` — 漏洞阻止模式（ignore/any/critical/kev/fixable）
   - 匹配的漏洞 → violation，列出前 5 个漏洞 ID

5. `fail_on_severity` — 严重度阈值（none/medium/high）
   - 风险标志中超过阈值的 → violation

6. `allow_metadata_only` — 如果不允许 metadata-only 但报告是 → violation

7. 插件系统 — 如果有 PluginManager，追加自定义检查

最终返回 `PolicyEvaluation`：passed = not violations, 带所有配置快照。

### 1.2 恶意包评分（malicious.py，1,569 行）

**分数阈值**（L203-208）：
| 等级 | 阈值 |
|---|---|
| low | ≥1 |
| elevated | ≥25 |
| high | ≥50 |
| critical | ≥75 |

**heuristic_score() 函数（L445-465）— 加权递减评分：**
```python
confidence_weight = {"low": 0.5, "medium": 0.75, "high": 1.0}
weighted = sorted(
    (finding.score * confidence_weight[finding.confidence]
     for finding in findings
     if finding.score > 0
     and finding.score >= thresholds.get(finding.code, ...)),
    reverse=True)
return min(100, round(sum(value * (0.65**index) for index, value in enumerate(weighted))))
```

**关键设计**：分数最高的 finding 贡献最大，但后续 finding 的贡献按 0.65^index 递减。一个 75 分的 critical 加一个 25 分的 elevated = 75 + 25*0.65 = 91 分（不到 100 上限）。**单条 critical 证据不足以满分，多条证据递减聚合。**

每个 heuristic rule 有元数据：`false_positive_rate`, `confidence`, `rule_version`, `score_threshold`。

### 1.3 SLSA 分析（provenance.py，699 行）

**analyze_slsa_provenance()（L42-90+）验证链：**

1. `buildDefinition` 和 `runDetails` 必须存在
2. `builder.id` 必须是 resource URI
3. `buildType` 在 GitHub workflow 列表中 → 但 publisher_kind 不是 GitHub → 拒绝（类型不匹配）
4. `builder.id` 的 hostname 不是 `github.com` → 拒绝
5. 解析 `resolvedDependencies` → 源码仓库 + commit
6. 解析 `externalParameters.workflow` → 仓库 URI + workflow 路径
7. 检查 workflow 路径是否与 publisher 的 workflow 匹配

**组织白名单匹配（L289-306）：**
- 支持 `organization` 或 `provider:organization` 格式
- 检查 `repository == organization` 或 `repository.startswith(organization + "/")`
- 例如 `github:expressjs` 匹配 `expressjs/express`

---

## 二、repo-forensics — 跨扫描器关联引擎

**165,170 行，287 个代码文件。580 unique re.compile + 451 rulepack rules。**

### 2.1 关联引擎（forensics_core.py，3,770 行）— correlate() 函数（L2512-3100+）

**设计哲学：** 单个扫描器的发现只是"能力存在"的证据。多个扫描器在**同一个文件**中发现互补能力时，才构成"攻击链"。

**19 条关联规则**（部分列出）：

| 规则 | 条件 | 严重度 | 说明 |
|---|---|---|---|
| Rule 1 | env access + network call（同文件，不同 finding） | critical/high | "Potential Data Exfiltration" |
| Rule 2 | encoding/obfuscation + code execution（同文件，不同 finding） | critical/high | "Obfuscated Code Execution" |
| Rule 3 | sensitive file read + network call | high | "Credential Theft Pattern" |
| Rule 19 | exec + network + credential（同文件，≥2 个不同 finding） | critical | "Lethal Trifecta" |
| Cross-file Rule 19 | exec + network + credential（跨文件） | critical | "Cross-File Lethal Trifecta" |

**Rule 19 "Lethal Trifecta" 详细分析（L2986-3095）：**

L2988-2989 注释：*"Per the SkillSafe ClawHavoc post-mortem, this pattern catches ~91% of malicious skills that evade the simpler Rule 1/Rule 3 checks."*

**三个原语的关键词集**（L3003-3039）——每个有 20-40 个精确匹配字符串：

- **exec**：`"code execution"`, `"eval("`, `"exec("`, `"os.system("`, `"subprocess.run"`, `"child_process.exec"`, `"command injection"`, `"shell=true"`, `"dangerous exec"` — 注意：移除了裸 `"exec"`, `"post"`, `"http"` 因为在合法 CI 脚本中误报
- **network**：`"exfiltration"`, `"reverse shell"`, `"/dev/tcp/"`, `"requests.post("`, `"urllib.request.urlopen("`, `"socket.connect("`, `"axios.post("`, `"httpx.post("`, `"webhook post"`, `"c2 callback"` — 移除了裸 `"http"`, `"network"` 因为 `"urllib HTTP request"` 和 `"postgres"` 误报
- **credential**：`".env read"`, `".ssh/id_"`, `".aws/credentials"`, `"id_rsa"`, `"github_token"`, `"npm_token"`, `"aws_secret_access_key"`, `"/etc/shadow"`, `"keyring.get_password("` — 移除了裸 `"password"`, `"secret"`, `"credential"` 因为 `".env.example"` 和 `"password field"` 误报

**误报防护机制**（L2991-3002 注释）：
- 每个原语必须来自**不同的 finding**（不能一个 finding 提到三个原语就触发）
- 至少 2 个不同的 finding 贡献者
- YARA 扫描器排除在关联之外（L2541）："a YARA match is a confirmed multi-string indicator, not a primitive capability"——把 YARA 的描述文字传回关联引擎会"从词汇事故中制造复合发现"

**compound_code_severity() 函数（L2661-2689）：**
- 如果文件是 .md/.markdown/.txt/.rst/.adoc → 直接 critical（"distant directives can still be executed together by an agent"）
- 如果是代码/二进制 → 要求**不同的 finding 在 25 行范围内**才升级到 critical（"Code capabilities far apart are a review lead, not a proven chain"）
- 用滑动窗口算法：排序所有 finding 的行号，双指针维护一个 25 行窗口，检查窗口内是否所有组都有贡献

**evidence_class 分层**（L2621-2632）：
- `direct` > `structural` > `inferred`
- 至少一个 direct leaf → 保持 critical
- 只有 inferred/structural → 上限为 HIGH

---

## 三、agtmls — 安装完整性验证（smoke-install-verify.py，152 行）

**152 行代码验证了 6 个安全属性。** 这是 Canari install gate 的直接参考。

### 3.1 六个安全属性

**属性 1：lockfile 覆盖完整性**（L46-58）
- 安装后 `.agtmls/manifest.json` 必须存在
- manifest.json 记录的 skills 列表必须等于实际安装的 skills 目录列表
- 每条记录必须有 `sha256:` 开头的 integrity 字段

**属性 2-3：篡改和删除检测**（L62-81）
- 干净安装 → `verify` 退出 0
- 修改一个 skill 的 SKILL.md → verify 退出 3 (EXIT_INTEGRITY_FAILURE) 且输出包含 "MODIFIED"
- 删除一个 skill → verify 输出包含 "MISSING"

**属性 4：未管理 skill 不删除**（L84-102）
- 手动创建一个 skill 目录 → verify 报告 "unmanaged"
- **退出码仍然是 0**（不是完整性失败）
- **不删除该 skill**："deleting what we did not install is not ours to do"

**属性 5：drift 检测**（L106-120）
- 修改 registry 中的一个 skill 文件
- 安装 → 退出 3 (EXIT_INTEGRITY_FAILURE)
- "a registry that no longer matches index.json cannot be installed, and the refusal installs nothing"

**属性 6：安装不落地**（文件末尾）
- 拒绝安装时，目标目录中没有写入任何文件
- 不是"先复制再报告"——是"拒绝就不做"

### 3.2 设计洞察

这 152 行代码定义了**安装完整性验证的完整语义**：

1. **lockfile 是真理的来源**：安装后每个文件都有 sha256 hash 记录在 lockfile 中
2. **三种失败模式**：MODIFIED（内容变了）、MISSING（文件没了）、UNMANAGED（不是我们装的）
3. **未管理 ≠ 失败**：第三方创建的文件不触发完整性错误，但必须报告
4. **drift 是安装时检测的**：不是安装后才发现，而是安装过程中就拒绝
5. **fail-don't-install**：拒绝安装时不写入任何内容

---

## 四、Canari 应该从这三个项目实现的具体功能

### 从 trustcheck 学：install gate 策略引擎

| 功能 | trustcheck 的实现 | Canari 的实现 |
|---|---|---|
| 策略配置 | PolicySettings dataclass + 8 个内置配置 | gate.py 加 PolicySettings |
| 漏洞模式 | ignore/any/critical/kev/fixable | verdict-based: pass/pass-with-findings/fail |
| 严重度阈值 | none/medium/high | 不需要（Canari 的 verdict 已包含严重度） |
| 组织白名单 | `github:expressjs` 格式 + 前缀匹配 | 可以加：`allowed_publishers: ["npm:user1", "pypi:org2"]` |
| 抑制列表 | VulnerabilitySuppression with expiry | 未来： false positive 的 suppression |
| 评分递减聚合 | 0.65^index weighting | 可以用于 scanner adapter 的多扫描器评分 |

### 从 repo-forensics 学：跨���描器关联

| 功能 | repo-forensics 的实现 | Canari 的实现 |
|---|---|---|
| 按文件分组 | by_file dict | scanner_adapter.py 返回的 findings 按 file 分组 |
| 互补能力检测 | env+network = exfil, encoding+exec = obfuscation | 两个 scanner 的 findings 在同一文件 = 更高严重度 |
| 置信度分层 | direct > structural > inferred | scanner 的 evidence_class 传播到 attestation |
| 25 行窗口 | compound_code_severity 滑动窗口 | 同一文件内两个 finding 的距离 |
| YARA 排除 | _CORRELATION_LEAF_EXCLUDED_SCANNERS | 某些 scanner 的输出不应参与关联 |

### 从 agtmls 学：安装完整性验证

| 功能 | agtmls 的实现 | Canari 的实现 |
|---|---|---|
| Lockfile | .agtmls/manifest.json with sha256 per skill | out/state.json 已有 sha256 per component |
| 篡改检测 | MODIFIED when content changes | verify_cli 可以对比 state.json 中的 sha256 |
| 删除检测 | MISSING when file deleted | 同上 |
| 未管理报告 | UNMANAGED for unknown files, 退出 0 | 新文件不触发失败但报告 |
| 安装不落地 | 拒绝时不写入 | install gate 拒绝时不下载 |

---

## 五、可复现性

所有三个项目的仓库在 `E:/Temp/canari_deep/repos/` 下。

关键源码文件：
- trustcheck: `src/trustcheck/policy.py` (664L), `malicious.py` (1,569L), `provenance.py` (699L)
- repo-forensics: `skills/repo-forensics/scripts/forensics_core.py` (3,770L), `pre_scan.py` (3,093L)
- agtmls: `scripts/smoke-install-verify.py` (152L), `scripts/_lib/signatures.py` (76L), `scripts/_lib/advisories.py` (119L)
