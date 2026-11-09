# trustcheck 拆解教材：安装信任决策的完整架构
## 36,103 行 Python，52 个模块，28 个数据类
## 逐模块逐行分析，作为 Canari install gate 和 scoring 的教材

---

## 第 1 章：数据模型（contract.py，704 行，31 个 Pydantic 类）

trustcheck 用 Pydantic BaseModel 定义了**信任报告的完整数据模型**。这不是简单的 verdict 字段——它是一个 30+ 层的嵌套结构。

### TrustReportPayload（L512-543）— 顶层报告

```python
class TrustReportPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")  # 未知字段直接拒绝
    project: str
    version: str
    package_url: str
    declared_dependencies: list[str]
    declared_repository_urls: list[str]
    expected_repository: str | None
    ownership: OwnershipPayload
    vulnerabilities: list[VulnerabilityRecordPayload]
    files: list[FileProvenancePayload]          # 每个文件的 provenance
    coverage: CoverageSummaryPayload             # 验证覆盖率
    publisher_trust: PublisherTrustSummaryPayload
    provenance_consistency: ProvenanceConsistencyPayload
    release_drift: ReleaseDriftSummaryPayload
    malicious_package: MaliciousPackageAssessmentPayload
    dependencies: list[DependencyInspectionPayload]
    risk_flags: list[RiskFlagPayload]
    recommendation: str                          # "metadata-only" | "verified" | ...
    policy: PolicyEvaluationPayload              # 策略评估结果
    diagnostics: ReportDiagnosticsPayload
    remediation: RemediationSummaryPayload       # 修复建议
```

**关键设计：`extra="forbid"`。** 任何未声明的字段直接被 Pydantic 拒绝。这与 Canari 的 schema 不同——Canari 的 JSON Schema 没有设置 `additionalProperties: false`（round 12 发现的 schema 缺陷）。

**31 个嵌套数据类的含义：**

| 数据类 | 含义 | Canari 对应 |
|---|---|---|
| FileProvenancePayload | 每个发行文件的签名/provenance/identity | 无（Canari 只有 package 级别） |
| SlsaProvenancePayload | SLSA buildDefinition + materials + issues | native_provenance 简化版 |
| MaliciousPackageAssessmentPayload | 恶意评分 + 规则命中 + 阈值 | 无（scanner adapter 输出） |
| DependencyInspectionPayload | 每个依赖的信任检查结果 | 无 |
| ReleaseDriftSummaryPayload | 仓库 URL 变化 / 版本跳跃 | 无（supersedes 链是另一维度）|
| OwnershipPayload | owner/organization/user 信息 | maintainers 列表 |
| RemediationSummaryPayload | 修复建议 + 补丁 | 无 |

**Canari 应该学**：verdict 不是单个字符串——它应该附带 trust report 的完整上下文（哪些文件验证了、哪些没有、恶意评分多少、依赖有多少问题）。

---

## 第 2 章：策略引擎（policy.py，664 行）

### 2.1 8 个内置策略配置

trustcheck 不是硬编码一个策略——它有 8 个**预定义场景**：

```python
BUILTIN_POLICIES = {
    "default":    PolicySettings(profile="default"),                              # 最宽松
    "strict":     PolicySettings(require_verified_provenance="all", ...),          # 最严格
    "regulated":  PolicySettings(require_verified_provenance="all", fail_on_severity="medium"),  # 金融/医疗
    "release-gate": PolicySettings(require_verified_provenance="all", require_expected_repository_match=True),  # CI/CD 门禁
    "startup":    PolicySettings(vulnerability_mode="fixable", fail_on_severity="high"),         # 快速迭代
    "enterprise-private-index": PolicySettings(require_expected_repository_match=True),          # 私有索引
    "open-source-maintainer": PolicySettings(vulnerability_mode="critical"),                     # 维护者
    "internal-metadata": PolicySettings(),                                                       # 内部
}
```

**Canari 的 gate.py 只有 4 个策略（default/strict/release-gate/lax），且维度只有 verdict 和 freshness。** trustcheck 的策略有 8 个可调维度。

### 2.2 evaluate_policy() 的检查链（L138-335）

执行顺序和优先级：

```
1. require_verified_provenance == "all"
   → 没有 files → violation "verified_provenance_required"
   → 有 files 但未全部验证 → violation，带覆盖率 "X/Y verified"

2. require_expected_repository_match
   → 没有 expected_repository → violation
   → 有但 code 在 {expected_repository_invalid, mismatch, unverified} → violation

3. allowed_publisher_organizations
   → 没有已验证 publisher → violation "publisher_organization_unverified"
   → 有但不在白名单 → violation "publisher_organization_not_allowed"
     （violation 消息列出不匹配的身份："kind:repository:workflow"）

4. vulnerability_mode
   → 匹配的漏洞 → violation，列前 5 个漏洞 ID

5. fail_on_severity
   → risk_flags 中超过阈值的 → violation

6. allow_metadata_only
   → 不允许但 recommendation == "metadata-only" → violation

7. PluginManager → 自定义插件检查

8. 组装 PolicyEvaluation → passed = not violations
```

**Canari 应该学**：gate decision 不应该只看 verdict——它应该看 verdict 上下文中的每个维度。

---

## 第 3 章：恶意包评分（malicious.py，1,569 行）

### 3.1 评分聚合公式

```python
def heuristic_score(findings, rule_thresholds=None) -> int:
    confidence_weight = {"low": 0.5, "medium": 0.75, "high": 1.0}
    weighted = sorted(
        (finding.score * confidence_weight[finding.confidence]
         for finding in findings
         if finding.score > 0 and finding.score >= thresholds.get(finding.code, ...)),
        reverse=True)
    return min(100, round(sum(value * (0.65**index) for index, value in enumerate(weighted))))
```

**数学含义**：如果有 3 个 finding，分数分别是 50, 30, 20（全部 high confidence）：
- 排序后：50, 30, 20
- 加权：50×1.0 + 30×0.65 + 20×0.4225 = 50 + 19.5 + 8.45 = 77.95 → 78 分

**设计意图**：最高分的 finding 主导评分，后续 finding 按指数递减。这防止了"大量低分 finding 累积成高分"的假阳性。

### 3.2 六种检测启发式

| 启发式 | 函数 | 分数 | 检测什么 |
|---|---|---|---|
| typosquatting | _typosquatting_findings | 45 (distance=1) / 32 (distance=2) | 包名与可信参考项目异常相似 |
| dependency confusion | _dependency_confusion_findings | varies | 包从多个索引拉取 |
| metadata anomaly | _metadata_anomaly_findings | 24-38 | 维护者/所有者/仓库 URL 变化 |
| release cadence | _release_cadence_findings | 18-22 | 发布频率异常 |
| native binary | native_binary_findings | varies | 二进制文件中的可疑结构 |
| source analysis | analyze_python_source | varies | AST 分析 |

### 3.3 Typosquatting 检测（L758-803）

```python
def _typosquatting_findings(project, trusted_names):
    candidate = canonicalize_name(project)
    compact_candidate = candidate.replace("-", "")
    for trusted in trusted_names:
        distance = _damerau_levenshtein(candidate, trusted)
        compact_distance = _damerau_levenshtein(compact_candidate, trusted.replace("-", ""))
        effective_distance = min(distance, compact_distance)
        maximum = max(len(compact_candidate), len(trusted.replace("-", "")), 1)
        similarity = 1.0 - effective_distance / maximum
        threshold = 1 if maximum < 8 else 2  # 短名字允许1个编辑距离，长名字允许2个
        if effective_distance <= threshold and similarity >= 0.72:
            # FLAG
```

**关键设计：**
- **Damerau-Levenshtein**（不是普通 Levenshtein）——额外支持相邻字符交换
- **compact name** — 去掉 `-` 后再比较（`left-pad` 和 `leftpad` 是同一个名字的变体）
- **自适应阈值** — 短名字（<8 字符）允许 1 个编辑距离，长名字允许 2 个。这比 Canari 的 SequenceMatcher 0.85 阈值精确得多
- **双重条件** — 距离 AND 相似度都必须满足

### 3.4 Metadata Anomaly 检测（L844-918）

**三类所有权变化**：

| 检测 | 分数 | 严重度 | 含义 |
|---|---|---|---|
| maintainer_identity_change | 24 | medium | author/author_email/maintainer/maintainer_email 变了 |
| project_ownership_change | 35 | high | owner/organization/user/username 变了 |
| declared_repository_change | 38 | high | 源码仓库 URL 变到完全不重叠的位置 |

**每一个都是 postmark-mcp 攻击的信号**——攻击者接管维护者账号后，这些字段会变化。

### 3.5 Release Cadence 检测（L921-1019）

**三种时间模式异常**：

| 检测 | 条件 | 分数 | 含义 |
|---|---|---|---|
| release_burst | 24 小时内 ≥5 个版本 | 20 | 可能在快速推送恶意更新 |
| release_after_dormancy | 距上次发布 ≥365 天 | 22 | 休眠项目突然更新（经典劫持信号）|
| release_cadence_acceleration | 当前间隔 ≤1h 且历史中位 ≥7 天 | 18 | 发布节奏突然加速 |

**Canari 应该学**：这些检测不需要执行代码——只需要 PyPI 的公开 metadata。Canari 可以在自己的扫描中加入这些启发式。

---

## 第 4 章：依赖解析与信任（resolver.py，1,504 行 + indexes.py，1,144 行）

trustcheck 不只是检查单个包——它解析整个依赖树，检查每个依赖的信任状态。

resolver.py 的核心：`resolve_dependencies()` 接收一个 lockfile（requirements.txt、poetry.lock 等），解析出每个依赖的名称+版本，然后对每个依赖调用 trustcheck 检查。

indexes.py 的核心：处理 PyPI 的包索引（simple index + JSON API），跟踪每个包的上传来源（哪个 index URL），检测 dependency confusion（同一个包名在私有索引和公共索引上都存在）。

---

## 第 5 章：修复建议（remediation.py，2,397 行）

trustcheck 不只是说"这个包有问题"——它生成具体的修复建议：

1. **plan_remediation()** — 分析漏洞和策略违规，计算修复方案（升级到哪个版本）
2. **validate_candidate()** — 验证修复版本是否满足所有约束（依赖兼容性、策略要求）
3. **prepare_remediation()** — 准备修复（修改 requirements.txt/pyproject.toml/poetry.lock）
4. **write_remediation_patch()** — 生成 diff patch
5. **create_pull_request()** — 自动创建 PR

**支持 5 种依赖文件格式**：requirements.txt、pyproject.toml（setuptools + poetry）、poetry.lock、pylock.toml。

---

## 第 6 章：导出系统（exports.py，2,479 行 + 7 个子模块）

trustcheck 可以将信任报告导出为 6 种格式：

| 格式 | 用途 | 文件 |
|---|---|---|
| SARIF | GitHub code-scanning | export_sarif.py |
| CycloneDX | SBOM | export_cyclonedx.py |
| SPDX | SBOM | export_spdx.py |
| OpenVEX | Vulnerability Exploitability eXchange | export_openvex.py |
| Markdown | 人读报告 | export_markdown.py |
| XML | 自定义 | export_xml.py |

**Canari 应该学**：签名 attestation 的 JSON 格式不够——消费者需要 SARIF（GitHub 集成）和 SBOM（供应链合规）。

---

## 第 7 章：Canari 应该实现的功能（按优先级）

### P0：直接可用的

| # | 功能 | trustcheck 参考 | Canari 实现 |
|---|---|---|---|
| 1 | **Release cadence 检测** | _release_cadence_findings L921-1019 | 在 baseline.py 加 L2.4_RELEASE_CADENCE check：从 PyPI JSON API 读 releases 时间线，检测 burst/dormancy/acceleration |
| 2 | **Metadata anomaly 检测** | _metadata_anomaly_findings L844-918 | 在 baseline.py 加 L2.5_METADATA_ANOMALY check：对比上次运行和本次运行的 maintainer/ownership/repository |
| 3 | **评分聚合公式** | heuristic_score L445-465, 0.65^index | 在 score.py 加 aggregate_heuristics() 函数 |

### P1：中期

| # | 功能 | trustcheck 参考 | Canari 实现 |
|---|---|---|---|
| 4 | **Typosquatting 检测** | _typosquatting_findings L758-803, Damerau-Levenshtein + compact name | 在 npm_enum.py 或独立模块中检测包名是否与可信项目相似 |
| 5 | **多策略 install gate** | policy.py BUILTIN_POLICIES 8 个场景 | gate.py 加 4 个策略：startup, regulated, release-gate, enterprise |
| 6 | **SARIF 导出** | export_sarif.py | 将 attestation 的 checks 导出为 SARIF 格式 |

### P2：远期

| # | 功能 | trustcheck 参考 | Canari 实现 |
|---|---|---|---|
| 7 | **依赖树信任传播** | resolver.py + indexes.py | 解析 lockfile，对每个依赖运行 trustcheck |
| 8 | **修复建议生成** | remediation.py plan_remediation | 基于检查结果生成修复建议 |
| 9 | **额外导出格式** | exports.py | CycloneDX SBOM, OpenVEX |
