# trustcheck 拆解教材：完整版
## 36,103 行 / 52 模块 / 28 数据类 / 逐行读
## 每个设计决策标注源码行号，每个模式说明安全理由

---

## 第 1 章：数据流架构

trustcheck 的数据流：

```
PyPI JSON API ─→ PypiClient ─→ TrustReport ─→ evaluate_policy ─→ GateDecision
                       │              │                            │
                       │              ├→ malicious_score            ├→ ALLOW
                       │              ├→ provenance                 ├→ BLOCK
                       │              ├→ typosquatting             └→ REVIEW
                       │              ├→ metadata_anomaly
                       │              └→ release_cadence
                       │
                       └→ cache (ContentAddressedCache)
```

**核心数据结构**：`TrustReportPayload`（contract.py L512-543）是一个 30+ 字段的 Pydantic
model，`extra="forbid"` —— 任何未声明字段直接拒绝。这比 Canari 的 JSON Schema 更严格：
Pydantic 在运行时强制，schema 只在验证时。

---

## 第 2 章：PyPI 客户端（pypi.py，795 行）

### 2.1 错误分类（L26-50 + L341-443）

trustcheck 将 PyPI API 错误分为**瞬态**（可重试）和**永久**（不可重试）两类：

```python
TRANSIENT_HTTP_STATUS_CODES = {408, 425, 429, 500, 502, 503, 504}
TRANSIENT_ERROR_TEXT = ("temporary failure", "timed out", "connection reset", ...)
PERMANENT_ERROR_TEXT = ("name or service not known", "certificate verify failed", ...)
```

每个错误是 `PypiClientError` 实例，携带 `transient` 标志 + `status_code` + `subcode`。

**重试逻辑（L241-294）：**
- `max_retries = 2`（总共最多 3 次尝试）
- `backoff_factor = 0.25`，指数退避：0.25s, 0.5s, 1.0s
- **永久错误立即抛出**，不重试（L290: `if not client_error.transient or attempt == self.max_retries: raise`）
- **瞬态错误继续重试**（L294: `self.sleep(backoff)`）

**URL 验证（L331-339）：** 只允许 HTTP(S)，其他 scheme 直接拒绝。

### 2.2 响应大小限制（L84-124）

```python
DEFAULT_MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024  # 128MB
DOWNLOAD_CHUNK_BYTES = 1024 * 1024  # 1MB chunks
```

读取响应时**双重检查**：
1. 先看 `Content-Length` 头（L87-93）：如果超过限制，直接拒绝
2. 逐 chunk 读取（L96-108）：如果实际读取超过限制，拒绝
3. 离线模式下的缓存文件也检查大小（L227）

### 2.3 内容寻址缓存（cache.py，156 行）

**SHA-256 验证的缓存系统：**

```python
class ContentAddressedCache:
    # 对象存储: root/objects/sha256/<digest>
    # 引用存储: root/refs/<namespace>/<key>
    # 读取时验证: hashlib.sha256(payload).hexdigest() == digest
    # 不匹配 → CacheIntegrityError
```

每次读取缓存都重新计算 SHA-256 并验证。缓存损坏不会静默返回错误数据——它会抛出异常。

**Canari 应该学**：verify_cli.py 可以缓存验证结果，加速重复验证。缓存需要完整性验证。

### 2.4 HTTP 连接池（L161 + L298-329）

`PypiClient` 支持 urllib3.PoolManager 作为可选的 HTTP 连接池。使用连接池时：
- `retries=False`（重试由外层控制）
- `preload_content=False`（流式读取）
- `response.release_conn()` 在 finally 中（确保连接归还池）

---

## 第 3 章：信任报告数据模型（contract.py，704 行）

31 个 Pydantic 类定义了信任报告的完整结构。核心关系：

```
TrustReportEnvelopePayload
  └── TrustReportPayload (report)
        ├── vulnerabilities: list[VulnerabilityRecordPayload]
        ├── files: list[FileProvenancePayload]
        │     └── publisher_identities: list[PublisherIdentityPayload]
        │     └── slsa_provenance: list[SlsaProvenancePayload]
        │           └── materials: list[ProvenanceMaterialPayload]
        │           └── issues: list[ProvenanceIssuePayload]
        ├── coverage: CoverageSummaryPayload
        ├── publisher_trust: PublisherTrustSummaryPayload
        ├── provenance_consistency: ProvenanceConsistencyPayload
        ├── release_drift: ReleaseDriftSummaryPayload
        ├── malicious_package: MaliciousPackageAssessmentPayload
        ├── dependencies: list[DependencyInspectionPayload]
        ├── dependency_summary: DependencySummaryPayload
        ├── risk_flags: list[RiskFlagPayload]
        ├── policy: PolicyEvaluationPayload
        ├���─ diagnostics: ReportDiagnosticsPayload
        └── remediation: RemediationSummaryPayload
```

**每个类都是 `BaseModel` + `extra="forbid"`**——Pydantic 在运行时强制字段白名单。

**FileProvenancePayload（L283-302）包含：**
- filename, sha256, size
- verified: bool（attestation 验证是否通过）
- publisher_identities: list[PublisherIdentityPayload]
- slsa_provenance: list[SlsaProvenancePayload]
- attestation_predicates: list[str]
- unstorable_fields: list[str]

**Canari 应该学**：一个 attestation 不应该只有一个 verdict——它应该有一个 `TrustReportPayload` 级别的详细报告，包含每个文件的验证状态、每个 publisher 的身份、每个依赖的状态。

---

## 第 4 章：信任状态差异（diff.py，918 行）

### 4.1 TrustDiffReport（L86-116）

```python
class TrustDiffReport:
    old_source: str
    new_source: str
    changes: list[TrustDiffChange]
    failures: list[dict]

    @property
    def max_severity(self) -> str:
        if self.failures: return "HIGH"
        if not self.changes: return "LOW"
        return max(change.severity for change in self.changes, key=...)
```

### 4.2 build_dependency_diff()（L119-160）

比较两个版本的依赖列表：

```python
for name in sorted(set(old_by_name) | set(new_by_name)):
    old = old_by_name.get(name)
    new = new_by_name.get(name)
    if old is None: changes.append(_change_for_added(new))
    if new is None: changes.append(_change_for_removed(old))
    if old.version != new.version or old_origin != new_origin:
        changes.append(TrustDiffChange(
            change_type="updated" if old.version != new.version else "source-changed",
            ...
        ))
```

**关键：`source-changed` 是一个独立的 change_type。** 版本没变但来源 index 变了也是变更。

### 4.3 should_fail_diff()（L455-461）

```python
def should_fail_diff(report: TrustDiffReport, *, fail_on_severity: str) -> bool:
    return report.max_severity severity >= fail_on_severity
```

### 4.4 六种 finding 来源

| finding 来源 | 检测什么 | 函数 |
|---|---|---|
| graph findings | 依赖图变化 | _graph_findings L522 |
| report findings | 信任报告变化 | _report_findings L563 |
| vulnerability | CVE 变化（新增/修复）| _vulnerability_findings L587 |
| malicious | 恶意评分变化 | _malicious_findings L608 |
| provenance | attestation 变化 | _provenance_findings L628 |
| identity | 发布者身份变化 | _identity_findings L653 |
| artifact | artifact hash 变化 | _artifact_findings L705 |

---

## 第 5 章：恶意包检测（malicious.py，1,569 行）

### 5.1 检测函数清单

| 函数 | 检测什么 | 分数 |
|---|---|---|
| _typosquatting_findings | 包名与可信项目 Damerau-Levenshtein ≤2 且相似度 ≥0.72 | 45/32 |
| _dependency_confusion_findings | 包从多个 index URL 可获取 | varies |
| _metadata_anomaly_findings | 维护者/所有者/仓库 URL 变化 | 24-38 |
| _release_cadence_findings | 发布频率异常（burst/dormancy/acceleration）| 18-22 |
| native_binary_findings | 二进制文件中的可疑结构 | varies |
| analyze_python_source | AST 分析（import/exec/eval）| varies |

### 5.2 Typosquatting 详细设计（L758-803）

```python
distance = _damerau_levenshtein(candidate, trusted)           # 正常编辑距离
compact_distance = _damerau_levenshtein(compact, trusted.replace("-",""))  # 去-后
effective_distance = min(distance, compact_distance)          # 取较小的
maximum = max(len(compact_candidate), len(trusted.replace("-","")), 1)
similarity = 1.0 - effective_distance / maximum
threshold = 1 if maximum < 8 else 2                           # 短名字更严格
if effective_distance <= threshold and similarity >= 0.72:
    score = 45 if distance == 1 else 32
```

**Damerau-Levenshtein 是自定义实现（L1367-1397）**——额外支持相邻字符交换（transposition）。

**_name_relation()（L1400-1413）** 分类相似类型：
- `separator substitution`：去掉 `-` 后相同
- `adjacent transposition or substitution`：等长，2 个相邻位置不同
- `character insertion or deletion`：长度不同
- `character substitution`：等长，非相邻位置不同

### 5.3 Metadata Anomaly 检测（L844-918）

三类所有权变化检测，**全部需要上一次 release 的 metadata 作为参照**：

| 检测代码 | 分数 | 严重度 | 条件 |
|---|---|---|---|
| maintainer_identity_change | 24 | medium | 当前维护者集合 != 上次维护者集合 |
| project_ownership_change | 35 | high | 当前所有者集合 != 上次所有者集合 |
| declared_repository_change | 38 | high | 当前仓库 URL 集合与上次完全不重叠 |

**declared_repository_change 最关键**（38 分，high confidence）——postmark-mcp 攻击就是改了仓库 URL。

### 5.4 Release Cadence 检测（L921-1019）

| 检测 | 分数 | 条件 |
|---|---|---|
| release_burst | 20 | 24h 内 ≥5 个版本 |
| release_after_dormancy | 22 | 距上次发布 ≥365 天 |
| release_cadence_acceleration | 18 | 当前间隔 ≤1h 且历史中位数 ≥7 天 |

**release_cadence_acceleration 的数学：** `latest_interval <= 60*60` (1h) 且 `baseline = statistics.median(intervals[:-1]) >= 7*24*60*60` (7 天)。**中位数而不是平均值**——防止少数快速发布拉低中位数。

---

## 第 6 章：依赖解析沙箱（resolver.py，1,504 行）

### 6.1 六种沙箱模式（L38）

```python
SANDBOX_MODES = ("off", "warn", "auto", "container", "bubblewrap", "strict")
```

| 模式 | 行为 |
|---|---|
| off | 不隔离，直接运行 pip |
| warn | 运行但打印警告 |
| auto | 自动检测可用隔离方式 |
| container | Docker 容器隔离 |
| bubblewrap | Linux bubblewrap namespace 隔离 |
| strict | 最严格：container 或 bubblewrap，无回退 |

### 6.2 Bubblewrap 隔离（L1000-1020）

```python
def _bubblewrap_readonly_binds(workspace, python_executable):
    candidates = [Path("/usr"), Path("/bin"), Path("/lib"), Path("/lib64"),
                  Path("/etc"), Path(sys.base_prefix), Path(sys.prefix),
                  python_executable.parent]
    # 去重：如果已选择的路径包含 candidate，跳过
    # 按路径长度排序（最短的先选，这样子目录不会重复绑定）
```

bubblewrap 只读绑定系统路径（/usr, /bin, /lib, /etc），写入只允许 workspace 目录。pip install 运行在隔离的 namespace 中，无法访问系统其他部分。

### 6.3 Dependency Confusion 检测（L192-229）

```python
def check_dependency_confusion(self, projects, additional_indexes=()):
    if len(index_urls) < 2: return ()  # 只有一个 index 就没有混淆风险
    findings = index_client.find_dependency_confusion(projects, index_urls)
    if findings and not self.allow_dependency_confusion:
        raise ResolutionError("dependency-confusion risk detected...")
```

**原理**：同一个包名如果同时在私有 index 和公共 PyPI 上存在，pip 可能从错误的 index 安装。trustcheck 检查每个包在所有配置的 index 上的可用版本，如果发现不一致就拒绝。

---

## 第 7 章：修复系统（remediation.py，2,397 行）

### 7.1 修复流程

```
plan_remediation()     → 分析漏洞 + 策略违规 → 计算修复方案
validate_candidate()   → 验证修复版本是否满足所有约束
prepare_remediation()  → 修改 requirements.txt / pyproject.toml / poetry.lock
apply_prepared_remediation() → 运行 pip install 更新
write_remediation_patch()    → 生成 diff
create_pull_request()  → 自动创建 GitHub PR
```

### 7.2 支持 5 种依赖文件格式

| 格式 | 编辑函数 |
|---|---|
| requirements.txt | _edit_requirements_file (L1552) |
| pyproject.toml (setuptools) | _edit_pyproject (L1655) |
| pyproject.toml (poetry) | _edit_poetry_table (L1825) |
| poetry.lock | _run_native_locker (poetry lock) |
| pylock.toml | _write_pylock (L1919) |

### 7.3 修复后验证（L2233-2299）

修复后重新运行 pip install 并验证每个文件的 SHA-256 是否与 lockfile 一致：
```python
def _validate_lockfile_hashes(...):
    # 对每个 artifact 计算实际 SHA-256
    # 与 lockfile 中声明的 hash 比对
    # 不匹配 → raise
```

---

## 第 8 章：导出系统（exports.py，2,479 行）

6 种导出格式，每种是独立函数：

| 格式 | 函数 | 行数 | 用途 |
|---|---|---|---|
| SARIF | _sarif_document | ~300 | GitHub code-scanning |
| CycloneDX JSON | _cyclonedx_document | ~120 | SBOM (JSON) |
| CycloneDX XML | _cyclonedx_xml | ~190 | SBOM (XML) |
| SPDX 2.x | _spdx_document | ~100 | SBOM |
| SPDX 3.0 | _spdx3_document | ~130 | SBOM (new spec) |
| OpenVEX | _openvex_document | ~85 | Vulnerability Exploitability eXchange |
| Markdown | _markdown_document | ~160 | 人读报告 |

每种格式都包含完整的 trust 信息：漏洞、恶意评分、provenance、publisher identity、策略评估结果。

---

## 第 9 章：Canari 应该实现的功能

### 从 trustcheck 学的（按 Canari 需求排序）

| # | 功能 | trustcheck 的实现 | Canari 改进 | 优先级 |
|---|---|---|---|---|
| 1 | **Release cadence 检测** | _release_cadence_findings L921-1019 | baseline.py 加 L2.4 check | P0 |
| 2 | **Metadata anomaly** | _metadata_anomaly_findings L844-918 | baseline.py 加 L2.5 check（对比上次 metadata） | P0 |
| 3 | **评分聚合公式** | heuristic_score L445-465 (0.65^index) | score.py 加 aggregate function | P0 |
| 4 | **错误分类（transient vs permanent）** | PypiClientError + TRANSIENT_HTTP_STATUS_CODES | npm_enum.py 加错误分类 | P1 |
| 5 | **响应大小限制** | _read_bounded_response L84-109 | baseline.py 下载加大小限制 | P1 |
| 6 | **Damerau-Levenshtein typosquatting** | _typosquatting_findings L758-803 | 独立检测模块 | P1 |
| 7 | **内容寻址缓存** | cache.py ContentAddressedCache | verify_cli.py 加缓存 | P1 |
| 8 | **策略引擎多维度** | policy.py 8 策略 × 8 维度 | gate.py 加更多策略维度 | P1 |
| 9 | **SARIF 导出** | exports.py _sarif_document | attestation checks → SARIF | P2 |
| 10 | **修复建议** | remediation.py plan_remediation | 基于检查结果生成修复 | P2 |

### 不需要学的

| 功能 | 原因 |
|---|---|
| 依赖树解析 | Canari 不做 dependency resolution |
| 沙箱（container/bubblewrap） | Canari 不执行代码 |
| PR 自动创建 | 超出 scope |
| PyPI attestation 上传 | Canari 是消费者不是发布者 |
