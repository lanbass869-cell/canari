# 选定的子问题（2026-11-19 定案）

## 一、选的是什么

> **规范里一个强制字段指向了不存在的 URL——它会不会传播，以及它到底会不会伤人？**

具体对象：MCP 的 SEP-2127 Server Cards。规范要求卡片用 `$schema` 声明自己的 schema，
而规范给出的那个 URL **404**。

## 二、为什么是它（而不是别的）

| 备选 | 不选的理由 |
|---|---|
| 扣留攻击 / 数据依赖下注 | 已关闭：folklore / E-value 理论覆盖 |
| 在线准入竞争比 | 顶尖团队在抢 |
| 移动拜占庭 | 活跃团队已有紧界 |
| 能力 vs 攻击的可识别性 | 已关闭：一行算术 |
| 跨生态同名碰撞 | 可测，但缺"所以呢"——没有受影响的证明 |
| **Server Card `$schema`** | **已测到硬事实、有明确危害假设、可三周做完、有 venue** |

关键差别：前六个候选要么被占要么平凡；**这一条我们手里已有别人没有的数据**，
而且它问的是一个**经验软件工程问题**（规范缺陷的传播），不是理论问题。

## 三、已核实的事实（2026-11-19 现场验证）

| 事实 | 数字 | 验证方式 |
|---|---|---|
| 真实卡片总数 | 54 | `experiments/server_card_adoption/POST.md` 的普查 |
| 引用 `…/schemas/v1/server-card.schema.json` | **45** | 同上 |
| 引用 `…/schemas/mcp-server-card/v1.json` | 1 | 同上 |
| 引用可解析但**错误**的 `…/2025-12-11/server.schema.json` | 5 | 同上 |
| 完全不声明 `$schema` | 3 | 同上 |
| **能解析到 card schema 的** | **0 / 54** | 同上 |
| 今天这两个 URL 的实际状态 | **HTTP 404 / 404** | 刚刚实测（2026-11-19） |
| 那个 200 的 URL 是什么 | 注册表的 `server.json` schema（`$comment` 写着 auto-generated from openapi） | 刚刚实测 |

**所以：一个规范强制的字段，54 个实现里 0 个能解析成功。**

## 四、两个必须通过的闸门

### 闸门 1：到底伤不伤人？

如果**没有任何工具去解析 `$schema`**，那这个 404 是惰性的——只是难看，不构成缺陷。

**检查方法**：在真实消费端里找"解析 `$schema`"的代码路径：
- MCP 客户端（LibreChat / AnythingLLM / 5ire / CodePilot / chatmcp）
- 官方 SDK（python / typescript / go）
- 校验器（registry 的 validator、IDE 插件）

**判定**：
- 有任一工具解析并按 schema 校验 → **伤人**，进闸门 2
- 全都不解析 → **降级为"规范卫生问题"**，不写论文，只写一条 issue

### 闸门 2：会不会继续传播？

**检查方法**：三点时间序列（今天 / 12 月中 / 1 月中），看新出现的卡片是否仍在抄这个 404 URL。
- 若新卡继续抄 → **传播未停**，说明规范缺陷在持续制造新错误
- 若新卡都修好了 → 传播已自行终止，只能写成"历史上的一次事件"

## 五、三周计划

| 周 | 做什么 | 产出 |
|---|---|---|
| 第 1 周 | 闸门 1：扫 9 个客户端 + 3 个 SDK 的 `$schema` 解析路径 | 一份"谁解析、谁不解析"的表 |
| 第 2 周 | 闸门 2 起点：重探 54 张卡 + 记录新卡；查 `ext-server-card#54` 状态 | 快照 + 变化 |
| 第 3 周 | 若两闸门都过：写 4 页短文；任一不过：写结论并关 | 论文稿 或 结论文档 |

## 六、杀项（明确写死）

1. **没有工具解析 `$schema`** → 不写论文（只提交 issue）
2. **`ext-server-card#54` 在我们开始前就修了** → 事件已结束，降级为 note
3. **54 这个 N 太小且找不到第二来源** → 换到"registry 的 server.json schema"这条更大的线
   （那里有 65,340 条记录可测）

## 七、这条为什么可能真是"新知识"

不是"我们发现了一个 404"——那太浅。真正的问题是：

> **当规范本身给出一个坏引用时，实现会多快、多广地继承它？**

这是一个**可复现的规范缺陷传播测量**，而且我们手里有全部 54 张卡和它们的原始 URL。
据我查到的范围，没有人做过这个测量。

**诚实前提**：如果闸门 1 不过，这就只是一条 GitHub issue，不是论文。我已经把这句写进杀项。

---

## 八、闸门 1 结果：**不通过，子问题作废**（2026-11-19）

去读了 `ext-server-card` 仓库的校验器源码，答案很干脆。

### 证据 1：官方校验器根本不解析 `$schema`

`scripts/validate-examples.ts` 的做法：

```ts
const SCHEMA_JSON = "schema.json";                 // 本地文件
const schema = JSON.parse(readFileSync(SCHEMA_JSON, "utf-8"));
ajv.addSchema(schema, "schema.json");
const validate = ajv.getSchema(`schema.json#/$defs/ServerCard`);
```

**它加载的是仓库里的本地 `schema.json`，按 `#/$defs/ServerCard` 校验。**
全程没有一次网络请求，**从不解析卡片里的 `$schema` URL**。

### 证据 2：`$schema` 只被当**字符串**检查

`examples/ServerCard/invalid/wrong-schema-name.json` 的内容是：

```json
{
  "$schema": "https://static.modelcontextprotocol.io/schemas/v1/server.schema.json",
  "name": "example-org/wrong-schema-name",
  ...
}
```

配的文件说明写着："References the removed registry server.json schema;
**only `server-card.schema.json` is valid in v1**."

也就是说：`$schema` 被约束成**一个特定的字符串常量**，校验器只比对字符串，
**从不解析它指向什么**。

### 结论

> **那个 404 是惰性的。** `$schema` 在这个生态里实际扮演的是**版本标记**，
> 不是"可解析的 schema 引用"。没有任何工具会去 fetch 它，所以它挂掉不影响任何行为。

**按我自己第 1 条杀项：不写论文。**

## 九、这个失败本身是有价值的

它证明了一件事，而且是可写的：

> **一个名字叫 `$schema`、格式与 JSON Schema 引用完全一致的字段，
> 实际上只被字符串匹配、从不被解析——这种"名不副实"正是它能把 404 藏 41 天的原因。**

但这是**设计批评**，不是测量论文。**最多写一条 issue，不进论文。**

## 十、重新选题（按同一套标准）

闸门 1 失败的教训：**先问"有没有人真的消费这个字段/这条数据"，再谈测多少。**

下一个候选（按"真实危害可验证"排序）：

| 候选 | 危害是否可验证 | 规模 |
|---|---|---|
| **注册表里 274/22,526 条引用指向装不上的版本** | ✅ **安装会硬失败**，可直接复现 | 22,526 |
| 跨生态同名碰撞（33 对） | ⚠️ 需要证明"有人真的装错" | 134 名 |
| 客户端零防御（0/9） | ⚠️ 需要证明危害 | 9 仓 |

**推荐下一个：package existence。** 因为它的"所以呢"是**可以直接跑出来的**——
挑几条真的 `npm install` / `pip install` 一次，看它是不是真的失败。
