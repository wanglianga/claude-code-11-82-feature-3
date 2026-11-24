# 区域影像中心受控分析平台

基于 **Vue 3 + Spring Boot 3 + PostgreSQL** 的受控影像分析沙箱。平台只处理**结构化影像特征与随访**，
不存储、不输出任何原始影像或患者级身份记录；通过批准编译、联合推断审查、累计披露预算与交付冻结/复现，
防止由多次合法聚合反推出小群体。

## 一、核心能力与对应实现

| 题目要求 | 实现位置 |
| --- | --- |
| 批准编译器生成可复现队列与字段投影 | `ApprovalService`、`CohortService`（确定性 JSON + specHash/cohortHash） |
| 查询解析器规范化筛选/分组/时间窗/输出，并与批准范围相交 | `QueryParser`（注释等展示文本不入哈希） |
| 结果关系账（队列/维度/过滤/抑制/舍入/水位） | `QueryAttempt`、`Deliverable.manifestJson` |
| 推断审查器：以所有已披露输出 + 公开总数为约束计算受抑制单元可行整数区间 | `InferenceEngine`（界传播 + DFS 可行性枚举）、`DisclosureReviewService` |
| 披露预算按研究空间 + 有效期累计窄化程度，不随查询文本/版本号重置 | `BudgetService`、`BudgetLedger`（空间×季度账本） |
| 交付器冻结结果/算法/审批/审查证明；复现器按当时审批与水线重建 | `DeliverableService`（sha256 清单 + 逐单元复现比对） |
| 最小发布单元 5；每空间每季度 10 风险点；唯一计数硬阻断；耗尽后仅零窄化结果 | `ResearchSpace`、`DisclosureReviewService` 裁决链 |
| 固定表组整组联合核验 / 交互会话实时扣共同预算（同一规则两条路线） | `reviewTableSet` / `review` + `InteractiveSession` |
| 撤回/到期拒新读，旧结果仅审计留存；算法升级只新增版本不改写旧结论 | `ApprovalService.requireReadable`、`AnalysisVersionService`、`DataSeeder`(feat-v1/v2) |
| **冻结模型版本哈希**：规范化清单（制品哈希/特征模式/登记指标/设备声明）sha256，审计独立重算比对 | `FrozenModel.versionHash`、`AuditManifests`、`ModelAuditService.runAudit` |
| **训练来源/设备范围账**：机构×扫描仪精确台账（审计可见），研究者/发布物仅见 `<20`/`>=20` 分桶与 20 舍入 | `TrainingSource`、`ModelAuditService.modelDetail/publicScope` |
| **登记指标复算**：按冻结验证集重算预登记敏感度（Wilson 区间）与校准 Brier/ECE/logistic 截距斜率（bootstrap 区间） | `AuditStats`、`ModelAuditService.metricRecompute`、`AuditStatsTest` |
| **稀有特征风险测试**：医院 Q 单扫描仪 4 例 / 3 例 RT-HALO 罕见纹理，两个 `<20` 联合单元的可解释风险分 | `ModelAuditService.riskUnits`（规模/集中度/独特性/设备垄断/MIA 因子） |
| **双路线审计**：聚合模型卡（抑制发布、声明设备绑定不可识别且未排除）；受控参数包（消融 + 成员推断 + 设备绑定探针，亚阈值统计不回传） | `cardRouteFindings` / `packageRouteFindings` |
| **输出抑制 + 逐例零输出**：阈值 20；小单元计数/风险分/单元统计一律 null；不存在逐例查询接口，导出探针对所有角色 403 并留痕 | `AuditPolicy`、`buildReleaseContent`、`ModelAuditController` 探针 |
| **发布闸门**：设备清单与声明不符 → `DEVICE_MANIFEST_MISMATCH` 阻断；未抑制小样本明细风险 ≥0.70 → 阻断；总体 MIA 优势 >0.20 → 抑制后仍阻断 | `ModelAuditService.gate/publish` |
| **模型审计视图**：版本卡、台账脱敏切换、双路线报告、风险条、模型卡 JSON、发布与阻断演示、逐例探针 | 前端 `ModelAuditView.vue`（导航「模型审计与模型卡」） |

### 风险点如何计算

- 候选约束分两层：**基线层** = 历史约束 + 本次抑制承诺（抑制是平台安全保证，不计点）；
  **增量层** = 精确披露等式、舍入区间、分区恒等。
- 对每个受保护单元（真实计数 < 5），比较加入增量约束前后的可行整数集合，
  **每少一个可能值计 1 点**；可行集被约束为唯一值时，无论预算余额一律硬阻断。
- 阻断不扣点、不留约束；同语义查询重复提交幂等零扣点；预算耗尽后只放行增量为 0 的结果。

### 模型审计 / 训练来源泄露筛查（本题特性）

虚构样例模型 `MDL-Q-CHEST 3.1.0-frozen` 用 **12,000 例**训练；医院 Q 的唯一扫描仪
`Q-AQ-07` 只覆盖 **4 例**，其中 **3 例**带罕见纹理 `RT-HALO`。因此
`HOSP_Q/Q-AQ-07`（n=4）与 `HOSP_Q/Q-AQ-07/RT-HALO`（n=3）两个联合单元都低于
**20 例披露阈值**。系统围绕该场景提供：

1. **版本哈希**：`versionHash = sha256(规范化JSON清单)`，清单覆盖制品哈希、源码 commit、
   训练/验证例数、决策阈值、特征 schema、预登记指标与设备声明；每次审计独立重算比对。
2. **训练来源/设备范围账**：7 个机构×设备行合计恰为 12,000。审计员可见精确值；
   分析师与发布物只见 `<20`/`>=20` 分桶，且大行计数按 20 舍入并附防相减说明
   （避免用总数 12,000 减去六个精确大计数反推出 4）。
3. **登记指标复算**：固定种子合成 2,400 例冻结验证集（逐例行仅服务端引擎可读，
   无任何对外接口），从逐例数据重算敏感度 + Wilson 95% 区间、Brier、10 箱 ECE、
   logistic 校准截距/斜率及 bootstrap 区间，并与冻结时登记值比对。
4. **稀有特征风险测试**：风险分 = 0.40 规模 + 0.20 罕见集中度 + 0.15 全局独特性
   + 0.15 设备垄断度 + 0.10 经验 MIA 因子。Q 两个单元分别约为 0.81 / 0.93（CRITICAL，
   越线 0.70），结论可解释。
5. **两条发布路线**：
   - **聚合模型卡 `MODEL_CARD`**：只含总体指标区间、抑制后的小单元风险等级（MEDIUM
     残余风险）与解释，易分发；明确标注 `DEVICE_BINDING_NOT_IDENTIFIABLE`、
     `deviceBindingRiskExcluded=false`，**不声称已排除设备绑定**，并承认无法对那 4 例
     复现逐例特征贡献。
   - **受控参数包 `PARAM_PACKAGE`**：在“隔离审计飞地”执行总体消融（含 Δ敏感度/Δ均分）、
     总体与目标设备子组的成员推断（AUC/优势）、设备绑定探针（设备签名 AUC≈0.998、
     模型输出扫描仪探针 AUC≈0.72 且 bootstrap 下界 >0.5 → `DISTINGUISHABLE`，必须报告）。
     罕见联合子组 n=17 < 20，其 MIA/消融统计 `returned=false`，数值不离开飞地。
6. **共同验收**：两条路线的总体指标都与冻结版本一致；所有产物 `caseLevelOutputCount=0`；
   罕见单元均有可解释结论。
7. **发布闸门（硬阻断）**：
   - `MDL-Q-CHEST 3.2.0-rc1`：声明漏报 `Q-AQ-07` 且虚列 `GHOST-X9`，还写了
     “不存在不足 20 例设备”的矛盾保证 → `DEVICE_MANIFEST_MISMATCH`，任何发布 409。
   - 对 3.1.0 要求 `applySuppression=false` 的未抑制明细/参数包 →
     `SMALL_SAMPLE_ATTACK_RISK_OVER_LINE` 409。
   - `MDL-XR-MEMO 0.9.1-rc2`：总体 MIA 优势 ≈0.64 > 0.20 越线 →
     `MIA_RISK_OVER_LINE`，即使抑制也阻断。

主要 API（前缀 `/api/model-audit`，另有别名 `/api/model-cards`）：

| 方法/路径 | 权限 | 说明 |
| --- | --- | --- |
| `GET /models`、`GET /models/{id}`、`GET /models/{id}/ledger` | 登录用户 | 版本列表/详情/台账；非审计角色自动脱敏 |
| `POST /models/{id}/runs` | AUDITOR/ADMIN | 运行 `{"route":"MODEL_CARD|PARAM_PACKAGE"}` 审计 |
| `GET /runs`、`GET /runs/{id}` | AUDITOR/ADMIN | 完整内部审计报告（含精确值） |
| `POST /runs/{id}/publish` | AUDITOR/ADMIN | 发布；`{"applySuppression":false}` 演示闸门阻断 |
| `GET /cards`、`GET /cards/{id}`、`/api/model-cards` | 登录用户 | 已发布抑制版模型卡/参数包 |
| `GET /cases`、`GET /models/{id}/cases`、`POST /case-export` | **全部 403** | 逐例输出探针，拒绝并写审计事件 |

## 二、目录结构

```
82/
├── backend/          Spring Boot 3.5 / Java 21 后端（JPA + JWT + PostgreSQL）
│   ├── src/main/java/com/sandbox/imaging/
│   │   ├── domain/       JPA 实体（20 张表，含 FrozenModel/TrainingSource/
│   │   │                 ValidationCase/ModelAuditRun/PublishedModelCard）
│   │   ├── inference/    线性整数约束与可行性枚举引擎
│   │   ├── modelaudit/   【本题】审计统计原语、策略常量、版本清单哈希、审计/闸门/抑制服务
│   │   ├── service/      批准编译、队列、查询解析/执行、披露审查、交付复现、预算
│   │   ├── web/          REST 控制器与视图投影（含 ModelAuditController）
│   │   └── bootstrap/    虚构演示数据 + 模型审计种子（ModelAuditSeeder）
│   ├── e2e_verify.py        既有披露场景端到端（35 项断言）
│   └── e2e_model_audit.py   本题模型审计端到端（46 项断言）
├── frontend/         Vue 3 + Vite + Pinia + Vue Router（11 个视图，含 ModelAuditView）
└── docker-compose.yml
```

## 三、一键启动（Docker Compose）

```bash
docker compose up --build
# 前端：http://localhost:8088
# 后端 API：http://localhost:8080/api
# PostgreSQL：localhost:5432（库/用户/密码 ccdev）
```

> 容器内 nginx 负责托管前端静态资源并把 `/api/` 反向代理到后端。

## 四、本地开发启动（使用预装运行时）

前置：PostgreSQL 运行在 `127.0.0.1:5432`（库/用户/密码 `ccdev`）。

### 后端（JDK 21 编译目标，本机 JDK 25 可运行）

```bash
cd backend
/opt/maven/bin/mvn spring-boot:run          # 默认读取 application.yml 的本地数据源
# 首次启动自动建表并写入虚构数据（DataSeeder + ModelAuditSeeder）
```

### 前端（Node 22）

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173 ，vite 已配置 /api 代理到 8080
```

## 五、测试账号

| 角色 | 用户名 | 密码 | 权限 |
| --- | --- | --- | --- |
| 管理员 | `admin` | `admin123` | 批准编译/激活/撤回、预算上限治理、水线、队列；亦可运行模型审计与发布 |
| 独立审计员 | `auditor` | `auditor123` | 模型审计双路线、查看精确台账/完整报告、发布抑制版模型卡与参数包 |
| 分析师 | `analyst` | `analyst123` | 队列复现、查询干跑/提交、固定表组、交付冻结与复现；查看脱敏台账与已发布模型卡，不能运行审计、不能取逐例记录 |

## 六、虚构演示数据

21 名脱敏患者（医院 A 14 名、医院 B 7 名），无原始影像、无真实身份：

- **APV-S1**（2026 上半年队列，水线 WL-2026Q3）：A=14、B=1，公开总数 15 —— 相减推断阻断演示。
- **APV-S2**（2026 下半年队列，水线 WL-2026Q4）：A=8、B=7 —— 无小单元安全披露演示。
- **APV-EXPIRED**：有效期 2025 年 —— 到期拒新读演示。
- 特征算法 `feat-v1` / `feat-v2` 两版 —— 算法升级只生成新分析版本，旧冻结结论与披露成本保留。

模型审计特性另播种 3 个冻结模型（`ModelAuditSeeder`，全部虚构）：

- **MDL-Q-CHEST `3.1.0-frozen`**：12,000 训练例；Q 院 Q-AQ-07 扫描仪 4 例 / 3 例 RT-HALO；
  2,400 例固定种子冻结验证集；设备声明与台账一致 —— 抑制后可发布、未抑制明细被阻断。
- **MDL-Q-CHEST `3.2.0-rc1`**：设备声明漏报 Q-AQ-07、虚列 GHOST-X9 —— 清单不符阻断演示。
- **MDL-XR-MEMO `0.9.1-rc2`**：过拟合模型，总体成员推断优势 ≈0.64 越线 —— 攻击风险阻断演示。

## 七、验证方式（均已实际执行）

> 以下结论来自本次交付在容器内的真实执行：JDK 25 运行 Maven（release 21 编译目标）、
> PostgreSQL 18.1（127.0.0.1:5432/ccdev）、Node 22.14。

### 0. 本题模型审计专项端到端（46 项断言，全部通过）

后端启动后：

```bash
python3 backend/e2e_model_audit.py
# 模型审计专项汇总：PASS=46 FAIL=0
```

覆盖：审计员登录与权限（分析师 403）、研究者台账脱敏、逐例探针 403 并留痕、
版本哈希复算一致、敏感度/Wilson 区间与 Brier/ECE/校准复算和登记值一致、
Q 单元 4/3 且 `<20`、风险分 0.81/0.93 越线、模型卡“设备绑定不可识别且未排除”、
抑制版模型卡无精确计数/风险分/措辞泄露、未抑制发布 409、参数包消融/MIA/设备绑定
（签名 AUC≈0.998、输出 AUC≈0.72 带区间、DISTINGUISHABLE）、罕见子组 `returned=false`、
路线不可混用、M2 清单不符阻断（识别漏报 Q-AQ-07 与 GHOST-X9）、M3 MIA 优势 0.64 越线阻断、
审计事件四类齐全。

### 1. 后端单元测试（推断引擎 + 审计统计，共 11 项）

```bash
cd backend && /opt/maven/bin/mvn test
# Tests run: 11, Failures: 0, Errors: 0, Skipped: 0
# InferenceEngineTest 5 项；AuditStatsTest 6 项（Wilson、敏感度、AUC、Brier/ECE、logistic 校准、策略阈值）
```

### 2. 既有端到端场景验证（35 项断言，无回归）

后端启动后：

```bash
python3 backend/e2e_verify.py
# 汇总：PASS=35 FAIL=0
```

覆盖：

1. **14/1 联合阻断**：总数表放行后，医院表干跑即识别 `hospital=B` 可行集被唯一推为 `{1}`，
   正式提交 BLOCKED 且不扣预算；固定表组（总数+医院）整组阻断；改用舍入到 5 后 B 被抑制、可行集恢复多值并放行。
2. **8/7 保留可用结果**：两单元均 ≥5，医院表 A=8/B=7 放行；同语义查询重复提交零扣点；
   冻结交付物后按当时审批与水线逐单元复现成功（outputMatch / cohortHashMatch / sha256 均一致）。
3. **撤回与到期**：撤回 APV-S2 后新查询返回 403，旧交付物仍可审计读取与复现（标记 approvalReadableNow=false）；
   到期批准新建版本被 403 拒绝。
4. **算法升级**：feat-v2 生成独立新版本并重新参加预算审查，旧交付物载荷哈希不变、未被改写。
5. **预算耗尽规则**：管理员把季度上限压到已用量后，窄化查询（1 风险点）被预算阻断，
   零窄化查询仍 ALLOWED 且账本不增长。

### 3. 前端构建（已实际执行）

```bash
cd frontend && npm install && npm run build
# ✓ built（含 ModelAuditView 独立 chunk，构建无错误）
```

登录后打开「场景验证导览」，可分别一键运行三个规定场景并查看联合推断可行集、裁决与审计留痕；
「模型审计与模型卡」视图可选择 3 个冻结模型，依次完成哈希/台账核对、双路线审计、
抑制版发布、未抑制发布阻断演示与逐例探针；其余视图提供批准/版本、队列复现、交互查询、
固定表组、交付复现、预算约束图与审计事件。

### 4. 一键 Docker 启动

```bash
docker compose up --build
# 前端 http://localhost:8088 ，后端 http://localhost:8080/api
```

后端镜像在构建阶段执行 `mvn clean package -DskipTests`，前端镜像执行 `npm install && npm run build`。
本题未引入任何新的 Maven/npm 依赖，且已在开发容器内实际执行并通过等价构建步骤
（`mvn package` 产出可运行 jar、`npm run build` 通过）；当前环境未提供 docker CLI，
因此未在此处实际执行 `docker compose build`。Dockerfile 与 compose 配置沿用基线、未改动。

## 八、安全边界说明

- 对外输出单元对被抑制数据不携带真实计数（`displayCount=null`），真实值仅存于内部台账与审计。
- 变量按 `批准@水线` 作用域隔离，不同队列的同名维度不会跨队列错误串扰。
- 可行性枚举设解数/节点上限，触顶时 fail-closed 阻断，避免在超大解空间下给出不完整的安全结论。
- 模型审计的逐例冻结验证集只供服务端统计引擎读取：没有任何返回 JPA 实体/逐例行的接口；
  逐例导出探针对 ADMIN/AUDITOR/ANALYST 一律 403 并写 `CASE_LEVEL_EXPORT_DENIED`。
- 小单元（<20）的精确计数、风险数值分与单元级 MIA/消融统计不进入模型卡/参数包；
  设备表全部计数 20 舍入或分桶，阻断利用训练总数相减的反推路径。
- 模型卡路线在数学上无法识别设备绑定效应时显式给出 `NOT_IDENTIFIABLE_FROM_AGGREGATES`
  与 `deviceBindingRiskExcluded=false`，不做“已排除设备风险”的虚假保证。
