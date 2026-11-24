#!/usr/bin/env python3
"""模型审计特性端到端验证（本题新增）。

覆盖验收点：
1. 冻结版本哈希可独立复算且一致；
2. 按冻结验证集重算预登记总体敏感度与校准指标（含区间），与冻结版本一致；
3. 训练来源/设备范围账：医院 Q 单扫描仪 4 例 / 3 例罕见纹理，联合单元 < 20；
4. 稀有特征风险测试给出可解释风险结论，风险分越线；
5. 输出抑制：模型卡/参数包不含精确小单元计数与单元统计量，逐例输出恒为 0；
6. 双路线：模型卡不能识别设备绑定时明确“未排除”；参数包报告消融/MIA/设备绑定；
7. 闸门：设备清单与声明不符阻断；小样本攻击风险未抑制发布阻断；MIA 越线模型阻断；
8. 权限：分析师不能运行审计；逐例导出对所有角色 403 并留痕。
"""
import json
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8080/api"
PASS, FAIL = [], []


def call(method, path, token=None, body=None, expect_error=False):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json",
                 **({"Authorization": "Bearer " + token} if token else {})})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        payload = e.read().decode()
        try:
            parsed = json.loads(payload)
        except Exception:
            parsed = {"raw": payload}
        if expect_error:
            return e.code, parsed
        raise AssertionError(f"{method} {path} 意外失败 {e.code}: {payload}")


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'✓' if cond else '✗'} {name} {detail}")


def login(u, p):
    return call("POST", "/auth/login", body={"username": u, "password": p})[1]["token"]


auditor = login("auditor", "auditor123")
admin = login("admin", "admin123")
analyst = login("analyst", "analyst123")

models = call("GET", "/model-audit/models", auditor)[1]
by_key = {(m["code"], m["version"]): m for m in models}
m1 = by_key[("MDL-Q-CHEST", "3.1.0-frozen")]["id"]
m2 = by_key[("MDL-Q-CHEST", "3.2.0-rc1")]["id"]
m3 = by_key[("MDL-XR-MEMO", "0.9.1-rc2")]["id"]
check("播种 3 个冻结模型版本", len(models) >= 3, f"n={len(models)}")
check("版本哈希为 64 位 sha256",
      all(len(m["versionHash"]) == 64 for m in models))
check("样例模型训练 12000 例",
      by_key[("MDL-Q-CHEST", "3.1.0-frozen")]["trainingCaseCount"] == 12000)

# ---------- 权限 ----------
code, _ = call("POST", f"/model-audit/models/{m1}/runs", analyst,
               {"route": "MODEL_CARD"}, expect_error=True)
check("分析师不得运行审计（403）", code == 403, str(code))

detail_an = call("GET", f"/model-audit/models/{m1}", analyst)[1]
qrow = [r for r in detail_an["ledger"] if r["scannerId"] == "Q-AQ-07"][0]
check("研究者台账中小单元精确计数被脱敏",
      qrow["caseCount"] is None and qrow["rareTextureCount"] is None
      and qrow["countBand"] == "<20" and qrow["suppressed"] is True,
      json.dumps(qrow, ensure_ascii=False))

# ---------- 逐例输出为零 ----------
for path, body in [("/model-audit/case-export", {"modelId": m1})]:
    code, payload = call("POST", path, analyst, body, expect_error=True)
    check("逐例导出探针被 403 拒绝且错误码明确",
          code == 403 and "CASE_LEVEL_OUTPUT_PROHIBITED" in payload.get("error", ""),
          payload.get("error", ""))
code, _ = call("GET", f"/model-audit/models/{m1}/cases", auditor, expect_error=True)
check("审计员同样不能经 GET 取逐例记录", code == 403, str(code))

# ---------- 路线一：聚合模型卡 ----------
_, run1 = call("POST", f"/model-audit/models/{m1}/runs", auditor, {"route": "MODEL_CARD"})
rep1 = run1["report"]
check("M1 版本哈希复算一致", run1["hashMatch"] is True
      and rep1["versionHash"]["frozen"] == rep1["versionHash"]["recomputed"])
mt = rep1["metrics"]
check("总体敏感度复算与登记一致（容差内）",
      mt["consistentWithFrozenVersion"] is True
      and mt["sensitivity"]["absoluteDiff"] <= 0.01,
      f"reg={mt['sensitivity']['registered']} got={mt['sensitivity']['recomputed']}")
check("敏感度带 Wilson 95% 区间且覆盖登记值",
      mt["sensitivity"]["wilson95Low"] <= mt["sensitivity"]["registered"]
      <= mt["sensitivity"]["wilson95High"])
check("校准指标(Brier/ECE/截距/斜率)完成复算并一致",
      mt["brier"]["absoluteDiff"] <= 0.01 and mt["ece10"]["absoluteDiff"] <= 0.02
      and "recomputedIntercept" in mt["calibrationLogistic"])
check("校准指标带 bootstrap 区间",
      mt["brier"]["bootstrap95Low"] <= mt["brier"]["recomputed"]
      <= mt["brier"]["bootstrap95High"])

q_scanner = [u for u in rep1["rareUnits"] if u["unitKey"] == "HOSP_Q/Q-AQ-07"][0]
q_rare = [u for u in rep1["rareUnits"] if u["unitKey"] == "HOSP_Q/Q-AQ-07/RT-HALO"][0]
check("医院Q×单扫描仪单元=4 且低于 20",
      q_scanner["caseCount"] == 4 and q_scanner["belowThreshold"])
check("医院Q×扫描仪×罕见纹理联合单元=3 且低于 20",
      q_rare["caseCount"] == 3 and q_rare["belowThreshold"])
check("罕见单元风险分越线(>=0.70)且有可解释结论",
      q_rare["lineCrossed"] and q_rare["attackRiskScore"] >= 0.70
      and "RT-HALO" in q_rare["explainableConclusion"]
      and "20" in q_rare["explainableConclusion"],
      f"score={q_rare['attackRiskScore']} level={q_rare['attackRiskLevel']}")
check("默认抑制后闸门 RELEASABLE", run1["decision"] == "RELEASABLE")
unsup = rep1["gate"]["unsuppressedDetail"]
check("未抑制明细闸门 BLOCKED 且原因为小样本攻击越线",
      unsup["decision"] == "BLOCKED"
      and any(r["code"] == "SMALL_SAMPLE_ATTACK_RISK_OVER_LINE" for r in unsup["blockReasons"]))

db_card = rep1["routeFindings"]["deviceBinding"]
check("模型卡路线声明设备绑定不可识别且未排除风险",
      db_card["status"] == "NOT_IDENTIFIABLE_FROM_AGGREGATES"
      and db_card["deviceBindingRiskExcluded"] is False)
check("模型卡路线承认无法复现 4 例特征贡献",
      rep1["routeFindings"]["caseLevelFeatureContribution"]["reproducible"] is False)
check("审计报告声明逐例输出为 0",
      rep1["zeroCaseOutput"]["caseLevelRecordsReturned"] == 0)

# 发布抑制版模型卡
_, card = call("POST", f"/model-audit/runs/{run1['id']}/publish", auditor, {})
content = card["content"]
check("抑制版模型卡发布成功且风险等级=MEDIUM",
      card["kind"] == "MODEL_CARD" and card["riskLevel"] == "MEDIUM"
      and len(card["contentHash"]) == 64)
check("模型卡总体指标与冻结版本一致",
      content["registeredPerformance"]["consistentWithFrozenVersion"] is True)
check("模型卡逐例输出计数为 0", content["caseLevelOutputCount"] == 0
      and content["perCaseTrainingRecordsIncluded"] is False)
pub_units = content["smallCellUnits"]
q_pub = [u for u in pub_units if u["unitKey"] == "HOSP_Q/Q-AQ-07/RT-HALO"][0]
check("模型卡小单元精确例数/风险分被抑制",
      q_pub["caseCount"] is None and q_pub["attackRiskScore"] is None
      and q_pub["caseCountBand"] == "<20"
      and q_pub["unitStatisticsReturned"] is False)
check("模型卡给出抑制后风险等级与解释",
      content["leakageRiskLevel"] == "MEDIUM"
      and q_pub["riskLevelAfterSuppression"] == "MEDIUM"
      and len(q_pub["explainableConclusion"]) > 20)
card_text = json.dumps(content, ensure_ascii=False)
check("模型卡文本不泄露精确小单元例数措辞",
      "仅 3 例" not in card_text and "仅 4 例" not in card_text
      and '"caseCount": 3' not in card_text and '"caseCount": 4' not in card_text)
q_device = [d for d in content["trainingScope"]["devices"] if d["scannerId"] == "Q-AQ-07"][0]
check("模型卡设备表 Q 行计数为 null+<20，且有防相减说明",
      q_device["caseCount"] is None and q_device["countBand"] == "<20"
      and "相减" in content["trainingScope"]["antiSubtractionNotice"])
check("模型卡明确未排除设备绑定风险",
      content["routeLimitations"]["deviceBinding"]["deviceBindingRiskExcluded"] is False)

# 未抑制发布必须被阻断
code, payload = call("POST", f"/model-audit/runs/{run1['id']}/publish", auditor,
                     {"applySuppression": False}, expect_error=True)
check("未抑制明细发布被 409 阻断",
      code == 409 and "SMALL_SAMPLE_ATTACK_RISK_OVER_LINE" in payload.get("error", ""),
      str(code))

# 分析师可读已发布模型卡（抑制内容）
code, cards_an = call("GET", "/model-cards", analyst)
check("研究者可经 /api/model-cards 读取已发布模型卡",
      code == 200 and any(c["id"] == card["id"] for c in cards_an))

# ---------- 路线二：受控参数包 ----------
_, runp = call("POST", f"/model-audit/models/{m1}/runs", auditor, {"route": "PARAM_PACKAGE"})
pf = runp["report"]["routeFindings"]
check("参数包路线同样复算登记指标且与冻结版本一致",
      runp["report"]["metrics"]["consistentWithFrozenVersion"] is True
      and runp["hashMatch"] is True)
check("参数包路线执行罕见特征消融（均分位移非零）",
      pf["ablationOverall"]["returned"] is True
      and pf["ablationOverall"]["deltaMeanScore"] > 0,
      f"deltaMean={pf['ablationOverall']['deltaMeanScore']}")
check("参数包路线执行总体成员推断测试",
      0 <= pf["membershipInferenceOverall"]["auc"] <= 1
      and "advantage" in pf["membershipInferenceOverall"])
check("参数包识别并报告设备绑定效应",
      pf["deviceBinding"]["status"] == "DISTINGUISHABLE"
      and pf["deviceBinding"]["deviceBindingDetected"] is True
      and pf["deviceBinding"]["scannerSignatureProbeAuc"] >= 0.9
      and len(pf["deviceBinding"]["modelScoreAucBootstrap95"]) == 2,
      json.dumps({k: pf["deviceBinding"][k] for k in
                  ("status", "scannerSignatureProbeAuc", "modelScoreScannerProbeAuc")},
                 ensure_ascii=False))
check("罕见联合单元统计不通过抑制规则(returned=false)",
      pf["rareJointUnitStat"]["returned"] is False
      and pf["rareJointUnitStat"]["suppressionReason"] == "JOINT_UNIT_N_BELOW_20")

_, pkg = call("POST", f"/model-audit/runs/{runp['id']}/publish", auditor, {})
pc = pkg["content"]
check("受控参数包发布成功", pkg["kind"] == "PARAM_PACKAGE" and len(pkg["contentHash"]) == 64)
check("参数包包含设备绑定结果且声明受控环境",
      pc["controlledFindings"]["deviceBinding"]["deviceBindingDetected"] is True
      and pc["controlledFindings"]["accessControls"]["executionEnvironment"] == "ISOLATED_AUDIT_ENCLAVE")
check("外发参数包罕见单元无数值泄露",
      pc["controlledFindings"]["rareJointUnitStat"]["returned"] is False
      and "aucInternal" not in json.dumps(pc["controlledFindings"]["rareJointUnitStat"]))
check("参数包逐例输出为 0", pc["caseLevelOutputCount"] == 0)

# 路线与发布物类型不可混用
code, payload = call("POST", f"/model-audit/runs/{run1['id']}/publish", auditor,
                     {"kind": "PARAM_PACKAGE"}, expect_error=True)
check("模型卡运行不能套发参数包（400）", code == 400, str(code))

# ---------- 阻断场景：设备清单不符 ----------
_, run2 = call("POST", f"/model-audit/models/{m2}/runs", auditor, {"route": "MODEL_CARD"})
check("M2 台账与发布声明不符 => BLOCKED",
      run2["decision"] == "BLOCKED"
      and any(r["code"] == "DEVICE_MANIFEST_MISMATCH"
              for r in run2["report"]["gate"]["blockReasons"]))
mc = run2["report"]["manifestCheck"]
check("不符明细同时识别漏报 Q-AQ-07 与虚列 GHOST-X9",
      "Q-AQ-07" in mc["missingInClaim"] and "GHOST-X9" in mc["undeclaredInLedger"])
code, _ = call("POST", f"/model-audit/runs/{run2['id']}/publish", auditor, {}, expect_error=True)
check("清单不符模型禁止发布（409）", code == 409, str(code))

# ---------- 阻断场景：攻击风险越线模型 ----------
_, run3 = call("POST", f"/model-audit/models/{m3}/runs", auditor, {"route": "PARAM_PACKAGE"})
mia_adv = run3["report"]["routeFindings"]["membershipInferenceOverall"]["advantage"]
check("M3 总体 MIA 优势越线(>0.20)且闸门 BLOCKED",
      mia_adv > 0.20 and run3["decision"] == "BLOCKED"
      and any(r["code"] == "MIA_RISK_OVER_LINE"
              for r in run3["report"]["gate"]["blockReasons"]),
      f"advantage={mia_adv}")
code, _ = call("POST", f"/model-audit/runs/{run3['id']}/publish", auditor, {}, expect_error=True)
check("攻击越线模型抑制后仍禁止发布（409）", code == 409, str(code))

# ---------- 审计留痕 ----------
events = call("GET", "/audit", auditor)[1]
actions = " ".join(e["action"] for e in events)
check("审计事件包含 MODEL_AUDIT_RUN / PUBLISHED / BLOCKED / CASE_DENIED",
      all(a in actions for a in
          ["MODEL_AUDIT_RUN", "MODEL_CARD_PUBLISHED", "MODEL_RELEASE_BLOCKED",
           "CASE_LEVEL_EXPORT_DENIED"]))

print(f"\n模型审计专项汇总：PASS={len(PASS)} FAIL={len(FAIL)}")
if FAIL:
    print("失败项：", FAIL)
    raise SystemExit(1)
print("全部模型审计断言通过")
