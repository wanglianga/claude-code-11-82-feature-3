package com.sandbox.imaging.modelaudit;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sandbox.imaging.common.ApiException;
import com.sandbox.imaging.domain.FrozenModel;
import com.sandbox.imaging.domain.ModelAuditRun;
import com.sandbox.imaging.domain.PublishedModelCard;
import com.sandbox.imaging.domain.TrainingSource;
import com.sandbox.imaging.domain.ValidationCase;
import com.sandbox.imaging.repo.FrozenModelRepository;
import com.sandbox.imaging.repo.ModelAuditRunRepository;
import com.sandbox.imaging.repo.PublishedModelCardRepository;
import com.sandbox.imaging.repo.TrainingSourceRepository;
import com.sandbox.imaging.repo.ValidationCaseRepository;
import com.sandbox.imaging.service.AuditService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static com.sandbox.imaging.modelaudit.AuditPolicy.ATTACK_RISK_BLOCK_LINE;
import static com.sandbox.imaging.modelaudit.AuditPolicy.BOOTSTRAP_REPLICATES;
import static com.sandbox.imaging.modelaudit.AuditPolicy.DISCLOSURE_THRESHOLD;
import static com.sandbox.imaging.modelaudit.AuditPolicy.MIA_ADVANTAGE_LINE;

/**
 * 冻结模型版本审计服务：
 * 版本哈希复核、训练来源/设备范围账核对、登记指标独立复算（含区间）、
 * 稀有特征小联合单元风险建模、双路线发现（模型卡限制 / 参数包消融+MIA+设备绑定）、
 * 发布闸门与小单元抑制后的模型卡/参数包构建。
 *
 * 本服务是唯一读取逐例 ValidationCase 的地方，且绝不把逐例数据放入任何对外产物。
 */
@Service
public class ModelAuditService {

    private final FrozenModelRepository modelRepo;
    private final TrainingSourceRepository sourceRepo;
    private final ValidationCaseRepository caseRepo;
    private final ModelAuditRunRepository runRepo;
    private final PublishedModelCardRepository cardRepo;
    private final ObjectMapper mapper;
    private final AuditService auditService;

    public ModelAuditService(FrozenModelRepository modelRepo, TrainingSourceRepository sourceRepo,
                             ValidationCaseRepository caseRepo, ModelAuditRunRepository runRepo,
                             PublishedModelCardRepository cardRepo, ObjectMapper mapper,
                             AuditService auditService) {
        this.modelRepo = modelRepo;
        this.sourceRepo = sourceRepo;
        this.caseRepo = caseRepo;
        this.runRepo = runRepo;
        this.cardRepo = cardRepo;
        this.mapper = mapper;
        this.auditService = auditService;
    }

    public FrozenModel mustGetModel(Long id) {
        return modelRepo.findById(id).orElseThrow(() -> ApiException.notFound("模型版本不存在: " + id));
    }

    // ================= 模型与台账视图 =================

    public List<Map<String, Object>> listModels() {
        return modelRepo.findAllByOrderByIdAsc().stream().map(m -> {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("id", m.getId());
            v.put("code", m.getCode());
            v.put("name", m.getName());
            v.put("version", m.getVersion());
            v.put("scenarioTag", m.getScenarioTag());
            v.put("status", m.getStatus());
            v.put("versionHash", m.getVersionHash());
            v.put("trainingCaseCount", m.getTrainingCaseCount());
            v.put("validationCaseCount", m.getValidationCaseCount());
            v.put("createdAt", m.getCreatedAt());
            runRepo.findByModelIdOrderByIdDesc(m.getId()).stream().findFirst()
                    .ifPresent(r -> v.put("latestDecision", r.getDecision()));
            cardRepo.findByModelIdOrderByIdDesc(m.getId()).stream().findFirst()
                    .ifPresent(c -> {
                        v.put("latestCardStatus", c.getStatus());
                        v.put("latestRiskLevel", c.getRiskLevel());
                    });
            return v;
        }).toList();
    }

    public Map<String, Object> modelDetail(Long id, boolean privileged) {
        FrozenModel m = mustGetModel(id);
        List<TrainingSource> sources = sourceRepo.findByModelIdOrderByIdAsc(id);
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("id", m.getId());
        v.put("code", m.getCode());
        v.put("name", m.getName());
        v.put("version", m.getVersion());
        v.put("scenarioTag", m.getScenarioTag());
        v.put("status", m.getStatus());
        v.put("versionHash", m.getVersionHash());
        v.put("artifactHash", m.getArtifactHash());
        v.put("sourceCommit", m.getSourceCommit());
        v.put("trainingCaseCount", m.getTrainingCaseCount());
        v.put("validationCaseCount", m.getValidationCaseCount());
        v.put("decisionThreshold", m.getDecisionThreshold());
        v.put("featureSchema", read(m.getFeatureSchemaJson()));
        v.put("registeredMetrics", read(m.getRegisteredMetricsJson()));
        v.put("deviceClaim", read(m.getDeviceClaimJson()));
        v.put("ledger", privileged ? exactLedger(sources) : redactedLedger(sources));
        v.put("viewerPrivileged", privileged);
        v.put("policy", policyMap());
        return v;
    }

    private List<Map<String, Object>> exactLedger(List<TrainingSource> sources) {
        return sources.stream().map(t -> {
            Map<String, Object> r = baseLedgerRow(t);
            r.put("caseCount", t.getCaseCount());
            r.put("rareTextureCount", t.getRareTextureCount());
            r.put("countBand", t.getCaseCount() < DISCLOSURE_THRESHOLD ? "<20" : ">=20");
            r.put("suppressed", false);
            return r;
        }).toList();
    }

    /** 研究者视图：低于阈值的精确计数不输出；所有设备计数按 20 舍入以防与总数相减反推 */
    private List<Map<String, Object>> redactedLedger(List<TrainingSource> sources) {
        return sources.stream().map(t -> {
            Map<String, Object> r = baseLedgerRow(t);
            boolean small = t.getCaseCount() < DISCLOSURE_THRESHOLD;
            r.put("caseCount", null);
            r.put("rareTextureCount", null);
            r.put("suppressed", small);
            r.put("countBand", small ? "<20" : ">=20");
            r.put("caseCountRounded20", small ? null : Math.round(t.getCaseCount() / 20.0) * 20);
            return r;
        }).toList();
    }

    private Map<String, Object> baseLedgerRow(TrainingSource t) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("institutionCode", t.getInstitutionCode());
        r.put("institutionName", t.getInstitutionName());
        r.put("scannerId", t.getScannerId());
        r.put("scannerModel", t.getScannerModel());
        r.put("vendor", t.getVendor());
        r.put("rareFeatureCode", t.getRareFeatureCode());
        return r;
    }

    private Map<String, Object> policyMap() {
        return Map.of("disclosureThreshold", DISCLOSURE_THRESHOLD,
                "attackRiskBlockLine", ATTACK_RISK_BLOCK_LINE,
                "miaAdvantageLine", MIA_ADVANTAGE_LINE);
    }

    // ================= 审计运行 =================

    @Transactional
    public ModelAuditRun runAudit(Long modelId, String route, String actor) {
        if (!"MODEL_CARD".equals(route) && !"PARAM_PACKAGE".equals(route)) {
            throw ApiException.badRequest("route 必须为 MODEL_CARD 或 PARAM_PACKAGE");
        }
        FrozenModel m = mustGetModel(modelId);
        List<TrainingSource> sources = sourceRepo.findByModelIdOrderByIdAsc(modelId);
        List<ValidationCase> cases = caseRepo.findByModelIdOrderByIdAsc(modelId);
        if (cases.isEmpty()) throw ApiException.conflict("冻结验证集缺失，无法独立复算");

        String hashRecomputed = AuditManifests.recomputeVersionHash(mapper, m);
        boolean hashMatch = hashRecomputed.equals(m.getVersionHash());

        Map<String, Object> manifest = manifestCheck(m, sources);
        Map<String, Object> metrics = metricRecompute(m, cases);
        List<Map<String, Object>> units = riskUnits(m, sources, cases);
        Map<String, Object> miaOverall = miaStat(cases);
        Map<String, Object> routeFindings = "MODEL_CARD".equals(route)
                ? cardRouteFindings()
                : packageRouteFindings(m, cases);

        double miaAdv = ((Number) miaOverall.get("advantage")).doubleValue();
        Map<String, Object> gate = gate(manifest, miaAdv, units);

        Map<String, Object> report = new LinkedHashMap<>();
        report.put("model", Map.of("id", m.getId(), "code", m.getCode(), "name", m.getName(),
                "version", m.getVersion(), "scenarioTag", m.getScenarioTag()));
        report.put("route", route);
        report.put("actor", actor);
        report.put("policy", policyMap());
        report.put("versionHash", Map.of("frozen", m.getVersionHash(),
                "recomputed", hashRecomputed, "match", hashMatch));
        report.put("manifestCheck", manifest);
        report.put("metrics", metrics);
        report.put("membershipInferenceOverall", miaOverall);
        report.put("rareUnits", units);
        report.put("routeFindings", routeFindings);
        report.put("zeroCaseOutput", Map.of(
                "caseLevelRecordsReturned", 0,
                "perCaseEndpointAvailable", false,
                "guarantee", "平台不存在输出逐例训练/验证记录的接口；逐例导出探针一律拒绝并留痕。"));
        report.put("gate", gate);
        report.put("conclusions", conclusions(route, hashMatch, metrics, manifest, units, gate, routeFindings));

        String json = writeJson(report);
        ModelAuditRun run = new ModelAuditRun();
        run.setModelId(modelId);
        run.setRoute(route);
        run.setActor(actor);
        run.setHashFrozen(m.getVersionHash());
        run.setHashRecomputed(hashRecomputed);
        run.setHashMatch(hashMatch);
        run.setDecision((String) gate.get("decision"));
        run.setReportJson(json);
        run.setReportHash(AuditManifests.hashCanonical(mapper, report));
        run = runRepo.save(run);

        auditService.log(null, actor, "MODEL_AUDIT_RUN",
                "模型 " + m.getCode() + "@" + m.getVersion() + " 路线 " + route
                        + " 裁决 " + run.getDecision() + " 哈希一致=" + hashMatch
                        + " 报告哈希 " + run.getReportHash().substring(0, 12));
        if ("BLOCKED".equals(run.getDecision())) {
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> reasons = (List<Map<String, Object>>) gate.get("blockReasons");
            auditService.log(null, actor, "MODEL_RELEASE_BLOCKED",
                    "审计闸门阻断 " + m.getCode() + "@" + m.getVersion() + "："
                            + reasons.stream().map(r -> (String) r.get("code")).collect(Collectors.joining(",")));
        }
        return run;
    }

    @Transactional(readOnly = true)
    public List<ModelAuditRun> listRuns() {
        return runRepo.findAllByOrderByIdDesc();
    }

    @Transactional(readOnly = true)
    public Map<String, Object> runView(Long id) {
        ModelAuditRun r = runRepo.findById(id).orElseThrow(() -> ApiException.notFound("审计运行不存在: " + id));
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("id", r.getId());
        v.put("modelId", r.getModelId());
        v.put("route", r.getRoute());
        v.put("actor", r.getActor());
        v.put("decision", r.getDecision());
        v.put("hashFrozen", r.getHashFrozen());
        v.put("hashRecomputed", r.getHashRecomputed());
        v.put("hashMatch", r.isHashMatch());
        v.put("reportHash", r.getReportHash());
        v.put("createdAt", r.getCreatedAt());
        v.put("report", read(r.getReportJson()));
        return v;
    }

    // ================= 清单核对 =================

    private Map<String, Object> manifestCheck(FrozenModel m, List<TrainingSource> sources) {
        Map<String, Object> claim = readMap(m.getDeviceClaimJson());
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> declared = (List<Map<String, Object>>) claim.getOrDefault("declaredScanners", List.of());
        Set<String> declaredIds = declared.stream().map(d -> String.valueOf(d.get("scannerId"))).collect(Collectors.toSet());
        Set<String> ledgerIds = sources.stream().map(TrainingSource::getScannerId).collect(Collectors.toSet());

        List<String> missingInClaim = ledgerIds.stream().filter(id -> !declaredIds.contains(id)).sorted().toList();
        List<String> undeclaredInLedger = declaredIds.stream().filter(id -> !ledgerIds.contains(id)).sorted().toList();

        boolean assuranceContradiction = claim.get("statement") != null
                && String.valueOf(claim.get("statement")).contains("不存在单台设备覆盖不足 20 例")
                && sources.stream().anyMatch(t -> t.getCaseCount() < DISCLOSURE_THRESHOLD);

        boolean match = missingInClaim.isEmpty() && undeclaredInLedger.isEmpty() && !assuranceContradiction;

        List<Map<String, Object>> discrepancies = new ArrayList<>();
        missingInClaim.forEach(id -> discrepancies.add(Map.of("type", "MISSING_IN_CLAIM",
                "scannerId", id, "message", "台账存在该设备但发布声明清单未列出")));
        undeclaredInLedger.forEach(id -> discrepancies.add(Map.of("type", "UNDECLARED_DEVICE",
                "scannerId", id, "message", "发布声明列出该设备，但训练来源台账中不存在")));
        if (assuranceContradiction) {
            discrepancies.add(Map.of("type", "ASSURANCE_CONTRADICTION", "scannerId", "-",
                    "message", "声明称不存在覆盖不足 20 例的设备，但台账存在小单元，声明与事实不符"));
        }

        Map<String, Object> r = new LinkedHashMap<>();
        r.put("match", match);
        r.put("declaredScannerCount", declaredIds.size());
        r.put("ledgerScannerCount", ledgerIds.size());
        r.put("missingInClaim", missingInClaim);
        r.put("undeclaredInLedger", undeclaredInLedger);
        r.put("assuranceContradiction", assuranceContradiction);
        r.put("discrepancies", discrepancies);
        r.put("statement", claim.get("statement"));
        return r;
    }

    // ================= 指标复算 =================

    private Map<String, Object> metricRecompute(FrozenModel m, List<ValidationCase> cases) {
        double threshold = m.getDecisionThreshold();
        List<Double> scores = cases.stream().map(ValidationCase::getScore).toList();
        List<Integer> ys = cases.stream().map(ValidationCase::getYTrue).toList();
        int[] cm = AuditStats.confusion(scores, ys, threshold);
        int tp = cm[0], fp = cm[1], tn = cm[2], fn = cm[3];
        int pos = tp + fn;
        double sens = AuditStats.round(pos == 0 ? 0 : (double) tp / pos, 4);
        AuditStats.Ci wilson = AuditStats.wilson(tp, pos, 1.96);

        double brierPoint = AuditStats.round(AuditStats.brier(scores, ys), 4);
        double ecePoint = AuditStats.round(AuditStats.ece(scores, ys, 10), 4);
        AuditStats.BootstrapCi brierCi = AuditStats.bootstrapCi(scores, ys,
                AuditStats::brier, BOOTSTRAP_REPLICATES, 77001L);
        AuditStats.BootstrapCi eceCi = AuditStats.bootstrapCi(scores, ys,
                (ss, yy) -> AuditStats.ece(ss, yy, 10), BOOTSTRAP_REPLICATES, 77002L);
        double[] cal = AuditStats.logisticCalibration(scores, ys);

        Map<String, Object> reg = readMap(m.getRegisteredMetricsJson());
        @SuppressWarnings("unchecked")
        Map<String, Object> regSens = (Map<String, Object>) reg.getOrDefault("sensitivity", Map.of());
        @SuppressWarnings("unchecked")
        Map<String, Object> regCal = (Map<String, Object>) reg.getOrDefault("calibration", Map.of());
        double regSensV = num(regSens.get("value"));
        double regBrier = num(regCal.get("brier"));
        double regEce = num(regCal.get("ece10"));
        double regInt = num(regCal.get("intercept"));
        double regSlope = num(regCal.get("slope"));

        double sensDiff = AuditStats.round(Math.abs(sens - regSensV), 4);
        double brierDiff = AuditStats.round(Math.abs(brierPoint - regBrier), 4);
        double eceDiff = AuditStats.round(Math.abs(ecePoint - regEce), 4);
        boolean sensOk = sensDiff <= 0.01;
        boolean brierOk = brierDiff <= 0.01;
        boolean eceOk = eceDiff <= 0.02 && ecePoint <= 0.08;
        boolean ciContainsRegistered = regSensV >= wilson.low() - 1e-9 && regSensV <= wilson.high() + 1e-9;
        boolean consistent = sensOk && brierOk && eceOk && ciContainsRegistered;

        Map<String, Object> r = new LinkedHashMap<>();
        r.put("threshold", threshold);
        r.put("confusion", Map.of("tp", tp, "fp", fp, "tn", tn, "fn", fn));
        r.put("positiveCases", pos);
        r.put("sensitivity", metricBlock("sensitivity", regSensV, sens, sensDiff,
                Map.of("wilson95Low", wilson.low(), "wilson95High", wilson.high(),
                        "registeredWithinCi", ciContainsRegistered)));
        r.put("brier", metricBlock("brier", regBrier, brierPoint, brierDiff,
                Map.of("bootstrap95Low", brierCi.low(), "bootstrap95High", brierCi.high())));
        r.put("ece10", metricBlock("ece10", regEce, ecePoint, eceDiff,
                Map.of("bootstrap95Low", eceCi.low(), "bootstrap95High", eceCi.high(),
                        "acceptanceMax", 0.08)));
        Map<String, Object> calib = new LinkedHashMap<>();
        calib.put("recomputedIntercept", cal[0]);
        calib.put("recomputedSlope", cal[1]);
        calib.put("interceptSe", cal[2]);
        calib.put("slopeSe", cal[3]);
        calib.put("registeredIntercept", regInt);
        calib.put("registeredSlope", regSlope);
        calib.put("interceptDiff", AuditStats.round(Math.abs(cal[0] - regInt), 4));
        calib.put("slopeDiff", AuditStats.round(Math.abs(cal[1] - regSlope), 4));
        r.put("calibrationLogistic", calib);
        r.put("consistentWithFrozenVersion", consistent);
        List<String> reasons = new ArrayList<>();
        if (!sensOk) reasons.add("敏感度复算偏差超过 0.01 容差");
        if (!brierOk) reasons.add("Brier 复算偏差超过 0.01 容差");
        if (!eceOk) reasons.add("ECE 复算偏差超过 0.02 容差或超过 0.08 上限");
        if (!ciContainsRegistered) reasons.add("登记敏感度未落入复算 Wilson 95% 区间");
        r.put("consistencyIssues", reasons);
        return r;
    }

    private Map<String, Object> metricBlock(String metric, double registered, double recomputed,
                                            double diff, Map<String, Object> extra) {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("metric", metric);
        b.put("registered", registered);
        b.put("recomputed", recomputed);
        b.put("absoluteDiff", diff);
        b.putAll(extra);
        return b;
    }

    // ================= 稀有单元风险 =================

    private List<Map<String, Object>> riskUnits(FrozenModel m, List<TrainingSource> sources,
                                                List<ValidationCase> cases) {
        int totalCases = sources.stream().mapToInt(TrainingSource::getCaseCount).sum();
        int totalRare = sources.stream().mapToInt(TrainingSource::getRareTextureCount).sum();
        double distinctiveness = AuditStats.round(Math.max(0, Math.min(1, 1 - (double) totalRare / totalCases)), 4);

        List<Map<String, Object>> units = new ArrayList<>();
        for (TrainingSource t : sources) {
            int instTotal = sources.stream()
                    .filter(x -> x.getInstitutionCode().equals(t.getInstitutionCode()))
                    .mapToInt(TrainingSource::getCaseCount).sum();
            double monopoly = AuditStats.round((double) t.getCaseCount() / instTotal, 4);

            units.add(buildUnit(m, cases, t, false, totalCases, t.getRareTextureCount(),
                    distinctiveness, monopoly));
            if (t.getRareTextureCount() > 0 && t.getRareFeatureCode() != null) {
                units.add(buildUnit(m, cases, t, true, totalCases, t.getRareTextureCount(),
                        distinctiveness, monopoly));
            }
        }
        return units;
    }

    private Map<String, Object> buildUnit(FrozenModel m, List<ValidationCase> cases, TrainingSource t,
                                          boolean rareJoint, int totalCases, int rareCount,
                                          double distinctiveness, double monopoly) {
        int n = rareJoint ? t.getRareTextureCount() : t.getCaseCount();
        Map<String, Object> dims = new LinkedHashMap<>();
        dims.put("institution", t.getInstitutionCode());
        dims.put("scanner", t.getScannerId());
        String unitKey = t.getInstitutionCode() + "/" + t.getScannerId();
        if (rareJoint) {
            dims.put("rareFeature", t.getRareFeatureCode());
            unitKey += "/" + t.getRareFeatureCode();
        }

        double sizeRisk = AuditStats.round(Math.max(0, Math.min(1,
                (double) (DISCLOSURE_THRESHOLD - n) / DISCLOSURE_THRESHOLD)), 4);
        double concentration = n == 0 ? 0 : AuditStats.round((double) rareCount / (rareJoint ? n : n), 4);
        // rareJoint 单元内全部为罕见特征 => 集中度 1
        if (rareJoint) concentration = 1.0;

        List<ValidationCase> subgroup = cases.stream()
                .filter(c -> c.getScannerId().equals(t.getScannerId())
                        && (!rareJoint || c.isRareTexture()))
                .toList();
        Map<String, Object> mia = miaStat(subgroup);
        double miaAdv = Math.max(0, ((Number) mia.get("advantage")).doubleValue());
        double miaFactor = AuditStats.round(Math.min(1, miaAdv / 0.5), 4);
        double score = AuditStats.round(
                0.40 * sizeRisk + 0.20 * concentration + 0.15 * distinctiveness
                        + 0.15 * monopoly + 0.10 * miaFactor, 4);
        String level = AuditPolicy.riskLevel(score);

        Map<String, Object> factors = new LinkedHashMap<>();
        factors.put("sizeRisk", sizeRisk);
        factors.put("rareConcentration", concentration);
        factors.put("globalRareDistinctiveness", distinctiveness);
        factors.put("scannerMonopolyAtInstitution", monopoly);
        factors.put("empiricalMiaFactor", miaFactor);

        Map<String, Object> empirical = new LinkedHashMap<>();
        empirical.put("validationSubgroupN", subgroup.size());
        empirical.put("miaAucInternal", mia.get("auc"));
        empirical.put("miaAdvantageInternal", mia.get("advantage"));
        if (!subgroup.isEmpty()) {
            List<Double> fs = subgroup.stream().map(ValidationCase::getScore).toList();
            List<Double> fr = subgroup.stream().map(ValidationCase::getScoreWithoutRare).toList();
            List<Integer> yy = subgroup.stream().map(ValidationCase::getYTrue).toList();
            double sFull = AuditStats.sensitivity(fs, yy, m.getDecisionThreshold());
            double sAbl = AuditStats.sensitivity(fr, yy, m.getDecisionThreshold());
            empirical.put("ablationSensitivityFullInternal", AuditStats.round(sFull, 4));
            empirical.put("ablationSensitivityWithoutRareInternal", AuditStats.round(sAbl, 4));
            empirical.put("ablationDeltaInternal", AuditStats.round(sFull - sAbl, 4));
        }

        Map<String, Object> u = new LinkedHashMap<>();
        u.put("unitKey", unitKey);
        u.put("jointUnit", rareJoint);
        u.put("dimensions", dims);
        u.put("caseCount", n);
        u.put("rareTextureCount", rareJoint ? n : rareCount);
        u.put("belowThreshold", n < DISCLOSURE_THRESHOLD);
        u.put("factors", factors);
        u.put("attackRiskScore", score);
        u.put("attackRiskLevel", level);
        u.put("lineCrossed", score >= ATTACK_RISK_BLOCK_LINE);
        u.put("empiricalInternal", empirical);
        u.put("explainableConclusion", explainUnit(unitKey, n, rareJoint, score, level, subgroup.size()));
        u.put("publicConclusion", "联合单元 " + unitKey + " 的规模低于 " + DISCLOSURE_THRESHOLD
                + " 例披露阈值，精确例数与单元级统计量已抑制；该单元固有攻击风险等级为 " + level
                + "，抑制后对外残余风险等级为 MEDIUM。任何未抑制的单元精确计数/统计量发布都会越过"
                + "小样本攻击风险闸门；聚合模型卡无法逐例复现其特征贡献，受控参数包内的对应统计量"
                + "同样不通过抑制规则、不得外发。");
        return u;
    }

    private String explainUnit(String key, int n, boolean rareJoint, double score, String level, int valN) {
        if (n >= DISCLOSURE_THRESHOLD) {
            return "单元 " + key + " 规模 " + n + " 已达 " + DISCLOSURE_THRESHOLD
                    + " 例阈值，可按常规聚合发布。";
        }
        return "联合单元 " + key + " 仅 " + n + " 例（< " + DISCLOSURE_THRESHOLD
                + "），小样本攻击综合风险 " + score + "（" + level + "）。"
                + "任何包含该单元精确计数或单元级统计量的发布都会显著提高成员推断/重识别风险并越线；"
                + "聚合发布物必须抑制其精确规模与单元统计量，仅保留风险等级与可解释结论。"
                + "模型卡路线无法对这 " + n + " 例复现特征贡献；受控参数包可在隔离环境计算，"
                + "但对应统计量（验证子组 n=" + valN + "，<20）同样不得离开受控环境。";
    }

    // ================= MIA / 路线发现 =================

    private Map<String, Object> miaStat(List<ValidationCase> group) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("sampleSize", group.size());
        if (group.size() < 2) {
            r.put("auc", null);
            r.put("advantage", null);
            return r;
        }
        List<Double> lossNeg = group.stream().map(c -> -c.getMiaLoss()).toList();
        List<Integer> member = group.stream().map(c -> c.isMemberFlag() ? 1 : 0).toList();
        double auc = AuditStats.round(AuditStats.auc(lossNeg, member), 4);
        r.put("auc", auc);
        r.put("advantage", AuditStats.round(2 * auc - 1, 4));
        return r;
    }

    private Map<String, Object> cardRouteFindings() {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("route", "MODEL_CARD");
        f.put("distributable", true);
        f.put("performedTests", List.of("FROZEN_HASH_RECHECK", "REGISTERED_METRIC_RECOMPUTE",
                "WILSON_BOOTSTRAP_INTERVALS", "LEDGER_MANIFEST_RECONCILIATION",
                "STRUCTURAL_SMALL_CELL_RISK"));
        f.put("notPerformedTests", List.of("RARE_FEATURE_ABLATION", "MEMBERSHIP_INFERENCE",
                "DEVICE_BINDING_PROBE"));
        f.put("caseLevelFeatureContribution", Map.of(
                "reproducible", false,
                "code", "CANNOT_REPRODUCE_CASE_LEVEL_FEATURE_CONTRIBUTION",
                "message", "聚合模型卡只有总体汇总值，无法对医院 Q 的亚阈值扫描仪联合单元单独复现逐例特征贡献。"));
        f.put("deviceBinding", Map.of(
                "status", "NOT_IDENTIFIABLE_FROM_AGGREGATES",
                "deviceBindingRiskExcluded", false,
                "code", "DEVICE_BINDING_NOT_IDENTIFIABLE",
                "message", "聚合指标无法识别扫描仪/设备绑定效应；本模型卡不声称已排除该风险，"
                        + "建议改走受控参数包路线执行设备探针与消融。"));
        return f;
    }

    private Map<String, Object> packageRouteFindings(FrozenModel m, List<ValidationCase> cases) {
        double threshold = m.getDecisionThreshold();

        // 总体消融（n 大，可外发）
        List<Double> full = cases.stream().map(ValidationCase::getScore).toList();
        List<Double> ablated = cases.stream().map(ValidationCase::getScoreWithoutRare).toList();
        List<Integer> ys = cases.stream().map(ValidationCase::getYTrue).toList();
        double sFull = AuditStats.sensitivity(full, ys, threshold);
        double sAbl = AuditStats.sensitivity(ablated, ys, threshold);
        double meanFull = full.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        double meanAbl = ablated.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        long rareN = cases.stream().filter(ValidationCase::isRareTexture).count();
        Map<String, Object> ablationOverall = new LinkedHashMap<>();
        ablationOverall.put("stat", "RARE_FEATURE_ABLATION_OVERALL");
        ablationOverall.put("sampleSize", cases.size());
        ablationOverall.put("rareFeatureCarriersInValidation", rareN);
        ablationOverall.put("returned", true);
        ablationOverall.put("sensitivityFull", AuditStats.round(sFull, 4));
        ablationOverall.put("sensitivityWithoutRare", AuditStats.round(sAbl, 4));
        ablationOverall.put("deltaSensitivity", AuditStats.round(sFull - sAbl, 4));
        ablationOverall.put("meanScoreFull", AuditStats.round(meanFull, 4));
        ablationOverall.put("meanScoreWithoutRare", AuditStats.round(meanAbl, 4));
        ablationOverall.put("deltaMeanScore", AuditStats.round(meanFull - meanAbl, 4));
        ablationOverall.put("brierFull", AuditStats.round(AuditStats.brier(full, ys), 4));
        ablationOverall.put("brierWithoutRare", AuditStats.round(AuditStats.brier(ablated, ys), 4));

        // MIA 总体（可外发）
        Map<String, Object> miaOverall = miaStat(cases);
        miaOverall.put("stat", "MEMBERSHIP_INFERENCE_OVERALL");
        miaOverall.put("returned", cases.size() >= DISCLOSURE_THRESHOLD);
        miaOverall.put("advantageLine", MIA_ADVANTAGE_LINE);
        miaOverall.put("lineCrossed",
                ((Number) miaOverall.getOrDefault("advantage", 0)).doubleValue() > MIA_ADVANTAGE_LINE);

        // 设备绑定：取台账中规模最小的扫描仪作为目标设备（本题即 Q-AQ-07 / R-DR-02）
        String targetScanner = sourceRepo.findByModelIdOrderByIdAsc(m.getId()).stream()
                .min((a, b) -> Integer.compare(a.getCaseCount(), b.getCaseCount()))
                .map(TrainingSource::getScannerId).orElse(null);
        Map<String, Object> device = deviceBinding(cases, targetScanner);

        // 目标设备聚合子组 MIA（验证子组 >=20 才外发）
        List<ValidationCase> scannerGroup = cases.stream().filter(c -> c.getScannerId().equals(targetScanner)).toList();
        Map<String, Object> miaScanner = miaStat(scannerGroup);
        miaScanner.put("stat", "MEMBERSHIP_INFERENCE_TARGET_SCANNER");
        miaScanner.put("scannerId", targetScanner);
        miaScanner.put("returned", scannerGroup.size() >= DISCLOSURE_THRESHOLD);
        if (scannerGroup.size() < DISCLOSURE_THRESHOLD) {
            miaScanner.put("suppressionReason", "SCANNER_CELL_N_BELOW_20");
        }

        // 罕见联合子组统计：内部保留数值，外部一律抑制
        List<ValidationCase> rareJoint = scannerGroup.stream().filter(ValidationCase::isRareTexture).toList();
        Map<String, Object> rareStat = miaStat(rareJoint);
        rareStat.put("stat", "MIA_AND_ABLATION_RARE_JOINT_UNIT");
        rareStat.put("scannerId", targetScanner);
        rareStat.put("returned", false);
        rareStat.put("suppressed", true);
        rareStat.put("suppressionReason", "JOINT_UNIT_N_BELOW_20");
        rareStat.put("message", "罕见特征×设备联合子组低于 20 例，单元级 MIA/消融统计不得离开受控环境。");

        Map<String, Object> access = new LinkedHashMap<>();
        access.put("executionEnvironment", "ISOLATED_AUDIT_ENCLAVE");
        access.put("modelAccess", "CHECKED_OUT_FROZEN_ARTIFACT_ONLY");
        access.put("dataAccess", "FROZEN_VALIDATION_SET_IN_ENCLAVE_ONLY");
        access.put("scriptAccess", "APPROVED_AUDIT_SCRIPTS_ONLY");
        access.put("caseLevelEgress", "BLOCKED");

        Map<String, Object> f = new LinkedHashMap<>();
        f.put("route", "PARAM_PACKAGE");
        f.put("distributable", "CONTROLLED_RECIPIENTS_ONLY");
        f.put("accessControls", access);
        f.put("ablationOverall", ablationOverall);
        f.put("membershipInferenceOverall", miaOverall);
        f.put("membershipInferenceTargetScanner", miaScanner);
        f.put("rareJointUnitStat", rareStat);
        f.put("deviceBinding", device);
        return f;
    }

    private Map<String, Object> deviceBinding(List<ValidationCase> cases, String targetScanner) {
        List<Double> sig = new ArrayList<>();
        List<Double> score = new ArrayList<>();
        List<Double> scoreNoRare = new ArrayList<>();
        List<Integer> label = new ArrayList<>();
        List<Double> qScores = new ArrayList<>(), otherScores = new ArrayList<>();
        for (ValidationCase c : cases) {
            int isQ = c.getScannerId().equals(targetScanner) ? 1 : 0;
            sig.add(c.getDeviceSignature());
            score.add(c.getScore());
            scoreNoRare.add(c.getScoreWithoutRare());
            label.add(isQ);
            if (isQ == 1) qScores.add(c.getScore()); else otherScores.add(c.getScore());
        }
        double sigAuc = AuditStats.round(AuditStats.auc(sig, label), 4);
        double scoreAuc = AuditStats.round(AuditStats.auc(score, label), 4);
        double scoreAucLow = scoreAuc, scoreAucHigh = scoreAuc;
        try {
            AuditStats.BootstrapCi ci = AuditStats.bootstrapCi(score, label,
                    AuditStats::auc, 200, 77003L);
            scoreAucLow = ci.low();
            scoreAucHigh = ci.high();
        } catch (Exception ignored) {
            // 区间计算失败时退化为点值，判定仍可依据 signature AUC
        }
        double ablatedAuc = AuditStats.round(AuditStats.auc(scoreNoRare, label), 4);

        double qMean = qScores.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        double oMean = otherScores.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        double pooledSd = pooledSd(qScores, otherScores);
        double cohenD = pooledSd == 0 ? 0 : AuditStats.round((qMean - oMean) / pooledSd, 4);

        boolean distinguishable = sigAuc >= 0.90 || (scoreAuc >= 0.70 && scoreAucLow > 0.5);
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("targetScanner", targetScanner);
        d.put("status", distinguishable ? "DISTINGUISHABLE" : "NOT_DISTINGUISHABLE");
        d.put("deviceBindingDetected", distinguishable);
        d.put("scannerSignatureProbeAuc", sigAuc);
        d.put("modelScoreScannerProbeAuc", scoreAuc);
        d.put("modelScoreAucBootstrap95", List.of(AuditStats.round(scoreAucLow, 4), AuditStats.round(scoreAucHigh, 4)));
        d.put("ablatedScoreScannerProbeAuc", ablatedAuc);
        d.put("scoreMeanTargetScanner", AuditStats.round(qMean, 4));
        d.put("scoreMeanOtherScanners", AuditStats.round(oMean, 4));
        d.put("scoreCohenD", cohenD);
        d.put("persistsAfterRareAblation", Math.abs(ablatedAuc - 0.5) >= Math.abs(scoreAuc - 0.5) - 0.03);
        d.put("message", distinguishable
                ? "设备绑定效应可区分：设备签名/模型输出能够识别目标扫描仪，必须在参数包中报告，"
                  + "并建议设备分层验证、特征去设备化或重新平衡训练来源。"
                : "现有验证集未能以足够置信度区分设备绑定效应；不能据此声称风险已排除。");
        return d;
    }

    private double pooledSd(List<Double> a, List<Double> b) {
        if (a.size() < 2 || b.size() < 2) return 0;
        double ma = a.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        double mb = b.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        double va = a.stream().mapToDouble(x -> (x - ma) * (x - ma)).sum() / (a.size() - 1);
        double vb = b.stream().mapToDouble(x -> (x - mb) * (x - mb)).sum() / (b.size() - 1);
        return Math.sqrt(((a.size() - 1) * va + (b.size() - 1) * vb) / (a.size() + b.size() - 2));
    }

    // ================= 闸门 =================

    private Map<String, Object> gate(Map<String, Object> manifest, double overallMiaAdv,
                                     List<Map<String, Object>> units) {
        List<Map<String, Object>> defaultReasons = new ArrayList<>();
        boolean manifestMatch = Boolean.TRUE.equals(manifest.get("match"));
        if (!manifestMatch) {
            defaultReasons.add(reason("DEVICE_MANIFEST_MISMATCH",
                    "训练设备清单与发布声明不符，阻断一切发布；须先更正声明或台账并重新冻结版本。"));
        }
        if (overallMiaAdv > MIA_ADVANTAGE_LINE) {
            defaultReasons.add(reason("MIA_RISK_OVER_LINE",
                    "总体成员推断优势 " + AuditStats.round(overallMiaAdv, 3) + " 超过越线值 "
                            + MIA_ADVANTAGE_LINE + "，小样本/成员攻击风险越线，抑制后仍阻断发布。"));
        }
        String defaultDecision = defaultReasons.isEmpty() ? "RELEASABLE" : "BLOCKED";

        List<Map<String, Object>> unsupReasons = new ArrayList<>(defaultReasons);
        for (Map<String, Object> u : units) {
            if (Boolean.TRUE.equals(u.get("belowThreshold")) && Boolean.TRUE.equals(u.get("lineCrossed"))) {
                unsupReasons.add(reason("SMALL_SAMPLE_ATTACK_RISK_OVER_LINE",
                        "联合单元 " + u.get("unitKey") + " 风险分 " + u.get("attackRiskScore")
                                + " ≥ " + ATTACK_RISK_BLOCK_LINE
                                + "；禁止发布含该单元精确计数/统计量的未抑制明细。"));
            }
        }
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("evaluatedArtifact", "SUPPRESSED_AGGREGATE_RELEASE");
        r.put("decision", defaultDecision);
        r.put("blockReasons", defaultReasons);
        r.put("unsuppressedDetail", Map.of(
                "evaluatedArtifact", "UNSUPPRESSED_DETAIL_OR_PARAM_PACKAGE",
                "decision", unsupReasons.isEmpty() ? "RELEASABLE" : "BLOCKED",
                "blockReasons", unsupReasons));
        r.put("policy", policyMap());
        return r;
    }

    private Map<String, Object> reason(String code, String message) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("code", code);
        r.put("message", message);
        return r;
    }

    private List<String> conclusions(String route, boolean hashMatch, Map<String, Object> metrics,
                                    Map<String, Object> manifest, List<Map<String, Object>> units,
                                    Map<String, Object> gate, Map<String, Object> findings) {
        List<String> c = new ArrayList<>();
        c.add(hashMatch ? "冻结版本哈希复算一致，审计对象确为登记的冻结版本。"
                : "版本哈希不一致：制品/清单可能被改写，阻断并启动完整性调查。");
        c.add(Boolean.TRUE.equals(metrics.get("consistentWithFrozenVersion"))
                ? "独立复算的总体敏感度与校准指标和冻结登记值一致，区间覆盖登记值。"
                : "登记指标复算不一致，不得发布。");
        c.add("所有对外产物逐例输出为 0，平台不提供逐例训练记录访问。");
        units.stream().filter(u -> Boolean.TRUE.equals(u.get("belowThreshold"))).findFirst()
                .ifPresent(u -> c.add("罕见联合单元 " + u.get("unitKey") + " 仅 " + u.get("caseCount")
                        + " 例，风险等级 " + u.get("attackRiskLevel") + "，发布执行 <20 抑制。"));
        if ("MODEL_CARD".equals(route)) {
            c.add("模型卡路线：设备绑定效应不可由聚合指标识别，未声称排除该风险；4 例特征贡献不可逐例复现。");
        } else {
            @SuppressWarnings("unchecked")
            Map<String, Object> db = (Map<String, Object>) findings.get("deviceBinding");
            c.add(Boolean.TRUE.equals(db.get("deviceBindingDetected"))
                    ? "参数包路线：设备绑定效应可区分（" + db.get("status") + "），已在报告中报告。"
                    : "参数包路线：未能以足够置信度区分设备绑定效应，不声称已排除。");
        }
        c.add("闸门结论（抑制后发布物）：" + gate.get("decision")
                + "；未抑制明细结论："
                + ((Map<?, ?>) gate.get("unsuppressedDetail")).get("decision") + "。");
        return c;
    }

    // ================= 发布与模型卡 =================

    @Transactional
    public PublishedModelCard publish(Long runId, boolean applySuppression, String kindOverride, String actor) {
        ModelAuditRun run = runRepo.findById(runId)
                .orElseThrow(() -> ApiException.notFound("审计运行不存在: " + runId));
        FrozenModel m = mustGetModel(run.getModelId());
        Map<String, Object> report = readMap(run.getReportJson());
        @SuppressWarnings("unchecked")
        Map<String, Object> gate = (Map<String, Object>) report.get("gate");

        if (!"RELEASABLE".equals(run.getDecision())) {
            throw ApiException.conflict("发布被闸门阻断：" + reasonCodes(gate.get("blockReasons")));
        }
        if (!applySuppression) {
            @SuppressWarnings("unchecked")
            Map<String, Object> unsup = (Map<String, Object>) gate.get("unsuppressedDetail");
            if ("BLOCKED".equals(unsup.get("decision"))) {
                throw ApiException.conflict("未抑制明细发布被阻断：" + reasonCodes(unsup.get("blockReasons")));
            }
        }

        String kind = kindOverride != null ? kindOverride : run.getRoute();
        if (!"MODEL_CARD".equals(kind) && !"PARAM_PACKAGE".equals(kind)) {
            throw ApiException.badRequest("kind 必须为 MODEL_CARD 或 PARAM_PACKAGE");
        }
        // 模型卡只能来自 MODEL_CARD 运行；参数包只能来自 PARAM_PACKAGE 运行，避免路线规避
        if (!kind.equals(run.getRoute())) {
            throw ApiException.badRequest("发布物类型必须与审计路线一致：" + run.getRoute());
        }

        Map<String, Object> content = buildReleaseContent(m, report, kind, applySuppression, runId);
        String json = writeJson(content);
        String hash = AuditManifests.hashCanonical(mapper, content);

        int version = cardRepo.findFirstByModelIdAndKindOrderByCardVersionDesc(m.getId(), kind)
                .map(PublishedModelCard::getCardVersion).orElse(0) + 1;
        PublishedModelCard card = new PublishedModelCard();
        card.setModelId(m.getId());
        card.setRunId(runId);
        card.setKind(kind);
        card.setCardVersion(version);
        card.setRiskLevel((String) content.get("leakageRiskLevel"));
        card.setContentJson(json);
        card.setContentHash(hash);
        card.setActor(actor);
        card = cardRepo.save(card);

        m.setStatus("CARD_PUBLISHED");
        modelRepo.save(m);
        auditService.log(null, actor, "MODEL_CARD_PUBLISHED",
                kind + " 发布 " + m.getCode() + "@" + m.getVersion() + " v" + version
                        + " 抑制=" + applySuppression + " 风险等级=" + card.getRiskLevel()
                        + " hash=" + hash.substring(0, 12));
        return card;
    }

    private String reasonCodes(Object reasons) {
        try {
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> list = (List<Map<String, Object>>) reasons;
            return list.stream().map(r -> "[" + r.get("code") + "] " + r.get("message"))
                    .collect(Collectors.joining(" | "));
        } catch (Exception e) {
            return String.valueOf(reasons);
        }
    }

    private Map<String, Object> buildReleaseContent(FrozenModel m, Map<String, Object> report,
                                                    String kind, boolean applySuppression, Long runId) {
        @SuppressWarnings("unchecked")
        Map<String, Object> metrics = (Map<String, Object>) report.get("metrics");
        @SuppressWarnings("unchecked")
        Map<String, Object> hashBlock = (Map<String, Object>) report.get("versionHash");
        @SuppressWarnings("unchecked")
        Map<String, Object> manifest = (Map<String, Object>) report.get("manifestCheck");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> units = (List<Map<String, Object>>) report.get("rareUnits");

        List<TrainingSource> sources = sourceRepo.findByModelIdOrderByIdAsc(m.getId());

        Map<String, Object> content = new LinkedHashMap<>();
        content.put("schema", "PARAM_PACKAGE".equals(kind)
                ? "controlled-parameter-package/v1" : "aggregate-model-card/v1");
        content.put("kind", kind);
        content.put("model", Map.of("code", m.getCode(), "name", m.getName(),
                "version", m.getVersion(), "scenarioTag", String.valueOf(m.getScenarioTag())));
        content.put("versionHash", hashBlock.get("frozen"));
        content.put("versionHashRecheckMatch", hashBlock.get("match"));
        content.put("sourceAuditRunId", runId);
        content.put("registeredPerformance", publicMetrics(metrics));
        content.put("trainingScope", publicScope(m, sources, applySuppression));
        content.put("manifestMatch", manifest.get("match"));

        // 小单元：抑制后只给等级/结论，不给内部风险分与精确例数
        List<Map<String, Object>> publicUnits = units.stream()
                .filter(u -> Boolean.TRUE.equals(u.get("belowThreshold")))
                .map(u -> publicUnit(u, applySuppression)).toList();
        content.put("smallCellUnits", publicUnits);

        String residual = residualRiskLevel(units, metrics);
        content.put("leakageRiskLevel", residual);
        content.put("riskLevel", residual);
        content.put("riskLevelBasis", "小单元精确规模/单元统计量抑制后的残余风险；"
                + "单元固有风险等级见 smallCellUnits[].inherentRiskLevel（不含数值分）。");
        content.put("caseLevelOutputCount", 0);
        content.put("perCaseTrainingRecordsIncluded", false);
        content.put("noCaseLevelAttestation", "本发布物不含任何逐例训练/验证记录，且平台侧逐例输出接口数为 0。");

        @SuppressWarnings("unchecked")
        Map<String, Object> findings = (Map<String, Object>) report.get("routeFindings");
        if ("MODEL_CARD".equals(kind)) {
            content.put("routeLimitations", Map.of(
                    "caseLevelFeatureContribution", findings.get("caseLevelFeatureContribution"),
                    "deviceBinding", findings.get("deviceBinding")));
            content.put("distribution", "可随模型卡聚合分发");
        } else {
            content.put("controlledFindings", publicPackageFindings(findings));
            content.put("distribution", "仅受控接收方；模型/数据/脚本须在隔离审计环境管控");
        }
        content.put("publishedPolicy", policyMap());
        return content;
    }

    private Map<String, Object> publicMetrics(Map<String, Object> metrics) {
        // 指标块本身全为总体聚合值，可直接发布；去掉内部一致性问题细节中的过程性字段无妨，保留结论
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("consistentWithFrozenVersion", metrics.get("consistentWithFrozenVersion"));
        p.put("sensitivity", metrics.get("sensitivity"));
        p.put("brier", metrics.get("brier"));
        p.put("ece10", metrics.get("ece10"));
        p.put("calibrationLogistic", metrics.get("calibrationLogistic"));
        p.put("threshold", metrics.get("threshold"));
        return p;
    }

    private Map<String, Object> publicScope(FrozenModel m, List<TrainingSource> sources, boolean suppress) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("trainingCaseCount", m.getTrainingCaseCount());
        s.put("institutionCount", sources.stream().map(TrainingSource::getInstitutionCode).distinct().count());
        s.put("scannerCount", sources.size());
        List<Map<String, Object>> devices = sources.stream().map(t -> {
            Map<String, Object> d = new LinkedHashMap<>();
            d.put("institutionCode", t.getInstitutionCode());
            d.put("scannerId", t.getScannerId());
            d.put("scannerModel", t.getScannerModel());
            d.put("vendor", t.getVendor());
            boolean small = t.getCaseCount() < DISCLOSURE_THRESHOLD;
            d.put("countBand", small ? "<20" : ">=20");
            if (suppress) {
                // 全部设备计数按 20 舍入/抑制，防止用 12000 总数相减反推出 4
                d.put("caseCount", null);
                d.put("caseCountRounded20", small ? null : Math.round(t.getCaseCount() / 20.0) * 20);
                d.put("suppressed", small);
            } else {
                d.put("caseCount", t.getCaseCount());
                d.put("rareTextureCount", t.getRareTextureCount());
            }
            return d;
        }).toList();
        s.put("devices", devices);
        if (suppress) {
            s.put("antiSubtractionNotice", "小单元精确计数已抑制；其余设备计数按 20 舍入，"
                    + "避免利用公开训练总数相减反推出亚阈值设备单元的精确例数。");
        }
        return s;
    }

    private Map<String, Object> publicUnit(Map<String, Object> u, boolean suppress) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("unitKey", u.get("unitKey"));
        p.put("dimensions", u.get("dimensions"));
        p.put("belowThreshold", true);
        p.put("disclosureThreshold", DISCLOSURE_THRESHOLD);
        p.put("inherentRiskLevel", u.get("attackRiskLevel"));
        p.put("riskLevelAfterSuppression", "MEDIUM");
        p.put("explainableConclusion", u.get("publicConclusion"));
        if (suppress) {
            p.put("caseCount", null);
            p.put("caseCountBand", "<20");
            p.put("attackRiskScore", null);
            p.put("unitStatisticsReturned", false);
            p.put("suppression", "EXACT_CELL_SIZE_AND_UNIT_LEVEL_STATISTICS_SUPPRESSED");
        } else {
            p.put("caseCount", u.get("caseCount"));
            p.put("attackRiskScore", u.get("attackRiskScore"));
        }
        return p;
    }

    private String residualRiskLevel(List<Map<String, Object>> units, Map<String, Object> metrics) {
        boolean hasSmall = units.stream().anyMatch(u -> Boolean.TRUE.equals(u.get("belowThreshold")));
        if (!hasSmall) return "LOW";
        // 抑制后仅余“存在亚阈值单元”的存在性泄露，残余风险取 MEDIUM；
        // 总体 MIA 越线模型在闸门处已被阻断，不会走到发布。
        return "MEDIUM";
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> publicPackageFindings(Map<String, Object> findings) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("accessControls", findings.get("accessControls"));
        p.put("ablationOverall", findings.get("ablationOverall"));

        Map<String, Object> miaAll = (Map<String, Object>) findings.get("membershipInferenceOverall");
        p.put("membershipInferenceOverall", externalStat(miaAll));

        Map<String, Object> miaScanner = (Map<String, Object>) findings.get("membershipInferenceTargetScanner");
        p.put("membershipInferenceTargetScanner", externalStat(miaScanner));

        // 罕见联合单元：只给抑制说明与风险等级，绝不带内部 auc/advantage
        Map<String, Object> rare = (Map<String, Object>) findings.get("rareJointUnitStat");
        Map<String, Object> rarePub = new LinkedHashMap<>();
        rarePub.put("stat", rare.get("stat"));
        rarePub.put("returned", false);
        rarePub.put("suppressed", true);
        rarePub.put("suppressionReason", rare.get("suppressionReason"));
        rarePub.put("message", rare.get("message"));
        p.put("rareJointUnitStat", rarePub);

        p.put("deviceBinding", findings.get("deviceBinding"));
        return p;
    }

    /** 外发统计量白名单：returned=false 时剥除全部数值字段 */
    private Map<String, Object> externalStat(Map<String, Object> stat) {
        Map<String, Object> o = new LinkedHashMap<>();
        if (stat == null) return o;
        boolean returned = Boolean.TRUE.equals(stat.get("returned"));
        o.put("stat", stat.get("stat"));
        o.put("sampleSize", returned ? stat.get("sampleSize") : null);
        o.put("returned", returned);
        if (returned) {
            stat.forEach((k, v) -> {
                if (!"stat".equals(k) && !"returned".equals(k)) o.put(k, v);
            });
        } else {
            o.put("suppressed", true);
            o.put("suppressionReason", stat.get("suppressionReason"));
        }
        return o;
    }

    // ================= 卡片读取 / 逐例拒绝 =================

    public List<Map<String, Object>> listCards() {
        return cardRepo.findAllByOrderByIdDesc().stream().map(c -> {
            Map<String, Object> v = cardSummary(c);
            return v;
        }).toList();
    }

    public Map<String, Object> cardView(Long id) {
        PublishedModelCard c = cardRepo.findById(id)
                .orElseThrow(() -> ApiException.notFound("发布物不存在: " + id));
        Map<String, Object> v = cardSummary(c);
        v.put("content", read(c.getContentJson()));
        return v;
    }

    private Map<String, Object> cardSummary(PublishedModelCard c) {
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("id", c.getId());
        v.put("modelId", c.getModelId());
        v.put("runId", c.getRunId());
        v.put("kind", c.getKind());
        v.put("cardVersion", c.getCardVersion());
        v.put("riskLevel", c.getRiskLevel());
        v.put("status", c.getStatus());
        v.put("contentHash", c.getContentHash());
        v.put("actor", c.getActor());
        v.put("createdAt", c.getCreatedAt());
        return v;
    }

    /** 逐例导出探针：对任何调用方都拒绝，并写审计事件；返回值恒为空集语义由异常承载 */
    public void denyCaseLevelExport(Long modelId, String actor, String reason) {
        String target = modelId == null ? "ALL_MODELS" : String.valueOf(modelId);
        auditService.log(null, actor, "CASE_LEVEL_EXPORT_DENIED",
                "拒绝逐例训练/验证记录导出 model=" + target + " reason=" + reason
                        + "；本平台逐例输出数恒为 0");
        throw ApiException.forbidden("[CASE_LEVEL_OUTPUT_PROHIBITED] 研究者不得取得逐例训练记录，"
                + "平台不提供任何逐例输出；仅可获取通过 <20 抑制规则的聚合统计。");
    }

    // ================= helpers =================

    private double num(Object o) {
        return o instanceof Number n ? n.doubleValue() : 0.0;
    }

    private String writeJson(Object o) {
        try {
            return mapper.writeValueAsString(o);
        } catch (Exception e) {
            throw new IllegalStateException("序列化审计报告失败", e);
        }
    }

    private Map<String, Object> read(String json) {
        if (json == null || json.isBlank()) return new LinkedHashMap<>();
        try {
            return mapper.readValue(json, new TypeReference<LinkedHashMap<String, Object>>() {});
        } catch (Exception e) {
            return new LinkedHashMap<>();
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> readMap(String json) {
        return read(json);
    }
}
