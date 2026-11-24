package com.sandbox.imaging.bootstrap;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sandbox.imaging.domain.AppUser;
import com.sandbox.imaging.domain.FrozenModel;
import com.sandbox.imaging.domain.TrainingSource;
import com.sandbox.imaging.domain.ValidationCase;
import com.sandbox.imaging.modelaudit.AuditManifests;
import com.sandbox.imaging.modelaudit.AuditStats;
import com.sandbox.imaging.repo.AppUserRepository;
import com.sandbox.imaging.repo.FrozenModelRepository;
import com.sandbox.imaging.repo.TrainingSourceRepository;
import com.sandbox.imaging.repo.ValidationCaseRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * 模型审计特性种子（全部为虚构数据，无真实患者/影像）：
 *
 * MDL-Q-CHEST 3.1.0：样例模型，12,000 例训练；医院 Q 唯一扫描仪 Q-AQ-07 仅 4 例、3 例罕见纹理，
 *   机构×设备单元(4) 与 机构×设备×罕见特征联合单元(3) 均低于 20 例披露阈值；设备声明与台账一致。
 * MDL-Q-CHEST 3.2.0-rc1：设备清单与发布声明不符（声明漏掉 Q-AQ-07 且虚构 GHOST-X9）=> 阻断。
 * MDL-XR-MEMO 0.9.1：成员推断优势越线的过拟合模型 => 抑制后仍阻断。
 *
 * 冻结验证集由固定种子的合成过程生成，登记指标在冻结时由同一统计引擎计算并写入登记 JSON，
 * 审计时从逐例持久化数据独立重算，因此“复算值与冻结登记一致”是可执行校验而非写死结论。
 */
@Component
@Order(20)
public class ModelAuditSeeder implements CommandLineRunner {

    private final AppUserRepository userRepo;
    private final FrozenModelRepository modelRepo;
    private final TrainingSourceRepository sourceRepo;
    private final ValidationCaseRepository caseRepo;
    private final PasswordEncoder encoder;
    private final ObjectMapper mapper;

    public ModelAuditSeeder(AppUserRepository userRepo, FrozenModelRepository modelRepo,
                            TrainingSourceRepository sourceRepo, ValidationCaseRepository caseRepo,
                            PasswordEncoder encoder, ObjectMapper mapper) {
        this.userRepo = userRepo;
        this.modelRepo = modelRepo;
        this.sourceRepo = sourceRepo;
        this.caseRepo = caseRepo;
        this.encoder = encoder;
        this.mapper = mapper;
    }

    @Override
    @Transactional
    public void run(String... args) {
        if (userRepo.findByUsername("auditor").isEmpty()) {
            userRepo.save(new AppUser("auditor", encoder.encode("auditor123"), "独立审计员", "AUDITOR"));
        }
        if (modelRepo.count() > 0) return;

        seedQModel(new QSpec(
                "MDL-Q-CHEST", "胸部 CT 结节风险模型", "3.1.0-frozen", "Q_RARE_CELL",
                2026112401L, 2400, 120, 17, 1.15, 0.85, 0.10, false,
                "a3f9c21e", "sha256:9c1f0a77b2e14d86f0a5c319e7d4b6821f0ac9e57bd346082ce117aa84b5d102"));

        seedQModel(new QSpec(
                "MDL-Q-CHEST", "胸部 CT 结节风险模型（候选）", "3.2.0-rc1", "MANIFEST_MISMATCH",
                2026112402L, 1400, 70, 11, 1.10, 0.85, 0.12, true,
                "b71d44a0", "sha256:1e77ac09d35f4b2881e60c2a94d77f03b6e21890ac55d7b64f1092fe71b09dd4"));

        seedMemoModel();
    }

    // ---------------- Q 系列：12,000 例 + 医院 Q 小联合单元 ----------------

    private record LedgerRow(String inst, String instName, String scanner, String scannerModel,
                             String vendor, int count, int rare) {}

    private List<LedgerRow> qLedger() {
        // rare 列特指本题罕见纹理 RT-HALO：该特征在 12,000 例训练中仅出现 3 次且全部在医院 Q
        return List.of(
                new LedgerRow("HOSP_A", "中心医院 A", "A-CT-01", "Revolution CT", "GE", 3800, 0),
                new LedgerRow("HOSP_A", "中心医院 A", "A-CT-02", "SOMATOM Force", "Siemens", 2600, 0),
                new LedgerRow("HOSP_A", "中心医院 A", "A-MR-01", "SIGNA Premier", "GE", 1200, 0),
                new LedgerRow("HOSP_B", "中心医院 B", "B-CT-01", "IQon Spectral CT", "Philips", 1500, 0),
                new LedgerRow("HOSP_B", "中心医院 B", "B-CT-02", "Aquilion Prime", "Canon", 900, 0),
                new LedgerRow("HOSP_C", "中心医院 C", "C-CT-01", "uCT 960+", "United Imaging", 1996, 0),
                new LedgerRow("HOSP_Q", "区人民医院 Q", "Q-AQ-07", "Aquilion Lightning", "Canon", 4, 3)
        );
    }

    private record QSpec(String code, String name, String version, String tag, long seed,
                         int nVal, int qVal, int qRareVal, double deviceShift, double rareCoef,
                         double memorization, boolean mismatchClaim,
                         String commit, String artifactHash) {}

    private void seedQModel(QSpec s) {
        FrozenModel m = baseModel(s.code(), s.name(), s.version(), s.tag(), s.commit(),
                s.artifactHash(), 12000, s.nVal());

        List<LedgerRow> rows = qLedger();
        for (LedgerRow r : rows) {
            sourceRepo.save(new TrainingSource(m.getId(), r.inst(), r.instName(), r.scanner(),
                    r.scannerModel(), r.vendor(), r.count(), r.rare(),
                    r.rare() > 0 ? "RT-HALO" : null));
        }

        // 发布设备声明：正常模型与台账一致；候选模型故意漏报 Q 并虚列设备
        List<Map<String, Object>> declared = new ArrayList<>();
        for (LedgerRow r : rows) {
            if (s.mismatchClaim() && r.scanner().equals("Q-AQ-07")) continue;
            Map<String, Object> d = new LinkedHashMap<>();
            d.put("scannerId", r.scanner());
            d.put("institutionCode", r.inst());
            d.put("vendor", r.vendor());
            d.put("scannerModel", r.scannerModel());
            declared.add(d);
        }
        if (s.mismatchClaim()) {
            Map<String, Object> ghost = new LinkedHashMap<>();
            ghost.put("scannerId", "GHOST-X9");
            ghost.put("institutionCode", "HOSP_Q");
            ghost.put("vendor", "Unknown");
            ghost.put("scannerModel", "未登记机型 X9");
            declared.add(ghost);
        }
        Map<String, Object> claim = new LinkedHashMap<>();
        claim.put("statement", s.mismatchClaim()
                ? "本模型训练设备均为主流机型，清单完整；不存在单台设备覆盖不足 20 例的情形。"
                : "设备清单与训练来源台账一致；已知 HOSP_Q / Q-AQ-07 联合单元低于 20 例披露阈值，"
                + "模型卡对该单元精确规模与统计量执行抑制，不声称已排除设备绑定效应。");
        claim.put("declaredScanners", declared);
        claim.put("acknowledgesSubThresholdUnits", !s.mismatchClaim());
        m.setDeviceClaimJson(writeJson(claim));

        List<ValidationCase> cases = generateQValidation(s);
        registerMetrics(m, cases, m.getDecisionThreshold());
        m.setVersionHash(AuditManifests.recomputeVersionHash(mapper, m));
        modelRepo.save(m);
        for (ValidationCase c : cases) c.setModelId(m.getId());
        caseRepo.saveAll(cases);
    }

    private List<ValidationCase> generateQValidation(QSpec s) {
        Random rnd = new Random(s.seed());
        List<ValidationCase> list = new ArrayList<>();
        for (int i = 0; i < s.nVal(); i++) {
            boolean q = i < s.qVal();
            // RT-HALO 在真实台账中为医院 Q 专属，验证集同样只在 Q 子组出现
            boolean rare = q && i < s.qRareVal();
            double x1 = rnd.nextGaussian();
            double x2 = rnd.nextGaussian();
            double trueLogit = -0.55 + 1.25 * x1 + 0.85 * x2 + 0.80 * (rare ? 1 : 0);
            int y = rnd.nextDouble() < sigmoid(trueLogit) ? 1 : 0;

            double predLogit = -0.57 + 1.22 * x1 + 0.87 * x2
                    + s.rareCoef() * (rare ? 1 : 0)
                    + s.deviceShift() * (q ? 1 : 0)
                    + rnd.nextGaussian() * 0.08;
            double score = sigmoid(predLogit);
            double scoreNoRare = sigmoid(predLogit - s.rareCoef() * (rare ? 1 : 0));
            double deviceSig = q ? 2.05 + rnd.nextGaussian() * 0.40 : rnd.nextGaussian() * 0.55;

            boolean member = (i % 2 == 0);
            double ll = -(y == 1 ? Math.log(Math.max(1e-6, score)) : Math.log(Math.max(1e-6, 1 - score)));
            double miaLoss = ll + rnd.nextGaussian() * 0.01;
            if (member) {
                miaLoss -= s.memorization() * 0.45;
                if (rare) miaLoss -= 0.22 + 0.10 * s.memorization();
            }

            ValidationCase c = new ValidationCase();
            c.setCaseKey(String.format("V-Q-%05d", i + 1));
            c.setYTrue(y);
            c.setScore(AuditStats.round(score, 6));
            c.setScoreWithoutRare(AuditStats.round(scoreNoRare, 6));
            c.setRareTexture(rare);
            c.setInstitutionCode(q ? "HOSP_Q" : pickOtherInst(i, rnd));
            c.setScannerId(q ? "Q-AQ-07" : pickOtherScanner(i, rnd));
            c.setDeviceSignature(AuditStats.round(deviceSig, 6));
            c.setMemberFlag(member);
            c.setMiaLoss(AuditStats.round(Math.max(0.001, miaLoss), 6));
            list.add(c);
        }
        return list;
    }

    private String pickOtherInst(int i, Random rnd) {
        int b = rnd.nextInt(100);
        if (b < 42) return "HOSP_A";
        if (b < 64) return "HOSP_B";
        return "HOSP_C";
    }

    private String pickOtherScanner(int i, Random rnd) {
        int b = rnd.nextInt(6);
        return switch (b) {
            case 0 -> "A-CT-01";
            case 1 -> "A-CT-02";
            case 2 -> "A-MR-01";
            case 3 -> "B-CT-01";
            case 4 -> "B-CT-02";
            default -> "C-CT-01";
        };
    }

    // ---------------- M3：成员推断越线模型 ----------------

    private void seedMemoModel() {
        FrozenModel m = baseModel("MDL-XR-MEMO", "数字化 X 光辅助筛查模型（过拟合候选）",
                "0.9.1-rc2", "ATTACK_OVER_LINE", "c52e88b1",
                "sha256:5ab21f90d77c4e6aa12f90c77d315b6e8a02c449fd7106b3a2e55cc8019dd2aa",
                4406, 1600);
        List<LedgerRow> rows = List.of(
                new LedgerRow("HOSP_D", "人民医院 D", "D-DR-01", "DigitalDiagnost", "Philips", 2600, 8),
                new LedgerRow("HOSP_E", "人民医院 E", "E-DR-01", "Discovery XR656", "GE", 1800, 5),
                new LedgerRow("HOSP_R", "偏远卫生院 R", "R-DR-02", "低价国产 DR", "OEM", 6, 5)
        );
        for (LedgerRow r : rows) {
            sourceRepo.save(new TrainingSource(m.getId(), r.inst(), r.instName(), r.scanner(),
                    r.scannerModel(), r.vendor(), r.count(), r.rare(), "RT-TEXTURE-OTHER"));
        }
        List<Map<String, Object>> declared = new ArrayList<>();
        for (LedgerRow r : rows) {
            Map<String, Object> d = new LinkedHashMap<>();
            d.put("scannerId", r.scanner());
            d.put("institutionCode", r.inst());
            d.put("vendor", r.vendor());
            d.put("scannerModel", r.scannerModel());
            declared.add(d);
        }
        Map<String, Object> claim = new LinkedHashMap<>();
        claim.put("statement", "设备清单与台账一致。");
        claim.put("declaredScanners", declared);
        claim.put("acknowledgesSubThresholdUnits", true);
        m.setDeviceClaimJson(writeJson(claim));

        Random rnd = new Random(2026112403L);
        List<ValidationCase> cases = new ArrayList<>();
        int n = 1600;
        for (int i = 0; i < n; i++) {
            boolean rUnit = i < 60;
            boolean rare = rUnit ? i < 13 : rnd.nextDouble() < 0.03;
            double x1 = rnd.nextGaussian();
            double trueLogit = -0.55 + 0.9 * x1 + 0.7 * (rare ? 1 : 0);
            int y = rnd.nextDouble() < sigmoid(trueLogit) ? 1 : 0;
            double predLogit = trueLogit + rnd.nextGaussian() * 0.05; // 过拟合：异常自信
            double score = sigmoid(predLogit);
            boolean member = i % 2 == 0;
            double ll = -(y == 1 ? Math.log(Math.max(1e-6, score)) : Math.log(Math.max(1e-6, 1 - score)));
            double miaLoss = ll + rnd.nextGaussian() * 0.008;
            if (member) miaLoss -= 0.46; // 强成员信号 => 总体 MIA 优势越线
            if (member && rare) miaLoss -= 0.2;
            ValidationCase c = new ValidationCase();
            c.setCaseKey(String.format("V-M-%05d", i + 1));
            c.setYTrue(y);
            c.setScore(AuditStats.round(score, 6));
            c.setScoreWithoutRare(AuditStats.round(sigmoid(predLogit - 0.7 * (rare ? 1 : 0)), 6));
            c.setRareTexture(rare);
            c.setInstitutionCode(rUnit ? "HOSP_R" : (rnd.nextBoolean() ? "HOSP_D" : "HOSP_E"));
            c.setScannerId(rUnit ? "R-DR-02" : (rnd.nextBoolean() ? "D-DR-01" : "E-DR-01"));
            c.setDeviceSignature(rUnit ? 1.8 + rnd.nextGaussian() * 0.6 : rnd.nextGaussian() * 0.8);
            c.setMemberFlag(member);
            c.setMiaLoss(AuditStats.round(Math.max(0.001, miaLoss), 6));
            cases.add(c);
        }
        registerMetrics(m, cases, m.getDecisionThreshold());
        m.setVersionHash(AuditManifests.recomputeVersionHash(mapper, m));
        modelRepo.save(m);
        for (ValidationCase c : cases) c.setModelId(m.getId());
        caseRepo.saveAll(cases);
    }

    // ---------------- 公共构造 ----------------

    private FrozenModel baseModel(String code, String name, String version, String tag,
                                  String commit, String artifactHash, int trainCount, int valCount) {
        FrozenModel m = new FrozenModel();
        m.setCode(code);
        m.setName(name);
        m.setVersion(version);
        m.setScenarioTag(tag);
        m.setSourceCommit(commit);
        m.setArtifactHash(artifactHash);
        m.setTrainingCaseCount(trainCount);
        m.setValidationCaseCount(valCount);
        m.setDecisionThreshold(0.4);
        List<String> schema = List.of("lesion_count", "max_mm", "density_score",
                "texture_rt_halo", "scanner_signature_v3");
        m.setFeatureSchemaJson(writeJson(Map.of("schemaVersion", "fs-3", "features", schema)));
        m.setRegisteredMetricsJson("{}");
        m.setDeviceClaimJson("{}");
        // 先保存以取得 id（台账需要外键）；登记指标与声明随后回填并重算哈希
        m.setVersionHash("pending");
        return modelRepo.saveAndFlush(m);
    }

    private void registerMetrics(FrozenModel m, List<ValidationCase> cases, double threshold) {
        List<Double> scores = cases.stream().map(ValidationCase::getScore).toList();
        List<Integer> ys = cases.stream().map(ValidationCase::getYTrue).toList();
        int[] cm = AuditStats.confusion(scores, ys, threshold);
        int tp = cm[0], fn = cm[3];
        double sens = AuditStats.round((double) tp / Math.max(1, tp + fn), 4);
        AuditStats.Ci sensCi = AuditStats.wilson(tp, tp + fn, 1.96);
        double brier = AuditStats.round(AuditStats.brier(scores, ys), 4);
        double ece = AuditStats.round(AuditStats.ece(scores, ys, 10), 4);
        double[] cal = AuditStats.logisticCalibration(scores, ys);

        Map<String, Object> reg = new LinkedHashMap<>();
        reg.put("decisionThreshold", threshold);
        Map<String, Object> sensitivity = new LinkedHashMap<>();
        sensitivity.put("value", sens);
        sensitivity.put("tp", tp);
        sensitivity.put("fn", fn);
        sensitivity.put("wilson95", List.of(sensCi.low(), sensCi.high()));
        reg.put("sensitivity", sensitivity);
        Map<String, Object> calib = new LinkedHashMap<>();
        calib.put("brier", brier);
        calib.put("ece10", ece);
        calib.put("intercept", AuditStats.round(cal[0], 4));
        calib.put("slope", AuditStats.round(cal[1], 4));
        reg.put("calibration", calib);
        // 预登记可接受准则
        reg.put("acceptance", Map.of(
                "sensitivityTolerance", 0.01,
                "brierTolerance", 0.01,
                "eceTolerance", 0.02,
                "maxEce", 0.08));
        m.setRegisteredMetricsJson(writeJson(reg));
    }

    private String writeJson(Object o) {
        try {
            return mapper.writeValueAsString(o);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static double sigmoid(double z) {
        return 1 / (1 + Math.exp(-z));
    }
}
