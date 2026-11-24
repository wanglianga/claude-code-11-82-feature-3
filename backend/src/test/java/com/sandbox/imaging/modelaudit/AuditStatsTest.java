package com.sandbox.imaging.modelaudit;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AuditStatsTest {

    @Test
    void wilsonIntervalContainsProportionAndIsBounded() {
        AuditStats.Ci ci = AuditStats.wilson(86, 100, 1.96);
        assertTrue(ci.low() < 0.86 && 0.86 < ci.high(), ci.toString());
        assertTrue(ci.low() >= 0 && ci.high() <= 1);
        AuditStats.Ci zero = AuditStats.wilson(0, 10, 1.96);
        assertEquals(0.0, zero.low());
        assertTrue(zero.high() > 0);
    }

    @Test
    void sensitivityAtThresholdCountsTpAndFn() {
        // 阳性 0.9/0.4（一击一中漏），阴性 0.6/0.1（一假阳一真阴）
        List<Double> scores = List.of(0.9, 0.4, 0.6, 0.1);
        List<Integer> ys = List.of(1, 1, 0, 0);
        assertEquals(0.5, AuditStats.sensitivity(scores, ys, 0.5), 1e-9);
        int[] cm = AuditStats.confusion(scores, ys, 0.5);
        assertArrayEquals(new int[]{1, 1, 1, 1}, cm);
    }

    @Test
    void aucPerfectAndTied() {
        List<Double> perfectScores = List.of(0.9, 0.8, 0.2, 0.1);
        List<Integer> ys = List.of(1, 1, 0, 0);
        assertEquals(1.0, AuditStats.auc(perfectScores, ys), 1e-9);

        List<Double> tied = List.of(0.5, 0.5, 0.5, 0.5);
        assertEquals(0.5, AuditStats.auc(tied, ys), 1e-9);

        // 反向排序 => AUC 0
        List<Double> reverse = List.of(0.1, 0.2, 0.8, 0.9);
        assertEquals(0.0, AuditStats.auc(reverse, ys), 1e-9);
    }

    @Test
    void brierAndEceAreNonNegativeAndFinite() {
        List<Double> scores = new ArrayList<>();
        List<Integer> ys = new ArrayList<>();
        for (int i = 0; i < 200; i++) {
            double p = (i % 10) / 10.0;
            scores.add(p);
            ys.add(i % 3 == 0 ? 1 : 0);
        }
        double brier = AuditStats.brier(scores, ys);
        double ece = AuditStats.ece(scores, ys, 10);
        assertTrue(brier >= 0 && brier <= 1);
        assertTrue(ece >= 0 && ece <= 1);
    }

    @Test
    void logisticCalibrationRecoversKnownCalibratedCurve() {
        // 构造近似 logit 线性校准数据：y ~ sigmoid(logit(p))，理想截距 0、斜率 1
        List<Double> scores = new ArrayList<>();
        List<Integer> ys = new ArrayList<>();
        java.util.Random rnd = new java.util.Random(42);
        for (int i = 0; i < 4000; i++) {
            double z = -2.5 + 5.0 * rnd.nextDouble();
            double p = 1 / (1 + Math.exp(-z));
            scores.add(p);
            ys.add(rnd.nextDouble() < p ? 1 : 0);
        }
        double[] cal = AuditStats.logisticCalibration(scores, ys);
        assertEquals(0.0, cal[0], 0.15, "intercept should be near 0");
        assertEquals(1.0, cal[1], 0.2, "slope should be near 1");
    }

    @Test
    void policyThresholdsMatchDisclosureRule() {
        assertEquals(20, AuditPolicy.DISCLOSURE_THRESHOLD);
        assertEquals("CRITICAL", AuditPolicy.riskLevel(0.9));
        assertEquals("MEDIUM", AuditPolicy.riskLevel(0.5));
        assertEquals("LOW", AuditPolicy.riskLevel(0.1));
    }
}
