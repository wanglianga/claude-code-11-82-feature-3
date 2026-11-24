package com.sandbox.imaging.modelaudit;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * 模型审计统计原语（纯函数、确定性）：
 * 敏感度 + Wilson 95% 区间、ROC-AUC（秩和法，并列取半）、Brier、ECE、
 * 校准截距/斜率（IRLS logistic），以及固定种子 bootstrap 区间。
 */
public final class AuditStats {

    private AuditStats() {}

    public record Ci(double low, double high) {}

    /** Wilson 二项比例区间 */
    public static Ci wilson(int k, int n, double z) {
        if (n == 0) return new Ci(0, 0);
        double phat = (double) k / n;
        double z2 = z * z;
        double denom = 1 + z2 / n;
        double center = (phat + z2 / (2 * n)) / denom;
        double margin = (z * Math.sqrt(phat * (1 - phat) / n + z2 / (4 * n * n))) / denom;
        return new Ci(round(center - margin, 6), round(center + margin, 6));
    }

    public static double sensitivity(List<Double> scores, List<Integer> ys, double threshold) {
        int tp = 0, fn = 0;
        for (int i = 0; i < scores.size(); i++) {
            if (ys.get(i) == 1) {
                if (scores.get(i) >= threshold) tp++; else fn++;
            }
        }
        return tp + fn == 0 ? 0 : (double) tp / (tp + fn);
    }

    public static int[] confusion(List<Double> scores, List<Integer> ys, double threshold) {
        int tp = 0, fp = 0, tn = 0, fn = 0;
        for (int i = 0; i < scores.size(); i++) {
            boolean pred = scores.get(i) >= threshold;
            boolean pos = ys.get(i) == 1;
            if (pred && pos) tp++;
            else if (pred) fp++;
            else if (pos) fn++;
            else tn++;
        }
        return new int[]{tp, fp, tn, fn};
    }

    public static double brier(List<Double> scores, List<Integer> ys) {
        double sum = 0;
        for (int i = 0; i < scores.size(); i++) {
            double d = scores.get(i) - ys.get(i);
            sum += d * d;
        }
        return sum / scores.size();
    }

    /** 10 等宽箱期望校准误差 */
    public static double ece(List<Double> scores, List<Integer> ys, int bins) {
        double ece = 0;
        int n = scores.size();
        for (int b = 0; b < bins; b++) {
            double lo = (double) b / bins, hi = (b + 1.0) / bins;
            int cnt = 0, ySum = 0;
            double pSum = 0;
            for (int i = 0; i < n; i++) {
                double p = scores.get(i);
                boolean in = (b == bins - 1) ? (p >= lo && p <= hi) : (p >= lo && p < hi);
                if (in) { cnt++; ySum += ys.get(i); pSum += p; }
            }
            if (cnt > 0) {
                ece += (double) cnt / n * Math.abs(pSum / cnt - (double) ySum / cnt);
            }
        }
        return ece;
    }

    /** ROC-AUC：正例分数大于负例的概率，并列计 0.5 */
    public static double auc(List<Double> scores, List<Integer> ys) {
        int n = scores.size();
        List<Integer> order = new ArrayList<>();
        for (int i = 0; i < n; i++) order.add(i);
        order.sort((a, b) -> Double.compare(scores.get(a), scores.get(b)));

        double[] ranks = new double[n];
        int i = 0;
        while (i < n) {
            int j = i;
            while (j + 1 < n && scores.get(order.get(j + 1)).equals(scores.get(order.get(i)))) j++;
            double avgRank = (i + j) / 2.0 + 1; // 1-based 平均秩
            for (int k = i; k <= j; k++) ranks[order.get(k)] = avgRank;
            i = j + 1;
        }
        double rankSumPos = 0;
        int nPos = 0, nNeg = 0;
        for (int idx = 0; idx < n; idx++) {
            if (ys.get(idx) == 1) { rankSumPos += ranks[idx]; nPos++; }
            else nNeg++;
        }
        if (nPos == 0 || nNeg == 0) return Double.NaN;
        double u = rankSumPos - (double) nPos * (nPos + 1) / 2;
        return u / ((double) nPos * nNeg);
    }

    /**
     * 校准模型 logit(P(Y=1)) = a + b * logit(score) 的 (截距 a, 斜率 b, 截距SE, 斜率SE)。
     * IRLS/Newton 迭代，带微小 ridge 保证可收敛。
     */
    public static double[] logisticCalibration(List<Double> scores, List<Integer> ys) {
        int n = scores.size();
        double[] x = new double[n];
        for (int i = 0; i < n; i++) {
            double p = Math.min(1 - 1e-6, Math.max(1e-6, scores.get(i)));
            x[i] = Math.log(p / (1 - p));
        }
        double a = 0, b = 1;
        for (int iter = 0; iter < 50; iter++) {
            double g0 = 0, g1 = 0, h00 = 1e-8, h01 = 0, h11 = 1e-8;
            for (int i = 0; i < n; i++) {
                double eta = a + b * x[i];
                double p = 1 / (1 + Math.exp(-eta));
                double w = Math.max(1e-9, p * (1 - p));
                double err = ys.get(i) - p;
                g0 += err;
                g1 += err * x[i];
                h00 += w;
                h01 += w * x[i];
                h11 += w * x[i] * x[i];
            }
            double det = h00 * h11 - h01 * h01;
            double da = (h11 * g0 - h01 * g1) / det;
            double db = (-h01 * g0 + h00 * g1) / det;
            a += da;
            b += db;
            if (Math.abs(da) < 1e-9 && Math.abs(db) < 1e-9) break;
        }
        // 终态 Hessian 逆 => 标准误
        double h00 = 1e-8, h01 = 0, h11 = 1e-8;
        for (int i = 0; i < n; i++) {
            double eta = a + b * x[i];
            double p = 1 / (1 + Math.exp(-eta));
            double w = Math.max(1e-9, p * (1 - p));
            h00 += w; h01 += w * x[i]; h11 += w * x[i] * x[i];
        }
        double det = h00 * h11 - h01 * h01;
        double seA = Math.sqrt(h11 / det);
        double seB = Math.sqrt(h00 / det);
        return new double[]{round(a, 6), round(b, 6), round(seA, 6), round(seB, 6)};
    }

    public record BootstrapCi(double low, double high, double point) {}

    /** 固定种子 bootstrap 百分位区间（对样本索引有放回重采样） */
    public static BootstrapCi bootstrapCi(List<Double> scores, List<Integer> ys,
                                          java.util.function.ToDoubleBiFunction<List<Double>, List<Integer>> stat,
                                          int replicates, long seed) {
        int n = scores.size();
        double point = stat.applyAsDouble(scores, ys);
        Random rnd = new Random(seed);
        double[] vals = new double[replicates];
        for (int r = 0; r < replicates; r++) {
            List<Double> ss = new ArrayList<>(n);
            List<Integer> yy = new ArrayList<>(n);
            for (int j = 0; j < n; j++) {
                int idx = rnd.nextInt(n);
                ss.add(scores.get(idx));
                yy.add(ys.get(idx));
            }
            vals[r] = stat.applyAsDouble(ss, yy);
        }
        java.util.Arrays.sort(vals);
        double low = vals[(int) Math.floor(0.025 * (replicates - 1))];
        double high = vals[(int) Math.ceil(0.975 * (replicates - 1))];
        return new BootstrapCi(round(low, 6), round(high, 6), round(point, 6));
    }

    public static double round(double v, int digits) {
        if (Double.isNaN(v) || Double.isInfinite(v)) return v;
        double f = Math.pow(10, digits);
        return Math.round(v * f) / f;
    }
}
