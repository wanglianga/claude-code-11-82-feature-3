package com.sandbox.imaging.modelaudit;

/** 模型审计与发布闸门策略常量 */
public final class AuditPolicy {

    private AuditPolicy() {}

    /** 联合单元披露阈值：低于 20 例必须抑制精确规模与单元统计量 */
    public static final int DISCLOSURE_THRESHOLD = 20;

    /** 小样本攻击综合风险越线值（内部 0..1），达到即禁止未抑制明细发布 */
    public static final double ATTACK_RISK_BLOCK_LINE = 0.70;

    /** 总体成员推断优势越线值（2*AUC-1），超过即判定攻击风险越线、抑制后仍阻断 */
    public static final double MIA_ADVANTAGE_LINE = 0.20;

    public static final int BOOTSTRAP_REPLICATES = 300;

    public static String riskLevel(double score) {
        if (score < 0.40) return "LOW";
        if (score < 0.60) return "MEDIUM";
        if (score < 0.80) return "HIGH";
        return "CRITICAL";
    }
}
