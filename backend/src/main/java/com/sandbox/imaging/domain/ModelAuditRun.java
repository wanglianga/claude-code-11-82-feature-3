package com.sandbox.imaging.domain;

import jakarta.persistence.*;

/**
 * 一次模型审计运行（聚合模型卡路线 MODEL_CARD 或受控参数包路线 PARAM_PACKAGE）。
 * reportJson 保存完整审计报告（审计员可见，含内部精确值），reportHash 冻结报告完整性。
 */
@Entity
@Table(name = "model_audit_run", indexes = {
        @Index(name = "idx_audit_run_model", columnList = "model_id"),
        @Index(name = "idx_audit_run_created", columnList = "created_at")
})
public class ModelAuditRun {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "model_id", nullable = false)
    private Long modelId;

    /** MODEL_CARD / PARAM_PACKAGE */
    @Column(nullable = false)
    private String route;

    @Column(nullable = false)
    private String actor;

    @Column(name = "hash_frozen", length = 64)
    private String hashFrozen;

    @Column(name = "hash_recomputed", length = 64)
    private String hashRecomputed;

    @Column(name = "hash_match", nullable = false)
    private boolean hashMatch;

    /** RELEASABLE / BLOCKED —— 针对该路线“默认抑制后发布物”的闸门结论 */
    @Column(nullable = false)
    private String decision;

    @Column(name = "report_json", nullable = false, columnDefinition = "text")
    private String reportJson;

    @Column(name = "report_hash", nullable = false, length = 64)
    private String reportHash;

    @Column(name = "created_at", nullable = false)
    private long createdAt = System.currentTimeMillis();

    public ModelAuditRun() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public Long getModelId() { return modelId; }
    public void setModelId(Long modelId) { this.modelId = modelId; }
    public String getRoute() { return route; }
    public void setRoute(String route) { this.route = route; }
    public String getActor() { return actor; }
    public void setActor(String actor) { this.actor = actor; }
    public String getHashFrozen() { return hashFrozen; }
    public void setHashFrozen(String hashFrozen) { this.hashFrozen = hashFrozen; }
    public String getHashRecomputed() { return hashRecomputed; }
    public void setHashRecomputed(String hashRecomputed) { this.hashRecomputed = hashRecomputed; }
    public boolean isHashMatch() { return hashMatch; }
    public void setHashMatch(boolean hashMatch) { this.hashMatch = hashMatch; }
    public String getDecision() { return decision; }
    public void setDecision(String decision) { this.decision = decision; }
    public String getReportJson() { return reportJson; }
    public void setReportJson(String reportJson) { this.reportJson = reportJson; }
    public String getReportHash() { return reportHash; }
    public void setReportHash(String reportHash) { this.reportHash = reportHash; }
    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }
}
