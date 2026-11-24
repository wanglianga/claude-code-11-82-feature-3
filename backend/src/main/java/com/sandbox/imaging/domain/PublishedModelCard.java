package com.sandbox.imaging.domain;

import jakarta.persistence.*;

/**
 * 已发布的聚合模型卡 / 受控参数包（内容已经过小单元抑制，可对研究者分发）。
 * contentHash 为发布物规范化 JSON 的 sha256，供分发后核验未被改写。
 */
@Entity
@Table(name = "published_model_card", indexes = {
        @Index(name = "idx_published_card_model", columnList = "model_id")
})
public class PublishedModelCard {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "model_id", nullable = false)
    private Long modelId;

    @Column(name = "run_id", nullable = false)
    private Long runId;

    /** MODEL_CARD / PARAM_PACKAGE */
    @Column(nullable = false)
    private String kind;

    @Column(name = "card_version", nullable = false)
    private int cardVersion;

    @Column(name = "risk_level", nullable = false)
    private String riskLevel;

    @Column(nullable = false)
    private String status = "PUBLISHED";

    @Column(name = "content_json", nullable = false, columnDefinition = "text")
    private String contentJson;

    @Column(name = "content_hash", nullable = false, length = 64)
    private String contentHash;

    @Column(nullable = false)
    private String actor;

    @Column(name = "created_at", nullable = false)
    private long createdAt = System.currentTimeMillis();

    public PublishedModelCard() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public Long getModelId() { return modelId; }
    public void setModelId(Long modelId) { this.modelId = modelId; }
    public Long getRunId() { return runId; }
    public void setRunId(Long runId) { this.runId = runId; }
    public String getKind() { return kind; }
    public void setKind(String kind) { this.kind = kind; }
    public int getCardVersion() { return cardVersion; }
    public void setCardVersion(int cardVersion) { this.cardVersion = cardVersion; }
    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public String getContentJson() { return contentJson; }
    public void setContentJson(String contentJson) { this.contentJson = contentJson; }
    public String getContentHash() { return contentHash; }
    public void setContentHash(String contentHash) { this.contentHash = contentHash; }
    public String getActor() { return actor; }
    public void setActor(String actor) { this.actor = actor; }
    public long getCreatedAt() { return createdAt; }
}
