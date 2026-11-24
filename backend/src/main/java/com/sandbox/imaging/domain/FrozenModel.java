package com.sandbox.imaging.domain;

import jakarta.persistence.*;

/**
 * 冻结模型版本：版本哈希覆盖制品哈希、特征模式、登记指标与发布设备声明。
 * 哈希在种子时按确定性规范化 JSON 计算，审计时独立重算比对。
 */
@Entity
@Table(name = "frozen_model", indexes = {
        @Index(name = "idx_frozen_model_code_ver", columnList = "code,version", unique = true)
})
public class FrozenModel {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** 模型代号，如 MDL-Q-CHEST */
    @Column(nullable = false)
    private String code;

    @Column(nullable = false)
    private String name;

    /** 冻结版本号，如 3.1.0-frozen */
    @Column(nullable = false)
    private String version;

    /** 冻结版本哈希（sha256 of canonical manifest） */
    @Column(name = "version_hash", nullable = false, length = 64)
    private String versionHash;

    /** 模型制品（权重包）哈希 */
    @Column(name = "artifact_hash", nullable = false, length = 128)
    private String artifactHash;

    @Column(name = "source_commit", nullable = false)
    private String sourceCommit;

    @Column(name = "training_case_count", nullable = false)
    private int trainingCaseCount;

    @Column(name = "validation_case_count", nullable = false)
    private int validationCaseCount;

    /** 预登记决策阈值（敏感度在该阈值下登记） */
    @Column(name = "decision_threshold", nullable = false)
    private double decisionThreshold;

    @Column(name = "feature_schema_json", columnDefinition = "text")
    private String featureSchemaJson;

    /** 预先登记指标（冻结时登记，审计复算对照），JSON */
    @Column(name = "registered_metrics_json", nullable = false, columnDefinition = "text")
    private String registeredMetricsJson;

    /** 发布声明：声明文本 + 声明设备清单，JSON */
    @Column(name = "device_claim_json", nullable = false, columnDefinition = "text")
    private String deviceClaimJson;

    /** 演示场景标签：Q_RARE_CELL / MANIFEST_MISMATCH / ATTACK_OVER_LINE */
    @Column(name = "scenario_tag")
    private String scenarioTag;

    /** FROZEN / CARD_PUBLISHED / RELEASE_BLOCKED */
    @Column(nullable = false)
    private String status = "FROZEN";

    @Column(name = "created_at", nullable = false)
    private long createdAt = System.currentTimeMillis();

    public FrozenModel() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getCode() { return code; }
    public void setCode(String code) { this.code = code; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }
    public String getVersionHash() { return versionHash; }
    public void setVersionHash(String versionHash) { this.versionHash = versionHash; }
    public String getArtifactHash() { return artifactHash; }
    public void setArtifactHash(String artifactHash) { this.artifactHash = artifactHash; }
    public String getSourceCommit() { return sourceCommit; }
    public void setSourceCommit(String sourceCommit) { this.sourceCommit = sourceCommit; }
    public int getTrainingCaseCount() { return trainingCaseCount; }
    public void setTrainingCaseCount(int trainingCaseCount) { this.trainingCaseCount = trainingCaseCount; }
    public int getValidationCaseCount() { return validationCaseCount; }
    public void setValidationCaseCount(int validationCaseCount) { this.validationCaseCount = validationCaseCount; }
    public double getDecisionThreshold() { return decisionThreshold; }
    public void setDecisionThreshold(double decisionThreshold) { this.decisionThreshold = decisionThreshold; }
    public String getFeatureSchemaJson() { return featureSchemaJson; }
    public void setFeatureSchemaJson(String featureSchemaJson) { this.featureSchemaJson = featureSchemaJson; }
    public String getRegisteredMetricsJson() { return registeredMetricsJson; }
    public void setRegisteredMetricsJson(String registeredMetricsJson) { this.registeredMetricsJson = registeredMetricsJson; }
    public String getDeviceClaimJson() { return deviceClaimJson; }
    public void setDeviceClaimJson(String deviceClaimJson) { this.deviceClaimJson = deviceClaimJson; }
    public String getScenarioTag() { return scenarioTag; }
    public void setScenarioTag(String scenarioTag) { this.scenarioTag = scenarioTag; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }
}
