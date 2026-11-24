package com.sandbox.imaging.domain;

import jakarta.persistence.*;

/**
 * 训练来源 / 设备范围账（审计侧内部台账，含精确计数）。
 * 典型小联合单元：医院 Q 的唯一一台扫描仪 Q-AQ-07 仅覆盖 4 例，其中 3 例带罕见纹理 RT-HALO。
 * 对研究者/发布物只输出分桶（>=20 / <20），不输出可被总数相减的精确计数。
 */
@Entity
@Table(name = "training_source", indexes = {
        @Index(name = "idx_training_source_model", columnList = "model_id")
})
public class TrainingSource {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "model_id", nullable = false)
    private Long modelId;

    @Column(name = "institution_code", nullable = false)
    private String institutionCode;

    @Column(name = "institution_name", nullable = false)
    private String institutionName;

    @Column(name = "scanner_id", nullable = false)
    private String scannerId;

    @Column(name = "scanner_model")
    private String scannerModel;

    @Column
    private String vendor;

    /** 该机构×设备单元覆盖的训练例数（内部精确值） */
    @Column(name = "case_count", nullable = false)
    private int caseCount;

    /** 其中带罕见纹理特征的例数 */
    @Column(name = "rare_texture_count", nullable = false)
    private int rareTextureCount;

    @Column(name = "rare_feature_code")
    private String rareFeatureCode;

    public TrainingSource() {}

    public TrainingSource(Long modelId, String institutionCode, String institutionName,
                          String scannerId, String scannerModel, String vendor,
                          int caseCount, int rareTextureCount, String rareFeatureCode) {
        this.modelId = modelId;
        this.institutionCode = institutionCode;
        this.institutionName = institutionName;
        this.scannerId = scannerId;
        this.scannerModel = scannerModel;
        this.vendor = vendor;
        this.caseCount = caseCount;
        this.rareTextureCount = rareTextureCount;
        this.rareFeatureCode = rareFeatureCode;
    }

    public Long getId() { return id; }
    public Long getModelId() { return modelId; }
    public String getInstitutionCode() { return institutionCode; }
    public String getInstitutionName() { return institutionName; }
    public String getScannerId() { return scannerId; }
    public String getScannerModel() { return scannerModel; }
    public String getVendor() { return vendor; }
    public int getCaseCount() { return caseCount; }
    public int getRareTextureCount() { return rareTextureCount; }
    public String getRareFeatureCode() { return rareFeatureCode; }
}
