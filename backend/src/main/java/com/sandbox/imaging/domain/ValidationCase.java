package com.sandbox.imaging.domain;

import jakarta.persistence.*;

/**
 * 冻结验证集的逐例记录（服务端内部）。
 * 仅允许审计计算引擎在隔离审计流程中读取，任何 REST 响应/发布物都不得包含逐例数据：
 * 平台不存在返回本实体的接口，逐例导出探针接口对所有调用方拒绝并留痕。
 */
@Entity
@Table(name = "validation_case", indexes = {
        @Index(name = "idx_validation_case_model", columnList = "model_id")
})
public class ValidationCase {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "model_id", nullable = false)
    private Long modelId;

    /** 虚构验证例键，不对应任何真实患者 */
    @Column(name = "case_key", nullable = false)
    private String caseKey;

    /** 冻结标签：1=阳性（如恶性/事件），0=阴性 */
    @Column(name = "y_true", nullable = false)
    private int yTrue;

    /** 冻结模型在预登记阈值前输出的概率分 */
    @Column(name = "score", nullable = false)
    private double score;

    /** 删去罕见纹理特征贡献后的消融分数（受控参数包路线使用） */
    @Column(name = "score_without_rare", nullable = false)
    private double scoreWithoutRare;

    @Column(name = "rare_texture", nullable = false)
    private boolean rareTexture;

    @Column(name = "institution_code", nullable = false)
    private String institutionCode;

    @Column(name = "scanner_id", nullable = false)
    private String scannerId;

    /** 设备签名特征（扫描仪相关的结构化取值，用于设备绑定探针） */
    @Column(name = "device_signature", nullable = false)
    private double deviceSignature;

    /** 成员推断实验中的成员标记（隔离环境影子实验数据，不对外逐例提供） */
    @Column(name = "member_flag", nullable = false)
    private boolean memberFlag;

    /** 成员推断实验使用的逐例损失（越低越像训练成员） */
    @Column(name = "mia_loss", nullable = false)
    private double miaLoss;

    public ValidationCase() {}

    public Long getId() { return id; }
    public Long getModelId() { return modelId; }
    public void setModelId(Long modelId) { this.modelId = modelId; }
    public String getCaseKey() { return caseKey; }
    public void setCaseKey(String caseKey) { this.caseKey = caseKey; }
    public int getYTrue() { return yTrue; }
    public void setYTrue(int yTrue) { this.yTrue = yTrue; }
    public double getScore() { return score; }
    public void setScore(double score) { this.score = score; }
    public double getScoreWithoutRare() { return scoreWithoutRare; }
    public void setScoreWithoutRare(double scoreWithoutRare) { this.scoreWithoutRare = scoreWithoutRare; }
    public boolean isRareTexture() { return rareTexture; }
    public void setRareTexture(boolean rareTexture) { this.rareTexture = rareTexture; }
    public String getInstitutionCode() { return institutionCode; }
    public void setInstitutionCode(String institutionCode) { this.institutionCode = institutionCode; }
    public String getScannerId() { return scannerId; }
    public void setScannerId(String scannerId) { this.scannerId = scannerId; }
    public double getDeviceSignature() { return deviceSignature; }
    public void setDeviceSignature(double deviceSignature) { this.deviceSignature = deviceSignature; }
    public boolean isMemberFlag() { return memberFlag; }
    public void setMemberFlag(boolean memberFlag) { this.memberFlag = memberFlag; }
    public double getMiaLoss() { return miaLoss; }
    public void setMiaLoss(double miaLoss) { this.miaLoss = miaLoss; }
}
