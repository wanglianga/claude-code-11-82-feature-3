package com.sandbox.imaging.modelaudit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sandbox.imaging.common.CanonicalJson;
import com.sandbox.imaging.domain.FrozenModel;

import java.util.LinkedHashMap;
import java.util.Map;

/** 冻结模型版本哈希清单：种子方与审计服务必须以完全相同的字段集合重建，保证哈希可复算 */
public final class AuditManifests {

    private AuditManifests() {}

    public static Map<String, Object> manifestMap(ObjectMapper mapper, FrozenModel m) {
        Map<String, Object> manifest = new LinkedHashMap<>();
        manifest.put("code", m.getCode());
        manifest.put("name", m.getName());
        manifest.put("version", m.getVersion());
        manifest.put("artifactHash", m.getArtifactHash());
        manifest.put("sourceCommit", m.getSourceCommit());
        manifest.put("trainingCaseCount", m.getTrainingCaseCount());
        manifest.put("validationCaseCount", m.getValidationCaseCount());
        manifest.put("decisionThreshold", m.getDecisionThreshold());
        manifest.put("featureSchema", readTree(mapper, m.getFeatureSchemaJson()));
        manifest.put("registeredMetrics", readTree(mapper, m.getRegisteredMetricsJson()));
        manifest.put("deviceClaim", readTree(mapper, m.getDeviceClaimJson()));
        return manifest;
    }

    public static String recomputeVersionHash(ObjectMapper mapper, FrozenModel m) {
        return CanonicalJson.sha256(CanonicalJson.write(mapper, manifestMap(mapper, m)));
    }

    public static String hashCanonical(ObjectMapper mapper, Object value) {
        return CanonicalJson.sha256(CanonicalJson.write(mapper, value));
    }

    private static JsonNode readTree(ObjectMapper mapper, String json) {
        try {
            return json == null ? mapper.nullNode() : mapper.readTree(json);
        } catch (Exception e) {
            throw new IllegalStateException("解析冻结 JSON 失败", e);
        }
    }
}
