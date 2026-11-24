package com.sandbox.imaging.web;

import com.sandbox.imaging.domain.ModelAuditRun;
import com.sandbox.imaging.domain.PublishedModelCard;
import com.sandbox.imaging.modelaudit.ModelAuditService;
import com.sandbox.imaging.security.SecurityUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 模型审计 / 模型卡 REST API。
 * 读模型与已发布模型卡：所有登录用户（研究者看到抑制/脱敏视图）。
 * 运行审计、读取完整审计报告、发布：仅 AUDITOR / ADMIN（在 SecurityConfig 中限定）。
 * 逐例导出探针：对所有角色拒绝。
 */
@RestController
public class ModelAuditController {

    private final ModelAuditService auditService;

    public ModelAuditController(ModelAuditService auditService) {
        this.auditService = auditService;
    }

    // ---------- 冻结模型版本与台账 ----------

    @GetMapping("/api/model-audit/models")
    public List<Map<String, Object>> models() {
        return auditService.listModels();
    }

    @GetMapping("/api/model-audit/models/{id}")
    public Map<String, Object> model(@PathVariable Long id, Authentication auth) {
        return auditService.modelDetail(id, privileged(auth));
    }

    @GetMapping("/api/model-audit/models/{id}/ledger")
    public Map<String, Object> ledger(@PathVariable Long id, Authentication auth) {
        Map<String, Object> detail = auditService.modelDetail(id, privileged(auth));
        return Map.of("modelId", id, "viewerPrivileged", detail.get("viewerPrivileged"),
                "policy", detail.get("policy"), "ledger", detail.get("ledger"));
    }

    // ---------- 审计运行（审计员/管理员） ----------

    @PostMapping("/api/model-audit/models/{id}/runs")
    public Map<String, Object> run(@PathVariable Long id, @RequestBody Map<String, String> body) {
        String route = body.getOrDefault("route", "MODEL_CARD");
        ModelAuditRun run = auditService.runAudit(id, route, SecurityUtils.currentUser());
        return auditService.runView(run.getId());
    }

    @GetMapping("/api/model-audit/runs")
    public List<Map<String, Object>> runs() {
        return auditService.listRuns().stream().map(r -> auditService.runView(r.getId())).toList();
    }

    @GetMapping("/api/model-audit/runs/{id}")
    public Map<String, Object> runDetail(@PathVariable Long id) {
        return auditService.runView(id);
    }

    @PostMapping("/api/model-audit/runs/{id}/publish")
    public Map<String, Object> publish(@PathVariable Long id, @RequestBody(required = false) Map<String, Object> body) {
        boolean suppress = body == null || !Boolean.FALSE.equals(body.get("applySuppression"));
        String kind = body == null ? null : (String) body.get("kind");
        PublishedModelCard card = auditService.publish(id, suppress, kind, SecurityUtils.currentUser());
        return auditService.cardView(card.getId());
    }

    // ---------- 已发布模型卡 / 参数包（研究者可读，内容已抑制） ----------

    @GetMapping("/api/model-audit/cards")
    public List<Map<String, Object>> cards() {
        return auditService.listCards();
    }

    @GetMapping("/api/model-audit/cards/{id}")
    public Map<String, Object> card(@PathVariable Long id) {
        return auditService.cardView(id);
    }

    /** 语义化别名：/api/model-cards */
    @GetMapping("/api/model-cards")
    public List<Map<String, Object>> modelCardsAlias() {
        return auditService.listCards();
    }

    @GetMapping("/api/model-cards/{id}")
    public Map<String, Object> modelCardAlias(@PathVariable Long id) {
        return auditService.cardView(id);
    }

    // ---------- 逐例输出：不存在可取数接口，探针一律拒绝并留痕 ----------

    @GetMapping("/api/model-audit/cases")
    public Map<String, Object> listCasesDenied() {
        auditService.denyCaseLevelExport(null, SecurityUtils.currentUser(), "GET_CASE_LIST");
        return Map.of("returned", 0); // 不会到达：deny 抛 403
    }

    @GetMapping("/api/model-audit/models/{id}/cases")
    public Map<String, Object> modelCasesDenied(@PathVariable Long id) {
        auditService.denyCaseLevelExport(id, SecurityUtils.currentUser(), "GET_MODEL_CASES");
        return Map.of("returned", 0);
    }

    @PostMapping("/api/model-audit/case-export")
    public Map<String, Object> exportCases(@RequestBody(required = false) Map<String, Object> body) {
        Long modelId = body != null && body.get("modelId") != null
                ? Long.valueOf(body.get("modelId").toString()) : null;
        auditService.denyCaseLevelExport(modelId, SecurityUtils.currentUser(), "POST_CASE_EXPORT");
        return Map.of("exportedRows", 0);
    }

    private boolean privileged(Authentication auth) {
        if (auth == null) return false;
        return auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(a -> a.equals("ROLE_AUDITOR") || a.equals("ROLE_ADMIN"));
    }
}
