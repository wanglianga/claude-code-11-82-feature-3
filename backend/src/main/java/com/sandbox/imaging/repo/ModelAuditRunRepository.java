package com.sandbox.imaging.repo;

import com.sandbox.imaging.domain.ModelAuditRun;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ModelAuditRunRepository extends JpaRepository<ModelAuditRun, Long> {
    List<ModelAuditRun> findByModelIdOrderByIdDesc(Long modelId);
    List<ModelAuditRun> findAllByOrderByIdDesc();
}
