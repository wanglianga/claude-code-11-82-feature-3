package com.sandbox.imaging.repo;

import com.sandbox.imaging.domain.ValidationCase;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ValidationCaseRepository extends JpaRepository<ValidationCase, Long> {
    List<ValidationCase> findByModelIdOrderByIdAsc(Long modelId);
    long countByModelId(Long modelId);
}
