package com.sandbox.imaging.repo;

import com.sandbox.imaging.domain.TrainingSource;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface TrainingSourceRepository extends JpaRepository<TrainingSource, Long> {
    List<TrainingSource> findByModelIdOrderByIdAsc(Long modelId);
}
