package com.sandbox.imaging.repo;

import com.sandbox.imaging.domain.FrozenModel;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface FrozenModelRepository extends JpaRepository<FrozenModel, Long> {
    Optional<FrozenModel> findByCodeAndVersion(String code, String version);
    List<FrozenModel> findAllByOrderByIdAsc();
}
