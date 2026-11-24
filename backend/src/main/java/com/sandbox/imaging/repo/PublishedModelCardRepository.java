package com.sandbox.imaging.repo;

import com.sandbox.imaging.domain.PublishedModelCard;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PublishedModelCardRepository extends JpaRepository<PublishedModelCard, Long> {
    List<PublishedModelCard> findByModelIdOrderByIdDesc(Long modelId);
    List<PublishedModelCard> findAllByOrderByIdDesc();
    Optional<PublishedModelCard> findFirstByModelIdAndKindOrderByCardVersionDesc(Long modelId, String kind);
}
