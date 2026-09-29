"""
JOCKY Forensic Correlation Service.
Coordinates automated normalization, IOC extraction, and correlation across organizations.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional
from sqlalchemy.orm import Session

from server.models.evidence import CentralEvidenceModel
from server.models.artifact import NormalizedArtifactModel, ArtifactRelationshipModel
from server.models.indicator import IndicatorModel, CrossSystemCorrelationModel
from server.models.correlation import CorrelatedFindingModel
from server.models.finding import CentralFindingModel
from forensics.normalization.engine import default_normalization_registry, NormalizationEngine
from forensics.indicators.extractor import default_indicator_extractor
from forensics.correlation.engine import default_correlation_engine
from forensics.normalization.models import NormalizedArtifact


class CorrelationService:
    @classmethod
    def run_for_organization(cls, db: Session, org_id: str) -> Dict[str, int]:
        """
        Execute full forensic normalization, indicator extraction, and correlation analysis
        for a specific organization.
        """
        # 1. Fetch Evidence
        ev_records = db.query(CentralEvidenceModel).filter(CentralEvidenceModel.organization_id == org_id).all()
        norm_engine = NormalizationEngine(default_normalization_registry)
        all_artifacts: List[NormalizedArtifact] = []

        for ev in ev_records:
            arts = norm_engine.normalize_evidence(
                evidence_id=ev.evidence_id,
                operation=ev.operation,
                data=ev.data,
                hostname=ev.hostname,
                agent_id=ev.agent_id,
                job_id=ev.job_id,
                organization_id=ev.organization_id,
                timestamp=ev.timestamp.isoformat() if ev.timestamp else None,
            )
            all_artifacts.extend(arts)

        existing_art_ids = {
            r[0] for r in db.query(NormalizedArtifactModel.artifact_id).filter(
                NormalizedArtifactModel.organization_id == org_id
            ).all()
        }

        new_artifacts = 0
        for art in all_artifacts:
            if art.artifact_id not in existing_art_ids:
                db_art = NormalizedArtifactModel(
                    artifact_id=art.artifact_id,
                    organization_id=art.organization_id,
                    agent_id=art.agent_id,
                    evidence_id=art.evidence_id,
                    job_id=art.job_id,
                    hostname=art.hostname,
                    artifact_type=art.artifact_type,
                    timestamp=datetime.fromisoformat(art.timestamp),
                    normalized_attributes=art.normalized_attributes,
                    raw_data=art.raw_data,
                    indicators=art.indicators,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(db_art)
                existing_art_ids.add(art.artifact_id)
                new_artifacts += 1
        db.commit()

        # 2. Extract Indicators
        extracted_indicators = default_indicator_extractor.extract_from_artifacts(all_artifacts, organization_id=org_id)
        new_indicators = 0
        for ind in extracted_indicators:
            db_ind = db.query(IndicatorModel).filter(
                IndicatorModel.organization_id == org_id,
                IndicatorModel.indicator_type == ind.indicator_type,
                IndicatorModel.value == ind.value,
            ).first()
            if not db_ind:
                db_ind = IndicatorModel(
                    indicator_id=ind.indicator_id,
                    organization_id=ind.organization_id,
                    indicator_type=ind.indicator_type,
                    value=ind.value,
                    first_seen=datetime.fromisoformat(ind.first_seen),
                    last_seen=datetime.fromisoformat(ind.last_seen),
                    occurrences=ind.occurrences,
                    severity=ind.severity,
                    source_artifacts=ind.source_artifacts,
                    agents_observed=ind.agents_observed,
                    metadata_json=ind.metadata,
                )
                db.add(db_ind)
                new_indicators += 1
            else:
                db_ind.occurrences += ind.occurrences
                db_ind.last_seen = datetime.fromisoformat(ind.last_seen)
                db_ind.source_artifacts = list(set(db_ind.source_artifacts + ind.source_artifacts))
                db_ind.agents_observed = list(set(db_ind.agents_observed + ind.agents_observed))
                if ind.severity in ["CRITICAL", "HIGH"] and db_ind.severity not in ["CRITICAL", "HIGH"]:
                    db_ind.severity = ind.severity
        db.commit()

        # 3. Correlation Rules
        findings = db.query(CentralFindingModel).filter(CentralFindingModel.organization_id == org_id).all()
        relationships, xcorrs, correlated_findings = default_correlation_engine.run(
            artifacts=all_artifacts,
            indicators=extracted_indicators,
            findings=findings,
            organization_id=org_id,
        )

        new_rels = 0
        for rel in relationships:
            exists = db.query(ArtifactRelationshipModel).filter(
                ArtifactRelationshipModel.source_artifact_id == rel.source_artifact_id,
                ArtifactRelationshipModel.target_artifact_id == rel.target_artifact_id,
                ArtifactRelationshipModel.relationship_type == rel.relationship_type,
            ).first()
            if not exists:
                db.add(ArtifactRelationshipModel(
                    relationship_id=rel.relationship_id,
                    organization_id=rel.organization_id,
                    source_artifact_id=rel.source_artifact_id,
                    target_artifact_id=rel.target_artifact_id,
                    relationship_type=rel.relationship_type,
                    confidence=rel.confidence,
                    evidence_ids=rel.evidence_ids,
                    metadata_json=rel.metadata,
                    created_at=datetime.now(timezone.utc),
                ))
                new_rels += 1

        new_xcorrs = 0
        for xc in xcorrs:
            db_xc = db.query(CrossSystemCorrelationModel).filter(
                CrossSystemCorrelationModel.organization_id == org_id,
                CrossSystemCorrelationModel.indicator_type == xc.indicator_type,
                CrossSystemCorrelationModel.indicator_value == xc.indicator_value,
            ).first()
            if not db_xc:
                db.add(CrossSystemCorrelationModel(
                    correlation_id=xc.correlation_id,
                    organization_id=xc.organization_id,
                    indicator_type=xc.indicator_type,
                    indicator_value=xc.indicator_value,
                    agents_count=xc.agents_count,
                    agent_ids=xc.agent_ids,
                    first_seen=datetime.fromisoformat(xc.first_seen),
                    last_seen=datetime.fromisoformat(xc.last_seen),
                    occurrences=xc.occurrences,
                    severity=xc.severity,
                    linked_investigation_ids=xc.linked_investigation_ids,
                    details=xc.details,
                    created_at=datetime.now(timezone.utc),
                ))
                new_xcorrs += 1
            else:
                db_xc.agents_count = xc.agents_count
                db_xc.agent_ids = xc.agent_ids
                db_xc.occurrences = xc.occurrences
                db_xc.last_seen = datetime.fromisoformat(xc.last_seen)

        new_cfnds = 0
        for cf in correlated_findings:
            exists = db.query(CorrelatedFindingModel).filter(
                CorrelatedFindingModel.organization_id == org_id,
                CorrelatedFindingModel.title == cf.title,
            ).first()
            if not exists:
                db.add(CorrelatedFindingModel(
                    correlation_id=cf.correlation_id,
                    organization_id=cf.organization_id,
                    title=cf.title,
                    category=cf.category,
                    severity=cf.severity,
                    confidence=cf.confidence,
                    description=cf.description,
                    finding_ids=cf.finding_ids,
                    artifact_ids=cf.artifact_ids,
                    indicator_ids=cf.indicator_ids,
                    agent_ids=cf.agent_ids,
                    created_at=datetime.now(timezone.utc),
                ))
                new_cfnds += 1

        db.commit()

        return {
            "evidence_analyzed": len(ev_records),
            "normalized_artifacts_created": new_artifacts,
            "total_normalized_artifacts": len(all_artifacts),
            "indicators_indexed": new_indicators,
            "relationships_discovered": new_rels,
            "cross_system_correlations": new_xcorrs,
            "correlated_findings_created": new_cfnds,
        }
