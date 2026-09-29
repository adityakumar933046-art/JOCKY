"""
JOCKY Central Evidence Service.
Supports multi-tenant scoping and chain of custody event management.
"""

from typing import List, Optional
from sqlalchemy.orm import Session
from server.models.evidence import CentralEvidenceModel
from server.models.custody import EvidenceCustodyEventModel


class EvidenceService:
    @staticmethod
    def get_evidence(
        db: Session,
        organization_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        job_id: Optional[str] = None,
        operation: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[CentralEvidenceModel]:
        query = db.query(CentralEvidenceModel)
        if organization_id:
            query = query.filter(CentralEvidenceModel.organization_id == organization_id)
        if agent_id:
            query = query.filter(CentralEvidenceModel.agent_id == agent_id)
        if job_id:
            query = query.filter(CentralEvidenceModel.job_id == job_id)
        if operation:
            query = query.filter(CentralEvidenceModel.operation == operation)
        return query.order_by(CentralEvidenceModel.timestamp.desc()).offset(offset).limit(limit).all()

    @staticmethod
    def get_by_id(db: Session, evidence_id: str) -> Optional[CentralEvidenceModel]:
        return db.query(CentralEvidenceModel).filter(CentralEvidenceModel.evidence_id == evidence_id).first()

    @staticmethod
    def get_custody_events(db: Session, evidence_id: str) -> List[EvidenceCustodyEventModel]:
        events = (
            db.query(EvidenceCustodyEventModel)
            .filter(EvidenceCustodyEventModel.evidence_id == evidence_id)
            .all()
        )
        if not events:
            return []

        # Reconstruct exact cryptographic chain order: root has previous_hash == ""
        by_prev = {e.previous_hash: e for e in events}
        ordered = []
        curr = by_prev.get("")
        visited = set()
        while curr and curr.event_id not in visited:
            ordered.append(curr)
            visited.add(curr.event_id)
            curr = by_prev.get(curr.event_hash)

        # Include any detached events sorted by timestamp
        for e in sorted(events, key=lambda x: x.timestamp):
            if e not in ordered:
                ordered.append(e)

        return ordered
