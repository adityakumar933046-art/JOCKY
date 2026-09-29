"""
JOCKY Central Finding Service.
Supports multi-tenant organization filtering and querying.
"""

from typing import List, Optional
from sqlalchemy.orm import Session
from server.models.finding import CentralFindingModel


class FindingService:
    @staticmethod
    def get_findings(
        db: Session,
        organization_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        job_id: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        rule_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[CentralFindingModel]:
        query = db.query(CentralFindingModel)
        if organization_id:
            query = query.filter(CentralFindingModel.organization_id == organization_id)
        if agent_id:
            query = query.filter(CentralFindingModel.agent_id == agent_id)
        if job_id:
            query = query.filter(CentralFindingModel.job_id == job_id)
        if severity:
            query = query.filter(CentralFindingModel.severity == severity.upper())
        if category:
            query = query.filter(CentralFindingModel.category == category.upper())
        if rule_id:
            query = query.filter(CentralFindingModel.rule_id == rule_id.upper())
        return query.order_by(CentralFindingModel.timestamp.desc()).offset(offset).limit(limit).all()

    @staticmethod
    def get_by_id(db: Session, finding_id: str) -> Optional[CentralFindingModel]:
        return db.query(CentralFindingModel).filter(CentralFindingModel.finding_id == finding_id).first()
