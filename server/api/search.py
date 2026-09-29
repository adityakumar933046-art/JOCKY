"""
JOCKY Forensic Global Search REST API Endpoint.
Provides fast multi-entity search across artifacts, indicators, findings, evidence, systems, and notes.
"""

from typing import List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_, cast, String

from server.database import get_db
from server.models.artifact import NormalizedArtifactModel
from server.models.indicator import IndicatorModel
from server.models.finding import CentralFindingModel
from server.models.evidence import CentralEvidenceModel
from server.models.agent import AgentModel
from server.models.investigation_note import InvestigationNoteModel
from server.models.user import UserModel
from server.schemas.forensics import SearchResponse, SearchResultItem
from server.api.security import get_current_user
from server.security.permissions import Roles

search_router = APIRouter(prefix="/search", tags=["Forensic Search"])


@search_router.get("", response_model=SearchResponse)
def global_forensic_search(
    q: str = Query(..., min_length=1, description="Search query string"),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    """
    Execute unified forensic search across artifacts, IOCs, threat findings,
    evidence records, endpoints, and investigation notes.
    """
    term = f"%{q}%"
    org_id = current_user.organization_id
    is_super = current_user.role == Roles.SUPER_ADMIN

    results: List[SearchResultItem] = []

    # 1. Search Indicators
    ind_q = db.query(IndicatorModel).filter(
        or_(IndicatorModel.value.ilike(term), IndicatorModel.indicator_type.ilike(term))
    )
    if not is_super:
        ind_q = ind_q.filter(IndicatorModel.organization_id == org_id)
    for ind in ind_q.limit(limit // 5 + 5).all():
        results.append(SearchResultItem(
            entity_type="INDICATOR",
            entity_id=ind.indicator_id,
            title=f"IOC: {ind.value}",
            subtitle=f"{ind.indicator_type} ({ind.occurrences} observed across {len(ind.agents_observed)} agents)",
            severity=ind.severity,
            timestamp=ind.last_seen.isoformat() if ind.last_seen else None,
            metadata={"type": ind.indicator_type, "occurrences": ind.occurrences},
        ))

    # 2. Search Threat Findings
    fnd_q = db.query(CentralFindingModel).filter(
        or_(
            CentralFindingModel.title.ilike(term),
            CentralFindingModel.description.ilike(term),
            CentralFindingModel.affected_object.ilike(term),
        )
    )
    if not is_super:
        fnd_q = fnd_q.filter(CentralFindingModel.organization_id == org_id)
    for f in fnd_q.limit(limit // 5 + 5).all():
        results.append(SearchResultItem(
            entity_type="FINDING",
            entity_id=f.finding_id,
            title=f"Finding: {f.title}",
            subtitle=f"Target: {f.affected_object or 'Host'} [{f.category}]",
            severity=f.severity,
            timestamp=f.timestamp.isoformat() if f.timestamp else None,
            metadata={"agent_id": f.agent_id, "category": f.category},
        ))

    # 3. Search Normalized Artifacts
    art_q = db.query(NormalizedArtifactModel).filter(
        or_(
            NormalizedArtifactModel.hostname.ilike(term),
            NormalizedArtifactModel.artifact_type.ilike(term),
            NormalizedArtifactModel.artifact_id.ilike(term),
            cast(NormalizedArtifactModel.normalized_attributes, String).ilike(term),
            cast(NormalizedArtifactModel.indicators, String).ilike(term),
        )
    )
    if not is_super:
        art_q = art_q.filter(NormalizedArtifactModel.organization_id == org_id)
    for a in art_q.limit(limit // 5 + 5).all():
        name = a.normalized_attributes.get("name") or a.normalized_attributes.get("filename") or a.artifact_type
        results.append(SearchResultItem(
            entity_type="ARTIFACT",
            entity_id=a.artifact_id,
            title=f"{a.artifact_type}: {name}",
            subtitle=f"Host: {a.hostname} (Agent: {a.agent_id})",
            severity="INFO",
            timestamp=a.timestamp.isoformat() if a.timestamp else None,
            metadata=a.normalized_attributes,
        ))

    # 4. Search Evidence Records
    ev_q = db.query(CentralEvidenceModel).filter(
        or_(
            CentralEvidenceModel.evidence_id.ilike(term),
            CentralEvidenceModel.hostname.ilike(term),
            CentralEvidenceModel.operation.ilike(term),
        )
    )
    if not is_super:
        ev_q = ev_q.filter(CentralEvidenceModel.organization_id == org_id)
    for ev in ev_q.limit(limit // 5 + 5).all():
        results.append(SearchResultItem(
            entity_type="EVIDENCE",
            entity_id=ev.evidence_id,
            title=f"Evidence: {ev.operation}",
            subtitle=f"Host: {ev.hostname} [SHA256: {ev.content_hash[:12] if ev.content_hash else 'N/A'}...]",
            severity="INFO",
            timestamp=ev.timestamp.isoformat() if ev.timestamp else None,
            metadata={"agent_id": ev.agent_id, "operation": ev.operation},
        ))

    # 5. Search Agents / Systems
    ag_q = db.query(AgentModel).filter(
        or_(
            AgentModel.agent_id.ilike(term),
            AgentModel.hostname.ilike(term),
            AgentModel.operating_system.ilike(term),
        )
    )
    if not is_super:
        ag_q = ag_q.filter(AgentModel.organization_id == org_id)
    for ag in ag_q.limit(limit // 5 + 5).all():
        results.append(SearchResultItem(
            entity_type="AGENT",
            entity_id=ag.agent_id,
            title=f"Host: {ag.hostname}",
            subtitle=f"{ag.operating_system} - Trust: {ag.trust_state} [{ag.status}]",
            severity="INFO",
            timestamp=ag.last_seen.isoformat() if ag.last_seen else None,
            metadata={"status": ag.status, "trust_state": ag.trust_state},
        ))

    # 6. Search Investigation Notes
    note_q = db.query(InvestigationNoteModel).filter(
        or_(
            InvestigationNoteModel.content.ilike(term),
            InvestigationNoteModel.author_name.ilike(term),
        )
    )
    if not is_super:
        note_q = note_q.filter(InvestigationNoteModel.organization_id == org_id)
    for n in note_q.limit(limit // 5 + 5).all():
        results.append(SearchResultItem(
            entity_type="NOTE",
            entity_id=n.note_id,
            title=f"Note by {n.author_name}",
            subtitle=n.content[:100] + ("..." if len(n.content) > 100 else ""),
            severity="INFO",
            timestamp=n.created_at.isoformat() if n.created_at else None,
            metadata={"investigation_id": n.investigation_id},
        ))

    return SearchResponse(
        query=q,
        total_results=len(results),
        results=results[:limit],
    )
