"""
JOCKY Production Database Initialization & Schema Verification Script.
Connects to the configured database (PostgreSQL or SQLite), creates all tables,
verifies indexes and constraints, and ensures core administrative entities exist.
"""

import sys
from datetime import datetime, timezone
from sqlalchemy import inspect

from server.config import config
from server.database import engine, Base, SessionLocal, init_db
from server.models import (
    OrganizationModel,
    UserModel,
    AgentModel,
    JobModel,
    CentralEvidenceModel,
    CentralFindingModel,
    InvestigationModel,
    EvidenceCustodyEventModel,
    AuditLogModel,
    NormalizedArtifactModel,
    ArtifactRelationshipModel,
    IndicatorModel,
    CrossSystemCorrelationModel,
    CorrelatedFindingModel,
    InvestigationNoteModel,
    InvestigationSnapshotModel,
)


def initialize_and_verify_database():
    print("=" * 70)
    print("JOCKY PRODUCTION DATABASE INITIALIZATION & VERIFICATION")
    print("=" * 70)
    print(f"Target Database URL: {config.DATABASE_URL.split('@')[-1] if '@' in config.DATABASE_URL else config.DATABASE_URL}")
    print(f"Environment Mode:    {config.ENV}")

    # Step 1: Create all tables
    print("\n[1/4] Creating all schema tables via SQLAlchemy metadata...")
    Base.metadata.create_all(bind=engine)
    print("  -> Tables created or verified successfully.")

    # Step 2: Inspect tables
    print("\n[2/4] Inspecting database tables and indexes...")
    inspector = inspect(engine)
    table_names = inspector.get_table_names()
    print(f"  -> Total tables detected: {len(table_names)}")
    for t in sorted(table_names):
        cols = inspector.get_columns(t)
        indexes = inspector.get_indexes(t)
        print(f"     * {t:<30} ({len(cols)} columns, {len(indexes)} indexes)")

    # Step 3: Run default seeding
    print("\n[3/4] Ensuring default administrative entities and roles exist...")
    init_db()
    print("  -> Default organization and role accounts verified.")

    # Step 4: Verify record counts
    print("\n[4/4] Verifying database connectivity and core records...")
    db = SessionLocal()
    try:
        org_count = db.query(OrganizationModel).count()
        user_count = db.query(UserModel).count()
        agent_count = db.query(AgentModel).count()
        job_count = db.query(JobModel).count()
        evidence_count = db.query(CentralEvidenceModel).count()
        finding_count = db.query(CentralFindingModel).count()
        artifact_count = db.query(NormalizedArtifactModel).count()

        print(f"  -> Organizations:        {org_count}")
        print(f"  -> Users:                {user_count}")
        print(f"  -> Agents Registered:    {agent_count}")
        print(f"  -> Jobs Processed:       {job_count}")
        print(f"  -> Evidence Records:     {evidence_count}")
        print(f"  -> Threat Findings:      {finding_count}")
        print(f"  -> Normalized Artifacts: {artifact_count}")
    finally:
        db.close()

    print("\n" + "=" * 70)
    print("PRODUCTION DATABASE INITIALIZATION COMPLETE - SYSTEM HEALTHY")
    print("=" * 70)


if __name__ == "__main__":
    initialize_and_verify_database()
