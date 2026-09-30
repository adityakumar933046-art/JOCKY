"""
JOCKY Central Database Engine, Session Management, and Default Seeding.
Supports SQLite (development/testing) and PostgreSQL (production).
"""

from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from server.config import config

connect_args = {}
if config.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    config.DATABASE_URL,
    connect_args=connect_args,
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency yielding a database session."""
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initialize all database tables and seed default organization and superadmin if not present."""
    import server.models  # Register all models with Base.metadata
    from server.models.organization import OrganizationModel
    from server.models.user import UserModel
    from server.security.crypto import hash_password

    Base.metadata.create_all(bind=engine)

    # Seed default organization and administrative users
    db = SessionLocal()
    try:
        default_org = db.query(OrganizationModel).filter(OrganizationModel.organization_id == config.DEFAULT_ORG_ID).first()
        if not default_org:
            default_org = OrganizationModel(
                organization_id=config.DEFAULT_ORG_ID,
                name="Default Forensic Organization",
                status="ACTIVE",
                created_at=datetime.now(timezone.utc),
            )
            db.add(default_org)
            db.commit()

        # Seed admin user
        admin_user = db.query(UserModel).filter(UserModel.username == "admin").first()
        if not admin_user:
            admin_user = UserModel(
                user_id="USR-SUPERADMIN",
                username="admin",
                email="admin@jocky.local",
                password_hash=hash_password("AdminSecure2026!"),
                role="SUPER_ADMIN",
                organization_id=config.DEFAULT_ORG_ID,
                is_active=True,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(admin_user)

        # Seed analyst user
        analyst_user = db.query(UserModel).filter(UserModel.username == "analyst").first()
        if not analyst_user:
            analyst_user = UserModel(
                user_id="USR-ANALYST",
                username="analyst",
                email="analyst@jocky.local",
                password_hash=hash_password("AnalystSecure2026!"),
                role="SECURITY_ANALYST",
                organization_id=config.DEFAULT_ORG_ID,
                is_active=True,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(analyst_user)

        # Seed signer user
        signer_user = db.query(UserModel).filter(UserModel.username == "signer").first()
        if not signer_user:
            signer_user = UserModel(
                user_id="USR-SIGNER",
                username="signer",
                email="signer@jocky.local",
                password_hash=hash_password("SignerSecure2026!"),
                role="SIGNER",
                organization_id=config.DEFAULT_ORG_ID,
                is_active=True,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(signer_user)

        # Seed verifier user
        verifier_user = db.query(UserModel).filter(UserModel.username == "verifier").first()
        if not verifier_user:
            verifier_user = UserModel(
                user_id="USR-VERIFIER",
                username="verifier",
                email="verifier@jocky.local",
                password_hash=hash_password("VerifierSecure2026!"),
                role="VERIFIER",
                organization_id=config.DEFAULT_ORG_ID,
                is_active=True,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(verifier_user)

        db.commit()
    except Exception as e:
        db.rollback()
        # Non-fatal if already seeded or during concurrent startup
    finally:
        db.close()
