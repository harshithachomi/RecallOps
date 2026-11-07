"""
RecallOps - Database Layer
Provides structured relational storage for incidents, audit trails, and developer feedback.
Supports SQLite (default) and PostgreSQL (via DATABASE_URL).
Includes automatic schema migration to ensure backward compatibility with existing databases.
"""

import os
import json
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import (
    create_engine,
    Column,
    String,
    Text,
    DateTime,
    Boolean,
    Integer,
    desc,
    text
)
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()


class IncidentRecord(Base):
    __tablename__ = "incidents"

    incident_id = Column(String(64), primary_key=True)
    original_log = Column(Text, nullable=False)
    error_message = Column(Text, nullable=False)
    error_category = Column(String(64), nullable=False, default="Unknown or unclassified errors")
    severity = Column(String(32), nullable=False, default="Medium")
    detected_evidence = Column(Text, nullable=True)  # JSON-encoded list of strings
    possible_root_cause = Column(Text, nullable=True)
    root_cause_confidence = Column(String(32), nullable=False, default="Possible")  # Confirmed, Likely, Possible
    ai_explanation = Column(Text, nullable=True)
    recommended_solution = Column(Text, nullable=True)  # JSON-encoded list of strings
    applied_solution = Column(Text, nullable=True)
    resolution_status = Column(String(64), nullable=False, default="Pending Investigation")
    developer_feedback = Column(Text, nullable=True)
    feedback_useful = Column(Boolean, nullable=True)
    feedback_type = Column(String(64), nullable=True)  # Solution successful, Solution unsuccessful, Partially successful, Incorrect root cause
    corrected_resolution = Column(Text, nullable=True)
    corrected_root_cause = Column(Text, nullable=True)
    failure_reason = Column(Text, nullable=True)
    recommendations_count = Column(Integer, default=0)
    recommendation_accepted = Column(Boolean, nullable=True)
    memory_source_used = Column(String(64), default="None")
    memory_reference = Column(String(128), nullable=True)
    source = Column(String(64), default="Live Ingestion")
    component = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self):
        evidence = []
        if self.detected_evidence:
            try:
                evidence = json.loads(self.detected_evidence)
            except Exception:
                evidence = [self.detected_evidence]

        solutions = []
        if self.recommended_solution:
            try:
                solutions = json.loads(self.recommended_solution)
            except Exception:
                solutions = [self.recommended_solution]

        return {
            "incident_id": self.incident_id,
            "original_log": self.original_log,
            "error_message": self.error_message,
            "error_category": self.error_category,
            "severity": self.severity,
            "detected_evidence": evidence,
            "possible_root_cause": self.possible_root_cause,
            "root_cause_confidence": self.root_cause_confidence or "Possible",
            "ai_explanation": self.ai_explanation,
            "recommended_solution": solutions,
            "applied_solution": self.applied_solution,
            "resolution_status": self.resolution_status,
            "developer_feedback": self.developer_feedback,
            "feedback_useful": self.feedback_useful,
            "feedback_type": self.feedback_type,
            "corrected_resolution": self.corrected_resolution,
            "corrected_root_cause": self.corrected_root_cause,
            "failure_reason": self.failure_reason,
            "recommendations_count": self.recommendations_count or len(solutions),
            "recommendation_accepted": self.recommendation_accepted,
            "memory_source_used": self.memory_source_used or "None",
            "memory_reference": self.memory_reference,
            "source": self.source,
            "component": self.component,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S") if self.created_at else None,
            "updated_at": self.updated_at.strftime("%Y-%m-%d %H:%M:%S") if self.updated_at else None,
        }


def _run_migrations(engine):
    """
    Safely adds any newly defined columns to an existing database table
    without deleting or corrupting historical incident records.
    """
    with engine.connect() as conn:
        # Check existing columns in 'incidents' table
        try:
            result = conn.execute(text("PRAGMA table_info(incidents)"))
            existing_cols = {row[1] for row in result.fetchall()}
            
            new_columns = [
                ("root_cause_confidence", "VARCHAR(32) DEFAULT 'Possible'"),
                ("memory_source_used", "VARCHAR(64) DEFAULT 'None'"),
                ("feedback_type", "VARCHAR(64)"),
                ("corrected_resolution", "TEXT"),
                ("corrected_root_cause", "TEXT"),
                ("recommendations_count", "INTEGER DEFAULT 0"),
                ("recommendation_accepted", "BOOLEAN")
            ]
            
            for col_name, col_type in new_columns:
                if col_name not in existing_cols:
                    conn.execute(text(f"ALTER TABLE incidents ADD COLUMN {col_name} {col_type}"))
            conn.commit()
        except Exception:
            # If not SQLite or table doesn't exist yet, metadata.create_all handles it
            pass


def get_database_engine():
    """
    Returns the SQLAlchemy engine based on DATABASE_URL or defaults to local SQLite.
    """
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        base_dir = Path(__file__).resolve().parent.parent
        data_dir = base_dir / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        db_path = data_dir / "recallops.db"
        db_url = f"sqlite:///{db_path}"

    engine = create_engine(db_url, echo=False)
    Base.metadata.create_all(engine)
    _run_migrations(engine)
    return engine


def get_session():
    """
    Creates and returns a new SQLAlchemy session.
    """
    engine = get_database_engine()
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return SessionLocal()
