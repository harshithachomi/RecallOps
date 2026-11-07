"""
RecallOps - Incident Manager
Handles incident persistence, updates, query filtering, and statistical aggregations.
Computes real-time dynamic feedback analytics and resolution metrics.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
from sqlalchemy import desc, func
from database import get_session, IncidentRecord


def generate_incident_id() -> str:
    short_uuid = uuid.uuid4().hex[:6].upper()
    return f"INC-{datetime.now(timezone.utc).strftime('%y%m%d')}-{short_uuid}"


def create_incident(
    original_log: str,
    error_message: str,
    error_category: str = "Unknown or unclassified errors",
    severity: str = "Medium",
    detected_evidence: Optional[List[str]] = None,
    possible_root_cause: Optional[str] = None,
    root_cause_confidence: str = "Possible",
    ai_explanation: Optional[str] = None,
    recommended_solution: Optional[List[str]] = None,
    recommendations_count: int = 0,
    memory_source_used: str = "None",
    component: Optional[str] = None,
    source: str = "Live Ingestion",
    memory_reference: Optional[str] = None,
    resolution_status: str = "Pending Investigation"
) -> Dict[str, Any]:
    """
    Creates and saves a new incident record in the database.
    """
    session = get_session()
    try:
        incident_id = generate_incident_id()
        evidence_str = json.dumps(detected_evidence or [])
        solution_str = json.dumps(recommended_solution or [])

        record = IncidentRecord(
            incident_id=incident_id,
            original_log=original_log,
            error_message=error_message,
            error_category=error_category,
            severity=severity,
            detected_evidence=evidence_str,
            possible_root_cause=possible_root_cause,
            root_cause_confidence=root_cause_confidence,
            ai_explanation=ai_explanation,
            recommended_solution=solution_str,
            recommendations_count=recommendations_count or len(recommended_solution or []),
            memory_source_used=memory_source_used,
            component=component,
            source=source,
            memory_reference=memory_reference,
            resolution_status=resolution_status,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        session.add(record)
        session.commit()
        session.refresh(record)
        return record.to_dict()
    finally:
        session.close()


def get_incident(incident_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves a single incident by its ID.
    """
    session = get_session()
    try:
        record = session.query(IncidentRecord).filter(IncidentRecord.incident_id == incident_id).first()
        return record.to_dict() if record else None
    finally:
        session.close()


def update_incident_resolution(
    incident_id: str,
    resolution_status: str,
    applied_solution: Optional[str] = None,
    developer_feedback: Optional[str] = None,
    feedback_useful: Optional[bool] = None,
    feedback_type: Optional[str] = None,
    corrected_resolution: Optional[str] = None,
    corrected_root_cause: Optional[str] = None,
    failure_reason: Optional[str] = None,
    recommendation_accepted: Optional[bool] = None
) -> Optional[Dict[str, Any]]:
    """
    Updates the resolution status, applied solution, and feedback for an incident.
    """
    session = get_session()
    try:
        record = session.query(IncidentRecord).filter(IncidentRecord.incident_id == incident_id).first()
        if not record:
            return None

        record.resolution_status = resolution_status
        if applied_solution is not None:
            record.applied_solution = applied_solution
        if developer_feedback is not None:
            record.developer_feedback = developer_feedback
        if feedback_useful is not None:
            record.feedback_useful = feedback_useful
        if feedback_type is not None:
            record.feedback_type = feedback_type
        if corrected_resolution is not None:
            record.corrected_resolution = corrected_resolution
        if corrected_root_cause is not None:
            record.corrected_root_cause = corrected_root_cause
        if failure_reason is not None:
            record.failure_reason = failure_reason
        if recommendation_accepted is not None:
            record.recommendation_accepted = recommendation_accepted

        record.updated_at = datetime.now(timezone.utc)

        session.commit()
        session.refresh(record)
        return record.to_dict()
    finally:
        session.close()


def list_incidents(
    category: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> List[Dict[str, Any]]:
    """
    Lists incidents matching optional filter criteria, sorted by creation date descending.
    """
    session = get_session()
    try:
        query = session.query(IncidentRecord)

        if category and category != "ALL":
            query = query.filter(IncidentRecord.error_category == category)
        if severity and severity != "ALL":
            query = query.filter(IncidentRecord.severity == severity)
        if status and status != "ALL":
            query = query.filter(IncidentRecord.resolution_status == status)
        if search and search.strip():
            term = f"%{search.strip()}%"
            query = query.filter(
                (IncidentRecord.error_message.ilike(term)) |
                (IncidentRecord.original_log.ilike(term)) |
                (IncidentRecord.incident_id.ilike(term)) |
                (IncidentRecord.component.ilike(term))
            )

        records = query.order_by(desc(IncidentRecord.created_at)).offset(offset).limit(limit).all()
        return [r.to_dict() for r in records]
    finally:
        session.close()


def get_feedback_analytics() -> Dict[str, Any]:
    """
    Computes rigorous resolution success rate and recommendation adoption
    directly from actual incident feedback records.
    """
    session = get_session()
    try:
        total = session.query(IncidentRecord).count()
        total_recommendations = (
            session.query(func.sum(IncidentRecord.recommendations_count)).scalar() or 0
        )
        accepted_recommendations = (
            session.query(IncidentRecord).filter(IncidentRecord.recommendation_accepted == True).count()
        )
        successful = (
            session.query(IncidentRecord).filter(
                (IncidentRecord.feedback_useful == True) |
                (IncidentRecord.feedback_type == "Solution successful") |
                (IncidentRecord.resolution_status.ilike("%Resolved - Verified%"))
            ).count()
        )
        partial = (
            session.query(IncidentRecord).filter(
                (IncidentRecord.feedback_type == "Partially successful") |
                (IncidentRecord.resolution_status.ilike("%Alternative%"))
            ).count()
        )
        unsuccessful = (
            session.query(IncidentRecord).filter(
                (IncidentRecord.feedback_useful == False) |
                (IncidentRecord.feedback_type == "Solution unsuccessful") |
                (IncidentRecord.resolution_status.ilike("%Unsuccessful%"))
            ).count()
        )

        evaluated = successful + partial + unsuccessful
        success_rate = round((successful / evaluated) * 100, 1) if evaluated > 0 else 0.0
        acceptance_rate = round((accepted_recommendations / total) * 100, 1) if total > 0 else 0.0

        return {
            "total_incidents_recorded": total,
            "total_recommendations_generated": total_recommendations,
            "accepted_recommendations": accepted_recommendations,
            "successful_resolutions": successful,
            "partial_resolutions": partial,
            "unsuccessful_resolutions": unsuccessful,
            "evaluated_resolutions_count": evaluated,
            "resolution_success_rate": success_rate,
            "acceptance_rate": acceptance_rate
        }
    finally:
        session.close()


def get_incident_statistics() -> Dict[str, Any]:
    """
    Computes summary metrics across all stored incidents.
    """
    session = get_session()
    try:
        total = session.query(IncidentRecord).count()
        resolved = session.query(IncidentRecord).filter(
            IncidentRecord.resolution_status.ilike("%Resolved%")
        ).count()
        pending = session.query(IncidentRecord).filter(
            IncidentRecord.resolution_status.ilike("%Pending%")
        ).count()
        unsuccessful = session.query(IncidentRecord).filter(
            IncidentRecord.resolution_status.ilike("%Unsuccessful%")
        ).count()
        critical = session.query(IncidentRecord).filter(
            IncidentRecord.severity == "Critical"
        ).count()

        # Category breakdown
        cat_counts = (
            session.query(IncidentRecord.error_category, func.count(IncidentRecord.incident_id))
            .group_by(IncidentRecord.error_category)
            .all()
        )
        categories = {cat: count for cat, count in cat_counts}

        # Severity breakdown
        sev_counts = (
            session.query(IncidentRecord.severity, func.count(IncidentRecord.incident_id))
            .group_by(IncidentRecord.severity)
            .all()
        )
        severities = {sev: count for sev, count in sev_counts}

        # Recent verified solutions
        recent_verified = (
            session.query(IncidentRecord)
            .filter(IncidentRecord.feedback_useful == True)
            .order_by(desc(IncidentRecord.updated_at))
            .limit(5)
            .all()
        )

        feedback_analytics = get_feedback_analytics()

        return {
            "total_stored_incidents": total,
            "resolved_incidents": resolved,
            "pending_incidents": pending,
            "unsuccessful_incidents": unsuccessful,
            "critical_incidents": critical,
            "categories": categories,
            "severities": severities,
            "recent_verified": [r.to_dict() for r in recent_verified],
            "feedback_analytics": feedback_analytics
        }
    finally:
        session.close()
