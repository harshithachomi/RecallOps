"""
RecallOps - Developer Feedback & Continuous Learning Manager
Captures human-in-the-loop developer verification, stores confirmed/alternative
solutions in the database, tracks recommendation acceptance, and retains
verified lessons learned or anti-pattern warnings in Hindsight memory.
"""

from typing import Dict, Any, Optional
from incident_manager import update_incident_resolution, get_incident
from hindsight_memory import retain_incident_memory, BANKS


def record_developer_feedback(
    incident_id: str,
    feedback_type: str,
    applied_solution: Optional[str] = None,
    failure_reason: Optional[str] = None,
    corrected_root_cause: Optional[str] = None,
    corrected_resolution: Optional[str] = None,
    comments: Optional[str] = None,
    recommendation_accepted: Optional[bool] = None,
    domain: str = "incidents"
) -> Dict[str, Any]:
    """
    Processes developer feedback for an incident across all 6 feedback workflows:
    1. Solution successful
    2. Alternative solution applied
    3. Solution unsuccessful (anti-pattern)
    4. Partially successful
    5. Incorrect root cause
    6. Additional troubleshooting / Still investigating
    """
    useful = False
    accepted = recommendation_accepted

    if feedback_type == "Solution successful":
        resolution_status = "Resolved - Verified Fix"
        useful = True
        if accepted is None:
            accepted = True
    elif feedback_type == "Alternative solution applied":
        resolution_status = "Resolved - Alternative Fix"
        useful = True
        if accepted is None:
            accepted = False
    elif feedback_type == "Partially successful":
        resolution_status = "Partially Resolved - Needs Tuning"
        useful = True
        if accepted is None:
            accepted = True
    elif feedback_type == "Incorrect root cause":
        resolution_status = "Root Cause Disputed - Reopened"
        useful = False
        if accepted is None:
            accepted = False
    elif feedback_type == "Solution unsuccessful":
        resolution_status = "Unsuccessful - Needs Investigation"
        useful = False
        if accepted is None:
            accepted = True  # Attempted the recommended solution and it failed
    else:  # "Additional troubleshooting information" / "Still investigating"
        resolution_status = "Investigation In-Progress"
        useful = None

    # Retrieve existing incident context
    incident = get_incident(incident_id)
    error_summary = incident.get("error_message", "Incident") if incident else "Incident"
    category = incident.get("error_category", "General") if incident else "General"
    original_root_cause = incident.get("possible_root_cause", "") if incident else ""

    combined_feedback = comments or ""
    if failure_reason:
        combined_feedback = f"Failure Reason: {failure_reason}. Notes: {combined_feedback}".strip()
    if corrected_root_cause:
        combined_feedback = f"Corrected Root Cause: {corrected_root_cause}. {combined_feedback}".strip()

    # Determine effective solution applied
    final_solution = applied_solution or corrected_resolution or ""

    # 1. Update relational database record
    updated_record = update_incident_resolution(
        incident_id=incident_id,
        resolution_status=resolution_status,
        applied_solution=final_solution,
        developer_feedback=combined_feedback,
        feedback_useful=useful,
        feedback_type=feedback_type,
        corrected_resolution=corrected_resolution,
        corrected_root_cause=corrected_root_cause,
        failure_reason=failure_reason,
        recommendation_accepted=accepted
    )

    bank_id = BANKS.get(domain, "incident-intelligence")

    # 2. Retain verified experience in Hindsight
    if feedback_type in ["Solution successful", "Alternative solution applied"]:
        memory_content = (
            f"[VERIFIED INCIDENT RESOLUTION]\n"
            f"Incident ID: {incident_id}\n"
            f"Category: {category}\n"
            f"Error Signature: {error_summary}\n"
            f"Root Cause: {original_root_cause}\n"
            f"Applied Solution: {final_solution or 'Verified as effective'}\n"
            f"Outcome: Confirmed Successful by Developer\n"
            f"Notes: {combined_feedback}"
        )
        retain_incident_memory(
            bank_id=bank_id,
            content=memory_content,
            metadata={
                "incident_id": incident_id,
                "summary": error_summary,
                "category": category,
                "root_cause": original_root_cause,
                "applied_solution": final_solution or "Verified as effective",
                "outcome": "Confirmed Successful",
                "verified": True,
                "is_anti_pattern": False,
                "notes": combined_feedback,
                "domain": domain
            }
        )
    elif feedback_type == "Partially successful":
        memory_content = (
            f"[PARTIALLY RESOLVED INCIDENT]\n"
            f"Incident ID: {incident_id}\n"
            f"Category: {category}\n"
            f"Error Signature: {error_summary}\n"
            f"Applied Solution: {final_solution}\n"
            f"Outcome: Partially Successful (Mitigated symptoms, further tuning needed)\n"
            f"Notes: {combined_feedback}"
        )
        retain_incident_memory(
            bank_id=bank_id,
            content=memory_content,
            metadata={
                "incident_id": incident_id,
                "summary": error_summary,
                "category": category,
                "root_cause": original_root_cause,
                "applied_solution": final_solution,
                "outcome": "Partially Successful",
                "verified": True,
                "is_anti_pattern": False,
                "notes": combined_feedback,
                "domain": domain
            }
        )
    elif feedback_type == "Incorrect root cause":
        memory_content = (
            f"[ROOT CAUSE CORRECTION & RESOLUTION]\n"
            f"Incident ID: {incident_id}\n"
            f"Category: {category}\n"
            f"Error Signature: {error_summary}\n"
            f"Disputed Initial Cause: {original_root_cause}\n"
            f"Corrected Root Cause: {corrected_root_cause or 'Developer identified distinct root cause'}\n"
            f"Corrected Effective Solution: {corrected_resolution or final_solution}\n"
            f"Outcome: Corrected by Developer\n"
            f"Notes: {combined_feedback}"
        )
        retain_incident_memory(
            bank_id=bank_id,
            content=memory_content,
            metadata={
                "incident_id": incident_id,
                "summary": error_summary,
                "category": category,
                "root_cause": corrected_root_cause or original_root_cause,
                "applied_solution": corrected_resolution or final_solution,
                "outcome": "Confirmed Successful (Corrected)",
                "verified": True,
                "is_anti_pattern": False,
                "notes": combined_feedback,
                "domain": domain
            }
        )
    elif feedback_type == "Solution unsuccessful":
        memory_content = (
            f"[UNSUCCESSFUL INCIDENT ATTEMPT - AVOID THIS ACTION]\n"
            f"Incident ID: {incident_id}\n"
            f"Category: {category}\n"
            f"Error Signature: {error_summary}\n"
            f"Failed Proposed Solution: {final_solution or 'Proposed recommendation'}\n"
            f"Reason for Failure: {failure_reason or 'Did not resolve the underlying root cause'}\n"
            f"Outcome: Unsuccessful (Anti-Pattern: Do not recommend again for similar signatures)"
        )
        retain_incident_memory(
            bank_id=bank_id,
            content=memory_content,
            metadata={
                "incident_id": incident_id,
                "summary": error_summary,
                "category": category,
                "root_cause": original_root_cause,
                "applied_solution": f"FAILED: {final_solution}",
                "outcome": "Unsuccessful",
                "verified": False,
                "is_anti_pattern": True,
                "notes": failure_reason,
                "domain": domain
            }
        )

    return updated_record or {}
