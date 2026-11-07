"""
RecallOps Master Test Suite (15 Comprehensive Verification Points)
Validates log parsing, classification, severity estimation, deterministic & LLM investigation,
Hindsight cloud vs local memory retention/recall, anti-pattern detection, the 2-incident experience learning cycle,
database persistence, all 6 developer feedback loops, dynamic analytics, dynamic prevention runbooks,
offline dataset benchmarks, and demonstration scenarios.
"""

import sys
import os
import json
from pathlib import Path
import pytest
import pandas as pd

# Add project root and src to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
for p in [str(PROJECT_ROOT), str(SRC_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from log_processor import parse_log_payload, extract_error_signature, extract_log_level
from incident_detector import classify_category, estimate_severity, detect_and_classify_incident, CATEGORIES
from root_cause_analyzer import investigate_incident, build_evidence_based_fallback
from database import get_session, IncidentRecord, get_database_engine
from incident_manager import (
    create_incident,
    get_incident,
    update_incident_resolution,
    list_incidents,
    get_incident_statistics,
    get_feedback_analytics
)
from hindsight_memory import (
    retain_incident_memory,
    recall_incident_memories,
    get_local_memory_cache,
    check_hindsight_cloud_status,
    get_memory_status
)
from feedback_manager import record_developer_feedback
from prevention_engine import generate_prevention_insights
from dataset_evaluator import evaluate_hdfs_detection, evaluate_swebench_retrieval


# 1. Log Ingestion (Multi-line, stack trace, empty log)
def test_01_log_ingestion_parsing():
    single_line = "2026-11-06 14:15:22.418 [payment-service] ERROR com.zaxxer.hikari.pool.HikariPool - Connection timed out after 30005ms"
    parsed_s = parse_log_payload(single_line)
    assert "Connection timed out" in parsed_s["error_message"]
    assert parsed_s["lines_count"] == 1

    multi_line = (
        "Traceback (most recent call last):\n"
        '  File "/app/server.py", line 42, in handle_request\n'
        "    res = client.query(sql)\n"
        "psycopg2.OperationalError: could not connect to server: Connection refused"
    )
    parsed_m = parse_log_payload(multi_line)
    assert parsed_m["lines_count"] == 4
    assert "Connection refused" in parsed_m["error_message"]

    empty_log = "     \n   "
    parsed_e = parse_log_payload(empty_log)
    assert parsed_e["lines_count"] == 0
    assert "Empty log" in parsed_e["error_message"]


# 2. Incident Classification across standard categories
def test_02_incident_classification_categories():
    test_cases = [
        ("FATAL: connection limit exceeded for non-replication superuser. HikariPool exhausted.", "Database connection errors"),
        ("401 Unauthorized: Bearer JWT token expired at 2026-11-06.", "Authentication errors"),
        ("java.lang.OutOfMemoryError: Java heap space. Memory allocation failed.", "Memory errors"),
        ("SocketTimeoutException: Read timed out connecting to 10.0.1.15:9000", "Network errors"),
        ("HTTP 502 Bad Gateway: Upstream service down", "API failures"),
        ("TypeError: 'NoneType' object is not subscriptable", "Application exceptions"),
        ("ConfigurationError: Environment variable DATABASE_URL is not set", "Configuration errors"),
        ("ModuleNotFoundError: No module named 'psycopg2'", "Dependency errors"),
        ("OSError: [Errno 28] No space left on device", "Resource exhaustion"),
        ("System running routine maintenance ping.", "Unknown or unclassified errors")
    ]
    for sample, expected_cat in test_cases:
        cat, conf = classify_category(sample)
        assert cat == expected_cat
        assert conf > 0.0


# 3. Severity Estimation across severity levels
def test_03_severity_estimation_levels():
    assert estimate_severity("FATAL: OutOfMemoryError JVM crash container OOMKilled", "Memory errors") == "Critical"
    assert estimate_severity("ERROR: Connection timed out to database host", "Database connection errors") in ["High", "Critical"]
    assert estimate_severity("WARN: Retrying request after socket reset", "Network errors") in ["Medium", "High"]
    assert estimate_severity("INFO: Process started on port 8080", "Unknown or unclassified errors") in ["Low", "Informational"]


# 4. Deterministic Fallback Investigation
def test_04_deterministic_fallback_investigation():
    inv = build_evidence_based_fallback(
        error_message="HikariPool connection acquisition timed out",
        error_category="Database connection errors",
        severity="High",
        evidence=["HikariPool timeout 30000ms", "Zero idle connections"]
    )
    assert "Deterministic Evidence-Based Engine" in inv["analysis_source"]
    assert "root_cause_confidence" in inv
    assert len(inv["recommended_solutions"]) >= 3
    assert len(inv["preventive_measures"]) >= 2
    assert "uncertainty_note" in inv


# 5. Root Cause Confidence Classification (Confirmed / Likely / Possible)
def test_05_root_cause_confidence_tagging():
    # Novel error with minimal evidence -> Possible or Likely
    inv_novel = build_evidence_based_fallback(
        error_message="Strange transient glitch",
        error_category="Unknown or unclassified errors",
        severity="Low",
        evidence=[]
    )
    assert inv_novel["root_cause_confidence"] == "Possible"

    # Known error with clear evidence -> Likely
    inv_likely = build_evidence_based_fallback(
        error_message="HikariPool connection timeout",
        error_category="Database connection errors",
        severity="High",
        evidence=["HikariPool timeout", "Active connections 100/100"]
    )
    assert inv_likely["root_cause_confidence"] == "Likely"

    # Known error with high-similarity verified past memory -> Confirmed
    verified_memory = [{
        "incident_id": "INC-TEST-CONFIRM",
        "summary": "HikariPool connection timeout pool exhausted",
        "applied_solution": "Increased maxPoolSize to 50",
        "outcome": "Confirmed Successful",
        "verified": True,
        "relevance_score": 0.95
    }]
    inv_confirmed = build_evidence_based_fallback(
        error_message="HikariPool connection timeout pool exhausted",
        error_category="Database connection errors",
        severity="High",
        evidence=["HikariPool timeout"],
        retrieved_memories=verified_memory
    )
    assert inv_confirmed["root_cause_confidence"] == "Confirmed"
    assert "INC-TEST-CONFIRM" in inv_confirmed["recommended_solutions"][0]


# 6. Hindsight Memory Retention
def test_06_hindsight_retention_metadata():
    status = retain_incident_memory(
        bank_id="incident-intelligence",
        content="Test verified incident resolution content",
        metadata={
            "incident_id": "INC-TEST-RETENTION",
            "category": "Database connection errors",
            "summary": "Database pool exhaustion during peak load",
            "applied_solution": "Scaled pool to 100 connections",
            "outcome": "Confirmed Successful",
            "verified": True,
            "evidence": ["pool_size=100"],
            "notes": "Verified under load"
        }
    )
    assert status["success"] is True
    assert status["local_retained"] is True
    assert "source" in status

    # Verify cached memory contains full metadata
    cache = get_local_memory_cache()
    cached = next((m for m in cache if m.get("incident_id") == "INC-TEST-RETENTION"), None)
    assert cached is not None
    assert cached["category"] == "Database connection errors"
    assert cached["applied_solution"] == "Scaled pool to 100 connections"


# 7. Hindsight Memory Recall & Scoring
def test_07_hindsight_recall_scoring():
    results = recall_incident_memories(
        query="Database pool exhaustion during peak load Scaled pool to 100 connections",
        domain="incidents",
        top_k=3
    )
    assert len(results) > 0
    top = results[0]
    assert "incident_id" in top
    assert "relevance" in top
    assert "source_type" in top
    assert top["relevance_score"] >= 0.5


# 8. Anti-Pattern Detection & Warnings
def test_08_anti_pattern_detection_and_warning():
    # Retain an unsuccessful experience
    retain_incident_memory(
        bank_id="incident-intelligence",
        content="Failed attempt to restart pod without increasing memory limits",
        metadata={
            "incident_id": "INC-ANTI-01",
            "category": "Memory errors",
            "summary": "Container OOMKilled heap exhaustion",
            "applied_solution": "Restarted container pod without changing memory quota",
            "outcome": "Unsuccessful",
            "verified": False,
            "is_anti_pattern": True,
            "notes": "Container was immediately killed again within 2 minutes."
        }
    )

    recalled = recall_incident_memories(
        query="Container OOMKilled heap exhaustion pod restart",
        domain="incidents"
    )
    anti_matches = [m for m in recalled if m.get("is_anti_pattern") or m.get("incident_id") == "INC-ANTI-01"]
    assert len(anti_matches) > 0

    inv = build_evidence_based_fallback(
        error_message="Container OOMKilled heap exhaustion",
        error_category="Memory errors",
        severity="Critical",
        evidence=["OOMKilled exit code 137"],
        retrieved_memories=anti_matches
    )
    assert len(inv["anti_pattern_warnings"]) > 0
    assert "Avoid action" in inv["anti_pattern_warnings"][0] or "ANTI-PATTERN" in inv["anti_pattern_warnings"][0]


# 9. Two-Incident Experience Recall Cycle (Core Hackathon Proof)
def test_09_two_incident_experience_learning_cycle():
    # Incident 1: Novel failure
    log_1 = "PaymentService HikariPool connection timeout: active=10, idle=0, timeout=30000ms"
    det_1 = detect_and_classify_incident(log_1)
    rec_1 = create_incident(
        original_log=log_1,
        error_message=det_1["error_message"],
        error_category=det_1["error_category"],
        severity=det_1["severity"],
        detected_evidence=det_1["detected_evidence"],
        component="PaymentService"
    )
    inc1_id = rec_1["incident_id"]

    # Developer resolves and confirms fix
    solution_1 = "Increased maxPoolSize to 60 and set connectionTimeout to 15000ms."
    record_developer_feedback(
        incident_id=inc1_id,
        feedback_type="Solution successful",
        applied_solution=solution_1,
        comments="Fixed connection starvation immediately.",
        recommendation_accepted=True
    )

    # Incident 2: Recurrence of similar failure
    log_2 = "PaymentService HikariPool connection timeout: pool exhausted"
    recalled_for_2 = recall_incident_memories(
        query="PaymentService HikariPool connection timeout pool exhausted",
        domain="incidents",
        top_k=3
    )
    assert len(recalled_for_2) > 0
    assert any(inc1_id == m.get("incident_id") for m in recalled_for_2) or any("maxPoolSize" in m.get("applied_solution", "") for m in recalled_for_2)

    # Investigation of Incident 2 must prioritize Incident 1's confirmed solution
    inv_2 = investigate_incident(
        error_message="PaymentService HikariPool connection timeout",
        error_category="Database connection errors",
        severity="High",
        original_log=log_2,
        evidence=["HikariPool connection timeout"],
        retrieved_memories=recalled_for_2,
        component="PaymentService"
    )
    assert "PAST VERIFIED EXPERIENCE" in inv_2["recommended_solutions"][0]
    assert inv_2["root_cause_confidence"] == "Confirmed"


# 10. Database Persistence & Retrieval
def test_10_database_crud_persistence():
    created = create_incident(
        original_log="Test persistence log",
        error_message="Test persistence message",
        error_category="Network errors",
        severity="Medium",
        detected_evidence=["TCP reset"]
    )
    inc_id = created["incident_id"]
    retrieved = get_incident(inc_id)
    assert retrieved is not None
    assert retrieved["incident_id"] == inc_id

    listed = list_incidents(category="Network errors")
    assert any(r["incident_id"] == inc_id for r in listed)


# 11. Developer Feedback Workflows (All 6 options)
def test_11_developer_feedback_all_workflows():
    inc = create_incident(
        original_log="Testing feedback options",
        error_message="Testing feedback options error",
        error_category="Application exceptions"
    )
    inc_id = inc["incident_id"]

    # Option 1: Solution successful
    res1 = record_developer_feedback(inc_id, "Solution successful", applied_solution="Fix 1")
    assert res1["resolution_status"] == "Resolved - Verified Fix"
    assert res1["feedback_useful"] is True

    # Option 2: Alternative solution applied
    res2 = record_developer_feedback(inc_id, "Alternative solution applied", applied_solution="Alt Fix")
    assert res2["resolution_status"] == "Resolved - Alternative Fix"

    # Option 3: Partially successful
    res3 = record_developer_feedback(inc_id, "Partially successful", applied_solution="Partial Fix")
    assert res3["resolution_status"] == "Partially Resolved - Needs Tuning"

    # Option 4: Incorrect root cause
    res4 = record_developer_feedback(
        inc_id,
        "Incorrect root cause",
        corrected_root_cause="Upstream firewall drop",
        corrected_resolution="Opened port 443"
    )
    assert res4["resolution_status"] == "Root Cause Disputed - Reopened"
    assert res4["corrected_root_cause"] == "Upstream firewall drop"

    # Option 5: Solution unsuccessful
    res5 = record_developer_feedback(
        inc_id,
        "Solution unsuccessful",
        applied_solution="Restart only",
        failure_reason="Process crashed again"
    )
    assert res5["resolution_status"] == "Unsuccessful - Needs Investigation"

    # Option 6: Additional troubleshooting
    res6 = record_developer_feedback(inc_id, "Still investigating")
    assert res6["resolution_status"] == "Investigation In-Progress"


# 12. Dynamic Feedback Analytics
def test_12_dynamic_feedback_analytics():
    analytics = get_feedback_analytics()
    assert "total_incidents_recorded" in analytics
    assert "resolution_success_rate" in analytics
    assert "acceptance_rate" in analytics
    assert isinstance(analytics["resolution_success_rate"], float)
    assert analytics["total_incidents_recorded"] >= 1


# 13. Dynamic Prevention Runbooks & Recurrence
def test_13_prevention_intelligence_dynamic():
    dummy_hdfs = pd.DataFrame({
        "Level": ["WARN", "WARN", "INFO", "INFO"],
        "EventTemplate": ["Got exception while serving block", "Got exception while serving block", "Normal block read", "Normal block write"],
        "Component": ["DataNode", "DataNode", "DataNode", "DataNode"]
    })
    insights = generate_prevention_insights(hdfs_df=dummy_hdfs)
    assert len(insights["prevention_runbooks"]) >= 1
    assert any("Got exception while serving block" in sig["signature"] for sig in insights["recurring_signatures"])


# 14. Offline Dataset Benchmarking (HDFS & SWE-bench)
def test_14_dataset_evaluation_benchmarks():
    dummy_hdfs = pd.DataFrame({
        "Level": ["WARN", "INFO", "INFO", "INFO"],
        "Content": ["Got exception while serving block blk_10", "Receiving block blk_10", "PacketResponder 1 terminating", "Verification succeeded"]
    })
    hdfs_eval = evaluate_hdfs_detection(dummy_hdfs)
    assert hdfs_eval["accuracy"] > 0.5
    assert hdfs_eval["sample_size"] == 4

    dummy_swe = pd.DataFrame({
        "repo": ["django/django", "django/django", "sympy/sympy"],
        "instance_id": ["django__django-100", "django__django-101", "sympy__sympy-200"],
        "patch": ["diff --git a/file.py", "diff --git b/file2.py", ""],
        "difficulty": ["<15 mins", "15 mins - 1 hour", None]
    })
    swe_eval = evaluate_swebench_retrieval(dummy_swe)
    assert swe_eval["total_issues"] == 3
    assert swe_eval["patch_available_count"] == 2
    assert swe_eval["patch_availability_rate"] == 66.7


# 15. Demonstration Mode Scenarios 1-5
def test_15_demonstration_scenarios_execution():
    demo_files = [
        "demo_samples/sample1_database_timeout_initial.log",
        "demo_samples/sample2_database_timeout_recurrence.log",
        "demo_samples/sample3_memory_oomkill.log",
        "demo_samples/sample4_authentication_jwt_expired.log",
        "demo_samples/sample5_empty.log"
    ]
    for rel_path in demo_files:
        p = PROJECT_ROOT / rel_path
        assert p.exists()
        with open(p, "r", encoding="utf-8") as f:
            content = f.read()

        det = detect_and_classify_incident(content)
        assert "error_category" in det
        assert "severity" in det

        inv = investigate_incident(
            error_message=det["error_message"],
            error_category=det["error_category"],
            severity=det["severity"],
            original_log=content,
            evidence=det["detected_evidence"]
        )
        assert "possible_root_cause" in inv
        assert "root_cause_confidence" in inv
