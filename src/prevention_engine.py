"""
RecallOps - Dynamic Prevention Intelligence Engine
Aggregates actual telemetry from HDFS cluster logs, SWE-bench defect history,
live database incidents, and Hindsight memory cache.
Detects recurring failure anti-patterns dynamically (frequency >= 2) and formulates
evidence-based prevention guardrails with zero hardcoded statistics.
"""

from typing import Dict, Any, List, Optional
import pandas as pd
from database import get_session, IncidentRecord
from hindsight_memory import get_local_memory_cache


def generate_prevention_insights(
    hdfs_df: Optional[pd.DataFrame] = None,
    swe_df: Optional[pd.DataFrame] = None
) -> Dict[str, Any]:
    """
    Analyzes live incident records and dataset telemetry to identify
    recurring failure anti-patterns and dynamically generate prevention runbooks.
    All statistics and trigger frequencies are computed strictly from real data.
    """
    recurring_signatures = []
    runbooks = []
    category_counts: Dict[str, int] = {}
    component_counts: Dict[str, int] = {}
    db_recurrences: Dict[str, int] = {}

    # 1. Analyze live database records dynamically
    session = get_session()
    total_live_incidents = 0
    try:
        db_records = session.query(IncidentRecord).all()
        total_live_incidents = len(db_records)
        for rec in db_records:
            cat = rec.error_category or "Unclassified"
            category_counts[cat] = category_counts.get(cat, 0) + 1
            comp = rec.component or "ApplicationCore"
            component_counts[comp] = component_counts.get(comp, 0) + 1

            # Track recurrence by category or signature
            sig_key = f"{cat} in {comp}"
            db_recurrences[sig_key] = db_recurrences.get(sig_key, 0) + 1
    finally:
        session.close()

    # Formulate dynamic runbooks for recurring live database patterns (frequency >= 2)
    rb_counter = 1
    for sig, count in db_recurrences.items():
        if count >= 2:
            recurring_signatures.append({
                "signature": f"Recurring live pattern: {sig}",
                "domain": "Production Live Telemetry",
                "occurrences": count,
                "severity": "High Recurrence",
                "evidence_source": f"RecallOps Incident Database ({count} live records)",
                "mitigation": "Automate health-check probes, scale connection pool limits, and enforce circuit breakers."
            })
            runbooks.append({
                "id": f"PREV-LIVE-0{rb_counter}",
                "title": f"Live Incident Recurrence Guard: {sig}",
                "trigger_evidence": f"{count} live incidents recorded in database matching '{sig}'.",
                "risk_level": "High Recurrence",
                "recommendation": (
                    f"1. Audit resource allocation and query concurrency for {sig}.\n"
                    f"2. Apply verified resolutions retained in RecallOps memory bank.\n"
                    f"3. Establish proactive metrics alerting when error rate exceeds 1% of request volume."
                ),
                "status": "Active Guardrail"
            })
            rb_counter += 1

    # 2. Analyze HDFS dataset dynamically if provided
    if hdfs_df is not None and not hdfs_df.empty:
        warn_slice = hdfs_df[hdfs_df["Level"] == "WARN"]
        warn_total = len(warn_slice)
        if warn_total > 0 and "EventTemplate" in warn_slice.columns:
            warn_events = warn_slice["EventTemplate"].value_counts()
            for template, count in warn_events.head(5).items():
                if int(count) >= 2:
                    recurring_signatures.append({
                        "signature": str(template),
                        "domain": "Distributed Storage (HDFS)",
                        "occurrences": int(count),
                        "severity": "Medium-High",
                        "evidence_source": f"HDFS Telemetry ({int(count)} WARN events detected)",
                        "mitigation": "Increase socket write timeout (dfs.datanode.socket.write.timeout) and configure TCP keepalives."
                    })
            # Formulate dynamic HDFS runbook from top event
            top_hdfs_template = warn_events.index[0]
            top_hdfs_count = int(warn_events.iloc[0])
            runbooks.append({
                "id": f"PREV-HDFS-0{rb_counter}",
                "title": "Distributed Storage Connection Timeout Guard",
                "trigger_evidence": f"{top_hdfs_count} occurrences of '{top_hdfs_template[:60]}...' detected in cluster logs.",
                "risk_level": "High Recurrence",
                "recommendation": (
                    "1. Audit client network latency to worker DataNodes.\n"
                    "2. Increase dfs.datanode.socket.write.timeout to 300,000ms.\n"
                    "3. Configure OS-level TCP keepalive probes with conservative intervals to prevent stale socket accumulation."
                ),
                "status": "Active Guardrail"
            })
            rb_counter += 1

    # 3. Analyze SWE-bench dataset dynamically if provided
    if swe_df is not None and not swe_df.empty and "repo" in swe_df.columns:
        top_repos = swe_df["repo"].value_counts().head(3)
        for repo_name, count in top_repos.items():
            if int(count) >= 2:
                recurring_signatures.append({
                    "signature": f"Defects and regressions in {repo_name}",
                    "domain": "Software Codebase (SWE-bench)",
                    "occurrences": int(count),
                    "severity": "High",
                    "evidence_source": f"SWE-bench Lite ({int(count)} issues cataloged)",
                    "mitigation": "Enforce automated unit test suite with boundary and null checks before pull request merge."
                })
        # Formulate dynamic SWE-bench runbook
        top_repo = top_repos.index[0]
        top_repo_count = int(top_repos.iloc[0])
        runbooks.append({
            "id": f"PREV-SWE-0{rb_counter}",
            "title": f"Codebase Regression Guard: {top_repo}",
            "trigger_evidence": f"{top_repo_count} historical defect cases cataloged in {top_repo}.",
            "risk_level": "Medium Recurrence",
            "recommendation": (
                f"1. Add linting rules to forbid unchecked query dereferencing in {top_repo}.\n"
                "2. Establish automated CI fixtures containing empty strings and NULL foreign keys.\n"
                "3. Provide fallback values for all unpopulated fields."
            ),
            "status": "Active Guardrail"
        })
        rb_counter += 1

    # 4. Analyze verified solutions in Hindsight memory cache
    memories = get_local_memory_cache()
    successful_fixes = [m for m in memories if m.get("verified") and m.get("applied_solution")]

    # Always ensure baseline systemic prevention runbook
    runbooks.append({
        "id": "PREV-SYS-01",
        "title": "Continuous Incident Experience Retention Guardrail",
        "trigger_evidence": f"{len(successful_fixes)} verified resolutions currently retained in RecallOps memory bank.",
        "risk_level": "Strategic",
        "recommendation": (
            "1. Require developer confirmation and resolution feedback for all closed incidents.\n"
            "2. Ingest post-mortem documentation directly into RecallOps / Hindsight memory banks.\n"
            "3. Review recurring failure tags during team architectural reviews."
        ),
        "status": "Active Guardrail"
    })

    return {
        "recurring_signatures": recurring_signatures,
        "prevention_runbooks": runbooks,
        "category_distribution": category_counts,
        "component_distribution": component_counts,
        "total_live_incidents": total_live_incidents,
        "verified_solutions_count": len(successful_fixes),
        "recent_verified_solutions": successful_fixes[:5],
        "has_live_recurrences": any(c >= 2 for c in db_recurrences.values())
    }
