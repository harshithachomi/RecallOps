"""
RecallOps - AI Root-Cause Investigation Engine
Integrates Groq LLM API (when configured) with deterministic fallback analysis.
Categorizes root cause confidence as Confirmed, Likely, or Possible.
Prioritizes past verified solutions, detects anti-patterns from past failures,
and generates structured investigation reports with zero fabrication.
"""

import os
import json
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

load_dotenv()


def build_evidence_based_fallback(
    error_message: str,
    error_category: str,
    severity: str,
    evidence: List[str],
    retrieved_memories: Optional[List[Dict[str, Any]]] = None,
    component: Optional[str] = None
) -> Dict[str, Any]:
    """
    Deterministic, highly explainable root-cause investigation engine.
    Used when Groq API credentials are not supplied or network is unavailable.
    Clearly labels that it is evidence-based and does not fabricate AI answers.
    """
    # Category-specific domain knowledge mapping
    KNOWLEDGE_BASE = {
        "Database connection errors": {
            "root_cause": "Database connection pool starvation or downstream TCP socket timeout.",
            "explanation": "The application service failed to acquire an active database connection within the configured timeout window. This commonly occurs during connection spikes, unclosed transactions, or network partitions between the application tier and database host.",
            "solutions": [
                "Inspect active connections on the database server (e.g. SELECT * FROM pg_stat_activity).",
                "Increase application connection pool max size and configure aggressive idle connection reaping.",
                "Verify database firewall rules and network latency between cluster worker nodes and database port.",
                "Review application code for uncommitted transactions or missing session.close() calls."
            ],
            "preventive_measures": [
                "Implement database connection pool metrics with alerting thresholds at 80% saturation.",
                "Configure connection health check probes (e.g., SELECT 1) with retry backoff."
            ]
        },
        "Authentication errors": {
            "root_cause": "Invalid authentication credentials, expired cryptographic token, or misconfigured permission claim.",
            "explanation": "Incoming request authorization failed at the security boundary. This typically indicates signature verification failure, clock drift on token validation, or revoked credentials.",
            "solutions": [
                "Verify validity and expiration timestamp of the bearer JWT or API token.",
                "Check server clock synchronization (NTP) to eliminate token validation drift.",
                "Inspect authentication service logs for credential rotation or key revocation events."
            ],
            "preventive_measures": [
                "Add automated token refresh handlers prior to expiration.",
                "Implement structured alerting for spikes in 401/403 HTTP status codes."
            ]
        },
        "Memory errors": {
            "root_cause": "JVM/Process heap exhaustion or container cgroup memory limit violation (OOMKill).",
            "explanation": "The process attempted an allocation exceeding the available system memory or container quota. Frequently caused by unbounded data streaming, large unpaged database queries, or retained reference leaks.",
            "solutions": [
                "Examine heap dump or container cgroup memory consumption graphs.",
                "Verify if recent requests loaded massive unpaged result sets into memory.",
                "Increase container memory allocation or adjust -Xmx / process memory limits."
            ],
            "preventive_measures": [
                "Enforce strict pagination limits on all query endpoints.",
                "Configure memory usage warning alerts at 75% container utilization."
            ]
        },
        "Network errors": {
            "root_cause": "Inter-node socket write timeout, connection reset, or transient network partition.",
            "explanation": "The socket connection was abruptly terminated or timed out during data transfer. Often triggered by client buffer saturation, MTU mismatches, or keepalive expiration.",
            "solutions": [
                "Increase socket write and read timeout thresholds on the transferring node.",
                "Inspect packet drops and network interface statistics (netstat / ifconfig).",
                "Verify health and responsiveness of the destination host / DataNode."
            ],
            "preventive_measures": [
                "Enable TCP keepalive probes with conservative intervals on cluster interconnects.",
                "Implement exponential backoff retry policies for distributed I/O operations."
            ]
        },
        "API failures": {
            "root_cause": "Upstream service unavailability, gateway timeout, or unhandled 5xx HTTP response.",
            "explanation": "An external or microservice API call failed or timed out. Usually caused by dependency degradation, downstream cold starts, or rate limit throttling.",
            "solutions": [
                "Inspect downstream API health status endpoints and latency metrics.",
                "Review request payload for schema compliance or rate limit header responses.",
                "Enable circuit breaker pattern to prevent cascading thread starvation."
            ],
            "preventive_measures": [
                "Implement circuit breakers with graceful fallback responses.",
                "Set realistic client-side timeouts on all outbound HTTP calls."
            ]
        },
        "Application exceptions": {
            "root_cause": "Unhandled runtime exception, unexpected null value, or invariant violation in code logic.",
            "explanation": "An unexpected condition triggered an uncaught exception in the application runtime. This points to missing input validation, edge-case data, or regression in recent commits.",
            "solutions": [
                "Trace the full stack trace to pinpoint the failing module and line number.",
                "Add defensive guards (e.g. null checks, type assertions, or try-except blocks).",
                "Examine input payloads that triggered the failure to construct reproducing regression tests."
            ],
            "preventive_measures": [
                "Add automated regression test coverage for boundary conditions and null values.",
                "Enforce static code analysis and linting in CI/CD pipelines."
            ]
        },
        "Configuration errors": {
            "root_cause": "Missing, malformed, or mismatched environment configuration setting.",
            "explanation": "The application could not parse or locate a required configuration variable or file at initialization.",
            "solutions": [
                "Inspect environment variables in the active deployment pod or container.",
                "Validate configuration file syntax against the required schema (e.g. YAML/JSON).",
                "Ensure secret managers or .env files are correctly mounted in the execution path."
            ],
            "preventive_measures": [
                "Add startup schema validation that fails fast with explicit error messages.",
                "Automate environment configuration drift auditing across environments."
            ]
        },
        "Dependency errors": {
            "root_cause": "Missing library package, binary incompatibility, or version conflict.",
            "explanation": "A required module or shared object could not be loaded at runtime.",
            "solutions": [
                "Verify installation of dependencies listed in requirements.txt or environment files.",
                "Check Python/runtime architecture compatibility (e.g. 64-bit vs 32-bit).",
                "Rebuild container image or virtual environment cleanly."
            ],
            "preventive_measures": [
                "Pin exact dependency versions using lockfiles.",
                "Run automated container image verification before deployment."
            ]
        },
        "Resource exhaustion": {
            "root_cause": "System resource saturation (file descriptors, disk space, or process thread limits).",
            "explanation": "The operating system refused resource allocation due to reaching configured limits.",
            "solutions": [
                "Check disk space usage (df -h) and inode availability (df -i).",
                "Inspect open file descriptor count (lsof | wc -l) and adjust ulimit if necessary.",
                "Clean up temporary files, stale cache directories, or rotated log files."
            ],
            "preventive_measures": [
                "Configure automated log rotation and disk cleanup policies.",
                "Monitor file descriptor and thread count metrics in infrastructure dashboards."
            ]
        }
    }

    kb_entry = KNOWLEDGE_BASE.get(error_category, {
        "root_cause": "Unclassified anomaly requiring contextual log investigation.",
        "explanation": "The log signature does not cleanly match standard automated failure templates. Contextual inspection of preceding and succeeding log lines is recommended.",
        "solutions": [
            "Inspect raw stack trace and surrounding log telemetry for correlated anomalies.",
            "Cross-reference system metrics (CPU, Memory, Network) around the incident timestamp.",
            "Consult component documentation and recent deployment change logs."
        ],
        "preventive_measures": [
            "Add structured telemetry logging around this code path.",
            "Retain verified resolution in Hindsight memory for future automated matching."
        ]
    })

    # Classify Root Cause Confidence: Confirmed vs Likely vs Possible
    root_cause_confidence = "Likely"
    anti_pattern_warnings: List[str] = []
    successful_memories: List[Dict[str, Any]] = []
    experience_context = None

    if retrieved_memories:
        for mem in retrieved_memories:
            is_anti = mem.get("is_anti_pattern", False) or "unsuccessful" in mem.get("outcome", "").lower()
            if is_anti:
                sol = mem.get("applied_solution", "Proposed solution")
                inc_ref = mem.get("incident_id", "Prior incident")
                reason = mem.get("notes") or "Failed to resolve underlying root cause"
                anti_pattern_warnings.append(
                    f"⚠️ [ANTI-PATTERN WARNING] Avoid action: '{sol}'. Previously attempted in {inc_ref} and confirmed unsuccessful ({reason})."
                )
            elif mem.get("verified") and mem.get("applied_solution"):
                successful_memories.append(mem)

        # If a high-similarity verified past incident exists, escalate confidence to Confirmed!
        if successful_memories:
            top_mem = successful_memories[0]
            rel_score = top_mem.get("relevance_score", 0.0)
            if rel_score >= 0.75:
                root_cause_confidence = "Confirmed"
                experience_context = (
                    f"Prior incident {top_mem.get('incident_id')} matched with {top_mem.get('relevance', 'high confidence')}. "
                    f"Verified resolution from past experience is available."
                )
            else:
                root_cause_confidence = "Likely"
                experience_context = f"Relevant historical precedent found in {top_mem.get('incident_id')}."
    elif len(evidence) >= 2:
        root_cause_confidence = "Likely"
    else:
        root_cause_confidence = "Possible"

    # Build prioritized solutions
    solutions = list(kb_entry["solutions"])
    if successful_memories:
        top_mem = successful_memories[0]
        top_past_sol = top_mem.get("applied_solution", "")
        top_inc_id = top_mem.get("incident_id", "HISTORICAL-REF")
        solutions.insert(0, f"[FROM PAST VERIFIED EXPERIENCE - {top_inc_id}] Applied fix that previously resolved similar incident: {top_past_sol}")

    return {
        "analysis_source": "Deterministic Evidence-Based Engine (Groq API Key Not Configured)",
        "incident_summary": f"Incident detected in {component or 'ApplicationCore'}: {error_message[:150]}",
        "error_category": error_category,
        "severity": severity,
        "detected_evidence": evidence,
        "possible_root_cause": kb_entry["root_cause"],
        "root_cause_confidence": root_cause_confidence,
        "explanation": kb_entry["explanation"],
        "recommended_solutions": solutions,
        "anti_pattern_warnings": anti_pattern_warnings,
        "recalled_experience_context": experience_context,
        "preventive_measures": kb_entry["preventive_measures"],
        "confidence": root_cause_confidence,
        "related_historical_incidents": retrieved_memories or [],
        "uncertainty_note": "Root causes listed are hypotheses based on log evidence and historical failure patterns. Developers should verify cluster state before applying destructive changes."
    }


def investigate_incident(
    error_message: str,
    error_category: str,
    severity: str,
    original_log: str,
    evidence: List[str],
    retrieved_memories: Optional[List[Dict[str, Any]]] = None,
    component: Optional[str] = None
) -> Dict[str, Any]:
    """
    Main investigation entrypoint. Calls Groq LLM API if configured,
    or smoothly falls back to the deterministic evidence-based engine.
    Ensures root cause confidence (Confirmed, Likely, Possible) and anti-pattern warnings.
    """
    groq_api_key = os.getenv("GROQ_API_KEY", "").strip()

    if not groq_api_key:
        return build_evidence_based_fallback(
            error_message=error_message,
            error_category=error_category,
            severity=severity,
            evidence=evidence,
            retrieved_memories=retrieved_memories,
            component=component
        )

    try:
        from groq import Groq
        client = Groq(api_key=groq_api_key)

        # Build memory context and anti-pattern blocks
        memory_context = ""
        anti_patterns = []
        has_verified_past_fix = False

        if retrieved_memories:
            memory_context = "PREVIOUS INCIDENT EXPERIENCES FROM HINDSIGHT MEMORY:\n"
            for idx, m in enumerate(retrieved_memories[:4], 1):
                inc_id = m.get("incident_id", "REF")
                summary = m.get("summary") or m.get("problem_statement", "")[:180]
                sol = m.get("applied_solution") or m.get("patch", "")[:200]
                outcome = m.get("outcome", "Unknown")
                is_anti = m.get("is_anti_pattern", False) or "unsuccessful" in outcome.lower()
                if is_anti:
                    anti_patterns.append(f"Incident {inc_id} tried '{sol}' which FAILED.")
                else:
                    has_verified_past_fix = True
                memory_context += f"Memory #{idx} [{inc_id}]: {summary} | Solution: {sol} | Outcome: {outcome}\n"

        system_prompt = (
            "You are RecallOps, an expert AI incident response investigator. "
            "Analyze the software error log and evidence provided. "
            "Prioritize previous verified successful resolutions when relevant. "
            "Explicitly warn against anti-patterns (solutions that previously failed). "
            "Classify root cause confidence strictly as 'Confirmed' (if high-similarity verified past match exists), "
            "'Likely' (if strong log evidence matches known failure mode), or 'Possible' (if ambiguous). "
            "Respond ONLY with a valid, clean JSON object matching this exact schema:\n"
            "{\n"
            '  "incident_summary": "Concise summary",\n'
            '  "error_category": "Standard category name",\n'
            '  "severity": "Critical|High|Medium|Low|Informational",\n'
            '  "detected_evidence": ["Evidence point 1", "Evidence point 2"],\n'
            '  "possible_root_cause": "Hypothesis for the root cause",\n'
            '  "root_cause_confidence": "Confirmed|Likely|Possible",\n'
            '  "explanation": "Detailed technical explanation",\n'
            '  "recommended_solutions": ["Solution 1", "Solution 2"],\n'
            '  "anti_pattern_warnings": ["Warning 1 if any failed solutions exist"],\n'
            '  "recalled_experience_context": "Explanation of how past memory was used",\n'
            '  "preventive_measures": ["Measure 1", "Measure 2"],\n'
            '  "confidence": "Confirmed|Likely|Possible",\n'
            '  "uncertainty_note": "Any nuances or uncertain factors"\n'
            "}\n"
            "Do not include markdown code fences or conversational text outside the JSON."
        )

        user_content = (
            f"ERROR MESSAGE: {error_message}\n"
            f"CATEGORY: {error_category}\n"
            f"SEVERITY: {severity}\n"
            f"COMPONENT: {component or 'Unknown'}\n"
            f"DETECTED EVIDENCE: {json.dumps(evidence)}\n"
            f"RAW LOG CONTEXT:\n{original_log[:1500]}\n\n"
            f"{memory_context}\n"
            "If previous verified solutions exist, leverage them at the top of recommended_solutions."
        )

        chat_completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            model="llama-3.3-70b-versatile",
            temperature=0.2,
            max_tokens=1024
        )

        response_text = chat_completion.choices[0].message.content.strip()
        if response_text.startswith("```"):
            response_text = response_text.split("```")[1]
            if response_text.startswith("json"):
                response_text = response_text[4:].strip()

        parsed_json = json.loads(response_text)
        parsed_json["analysis_source"] = "Groq LLaMA-3.3-70B AI Model"
        parsed_json["related_historical_incidents"] = retrieved_memories or []

        # Guarantee confidence tag consistency
        if "root_cause_confidence" not in parsed_json:
            parsed_json["root_cause_confidence"] = "Confirmed" if has_verified_past_fix else "Likely"

        return parsed_json

    except Exception as e:
        # Fallback with explicit error note
        fallback = build_evidence_based_fallback(
            error_message=error_message,
            error_category=error_category,
            severity=severity,
            evidence=evidence,
            retrieved_memories=retrieved_memories,
            component=component
        )
        fallback["analysis_source"] = f"Deterministic Fallback (Groq API attempt failed: {str(e)})"
        return fallback
