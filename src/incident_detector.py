"""
RecallOps - Incident Detector & Classifier
Classifies incident logs into 10 standard categories and estimates severity
using rule-based patterns and semantic heuristics.
Clearly distinguishes detected evidence, inferred conclusions, and uncertainties.
"""

import re
from typing import Dict, Any, List, Tuple
from log_processor import parse_log_payload

# 10 Standard Required Categories
CATEGORIES = [
    "Database connection errors",
    "Authentication errors",
    "Memory errors",
    "Network errors",
    "API failures",
    "Application exceptions",
    "Configuration errors",
    "Dependency errors",
    "Resource exhaustion",
    "Unknown or unclassified errors"
]

# Classification keyword mappings with weights
CATEGORY_RULES = {
    "Database connection errors": [
        r"database\s+connection", r"connection\s+refused.*(?:5432|3306|27017)",
        r"connection\s+pool", r"pool\s+exhausted", r"hikaripool",
        r"could\s+not\s+connect\s+to\s+server", r"db_timeout", r"deadlock\s+detected",
        r"database.*timeout", r"postgresql.*terminating",
        r"psycopg2\.(?:operationalerror|interfaceerror|databaseerror)",
        r"sqlalchemy\.(?:exc|engine)"
    ],
    "Authentication errors": [
        r"unauthorized", r"forbidden", r"invalid\s+token", r"jwt\s+expired",
        r"authentication\s+failed", r"access\s+denied", r"bad\s+credentials",
        r"permission\s+denied", r"oauth", r"401\s+unauthorized", r"403\s+forbidden"
    ],
    "Memory errors": [
        r"out\s+of\s+memory", r"java\.lang\.outofmemoryerror", r"oomkilled",
        r"heap\s+space", r"memory\s+exhausted", r"segmentation\s+fault",
        r"cannot\s+allocate\s+memory", r"memoryleak", r"sigsegv"
    ],
    "Network errors": [
        r"connection\s+timed\s+out", r"network\s+unreachable", r"connection\s+reset",
        r"broken\s+pipe", r"socket\s+write\s+timeout", r"packetresponder.*terminating",
        r"name\s+or\s+service\s+not\s+known", r"dns\s+lookup\s+failed", r"econnrefused",
        r"connection\s+aborted", r"sockettimeout"
    ],
    "API failures": [
        r"500\s+internal\s+server", r"502\s+bad\s+gateway", r"503\s+service\s+unavailable",
        r"504\s+gateway\s+timeout", r"api\s+endpoint", r"rest\s+client\s+error",
        r"http\s+request\s+failed", r"rate\s+limit\s+exceeded", r"429\s+too\s+many"
    ],
    "Application exceptions": [
        r"nullpointerexception", r"attributeerror", r"keyerror", r"valueerror",
        r"typeerror", r"indexerror", r"zerodivisionerror", r"syntaxerror",
        r"unhandled\s+exception", r"traceback\s+\(most\s+recent\s+call\s+last\)",
        r"runtimeerror", r"query.*crash"
    ],
    "Configuration errors": [
        r"missing\s+environment\s+variable", r"invalid\s+configuration",
        r"config\s+file\s+not\s+found", r"failed\s+to\s+parse\s+yaml",
        r"misconfigured", r"invalid\s+setting", r"unknown\s+host\s+in\s+config",
        r"configurationerror", r"environment\s+variable.*(?:not\s+set|missing)",
        r"configerror"
    ],
    "Dependency errors": [
        r"modulenotfounderror", r"importerror", r"classnotfoundexception",
        r"no\s+such\s+file\s+or\s+directory", r"dependency\s+conflict",
        r"version\s+mismatch", r"package.*not\s+installed",
        r"no\s+module\s+named", r"cannot\s+import\s+name"
    ],
    "Resource exhaustion": [
        r"no\s+space\s+left\s+on\s+device", r"too\s+many\s+open\s+files",
        r"disk\s+quota\s+exceeded", r"thread\s+limit\s+reached",
        r"cpu\s+throttling", r"fd\s+exhaustion", r"max\s+clients\s+reached"
    ]
}


def classify_category(text: str) -> Tuple[str, float]:
    """
    Classifies log text into one of the 10 standard categories.
    Returns (category_name, confidence_score).
    """
    text_lower = text.lower()
    best_category = "Unknown or unclassified errors"
    max_matches = 0

    for category, regex_list in CATEGORY_RULES.items():
        matches = 0
        for pattern in regex_list:
            if re.search(pattern, text_lower):
                matches += 1
        if matches > max_matches:
            max_matches = matches
            best_category = category

    if max_matches == 0:
        return "Unknown or unclassified errors", 0.35

    confidence = min(0.5 + (max_matches * 0.15), 0.95)
    return best_category, confidence


def estimate_severity(text: str, category: str) -> str:
    """
    Estimates incident severity: Critical, High, Medium, Low, Informational.
    """
    text_lower = text.lower()

    # Critical triggers
    if any(k in text_lower for k in ["fatal", "panic", "oomkilled", "segmentation fault", "data corruption", "cluster down"]):
        return "Critical"
    if category in ["Memory errors", "Resource exhaustion"] and any(k in text_lower for k in ["kill", "exhausted", "quota"]):
        return "Critical"

    # High triggers
    if any(k in text_lower for k in ["error", "exception", "failed", "refused", "timeout", "unauthorized", "deadlock"]):
        return "High"
    if category in ["Database connection errors", "Authentication errors"]:
        return "High"

    # Medium triggers
    if any(k in text_lower for k in ["warn", "warning", "retry", "slow", "deprecated"]):
        return "Medium"

    # Low / Informational triggers
    if any(k in text_lower for k in ["debug", "trace", "verbose"]):
        return "Low"
    if any(k in text_lower for k in ["info", "started", "completed", "succeeded", "registered"]):
        return "Informational"

    return "Medium"


def detect_and_classify_incident(raw_log: str, source: str = "Live Ingestion") -> Dict[str, Any]:
    """
    Performs complete detection, parsing, category classification, and severity estimation.
    """
    parsed = parse_log_payload(raw_log)
    category, cat_confidence = classify_category(raw_log)
    severity = estimate_severity(raw_log, category)

    # Distinguish evidence from inferences
    evidence = parsed["evidence"]
    if not evidence:
        evidence = [f"Log snippet: {parsed['error_message'][:150]}"]

    inferred_conclusion = f"The incident exhibits signatures characteristic of {category} with an estimated severity of {severity}."
    uncertainties = []

    if category == "Unknown or unclassified errors":
        uncertainties.append("Log does not match standard deterministic failure signatures. Contextual LLM evaluation recommended.")
    elif cat_confidence < 0.6:
        uncertainties.append(f"Confidence score is moderate ({cat_confidence * 100:.0f}%). Secondary symptoms may point to cascading network/service faults.")

    if severity == "Critical":
        uncertainties.append("High-impact event detected; verify immediately whether dependent services are experiencing brownouts.")

    return {
        "original_log": raw_log,
        "error_message": parsed["error_message"],
        "error_category": category,
        "category_confidence": round(cat_confidence, 2),
        "severity": severity,
        "detected_evidence": evidence,
        "inferred_conclusion": inferred_conclusion,
        "uncertainties": uncertainties,
        "timestamp": parsed["timestamp"],
        "component": parsed["component"],
        "lines_count": parsed["lines_count"],
        "source": source
    }

