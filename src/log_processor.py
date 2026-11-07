"""
RecallOps - Log Processor
Extracts timestamps, severity levels, components, and clean error messages
from unstructured server logs, stack traces, and structured CSV/text logs.
"""

import re
import csv
import io
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

# Common regex patterns for log level extraction
LEVEL_PATTERNS = [
    (r"\b(FATAL|CRITICAL)\b", "Critical"),
    (r"\b(ERROR|ERR|EXCEPTION|FAIL|FAILED)\b", "High"),
    (r"\b(WARN|WARNING)\b", "Medium"),
    (r"\b(INFO|NOTICE)\b", "Informational"),
    (r"\b(DEBUG|TRACE)\b", "Low"),
]

# Timestamp regex patterns
TIMESTAMP_PATTERNS = [
    # ISO 8601: 2026-11-06T14:22:10 or 2026-11-06 14:22:10
    r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b",
    # Date + Time: 2026-11-06 14:22:10
    r"\b(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\b",
    # HDFS style: 081109 203518 (YYMMDD HHMMSS)
    r"\b(\d{6}\s+\d{6})\b",
    # Syslog: Nov 06 14:22:10
    r"\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b"
]

# Component extraction patterns
COMPONENT_PATTERNS = [
    r"\[([a-zA-Z0-9_\-\.]+)\]",  # [DataNode], [auth-service]
    r"([a-zA-Z0-9_\-\.]+)::",     # Service::method
    r"dfs\.([a-zA-Z0-9_\.]+)",     # dfs.DataNode$PacketResponder
    r"org\.apache\.hadoop\.[a-zA-Z0-9_\.]+\.([a-zA-Z0-9_]+)",
    r"component=([a-zA-Z0-9_\-]+)",
    r"service=([a-zA-Z0-9_\-]+)",
    r"logger=([a-zA-Z0-9_\-\.]+)"
]


def extract_log_level(text: str) -> str:
    """
    Extracts the normalized log severity level from text.
    """
    upper_text = text.upper()
    for pattern, normalized in LEVEL_PATTERNS:
        if re.search(pattern, upper_text):
            return normalized
    return "Medium"  # Default fallback


def extract_timestamp(text: str) -> Optional[str]:
    """
    Extracts timestamp string from a log entry if present.
    """
    for pattern in TIMESTAMP_PATTERNS:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    return None


def extract_component(text: str) -> str:
    """
    Identifies the component or service associated with the log.
    """
    for pattern in COMPONENT_PATTERNS:
        match = re.search(pattern, text)
        if match:
            return match.group(1)

    # Heuristic component detection for common system keywords
    lower = text.lower()
    if "datanode" in lower:
        return "DataNode"
    elif "namenode" in lower:
        return "NameNode"
    elif "database" in lower or "postgres" in lower or "mysql" in lower:
        return "DatabaseService"
    elif "auth" in lower or "jwt" in lower or "token" in lower:
        return "AuthService"
    elif "api" in lower or "gateway" in lower or "endpoint" in lower:
        return "ApiGateway"
    elif "memory" in lower or "heap" in lower or "oom" in lower:
        return "SystemMemory"

    return "ApplicationCore"


def extract_error_signature(text: str) -> str:
    """
    Extracts the core concise error line or exception summary.
    """
    lines = [l.strip() for l in text.strip().splitlines() if l.strip()]
    if not lines:
        return "Empty log received"

    # Prioritize line containing Exception, Error, or Fail
    for line in lines:
        if any(keyword in line.lower() for keyword in ["exception:", "error:", "failed to", "fatal:"]):
            return line[:300]

    # Otherwise return the first substantial line
    return lines[0][:300]


def parse_log_payload(content: str, filename: Optional[str] = None) -> Dict[str, Any]:
    """
    Parses a log payload (single entry, multi-line stack trace, or log dump).
    Returns a structured dictionary with metadata and extracted evidence.
    """
    clean_content = content.strip()
    if not clean_content:
        return {
            "error_message": "Empty log entry provided",
            "log_level": "Informational",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "component": "Unknown",
            "lines_count": 0,
            "raw_log": "",
            "evidence": []
        }

    lines = clean_content.splitlines()
    error_msg = extract_error_signature(clean_content)
    log_level = extract_log_level(clean_content)
    timestamp = extract_timestamp(clean_content) or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    component = extract_component(clean_content)

    # Extract detected evidence fragments
    evidence = []
    for line in lines:
        line_clean = line.strip()
        if any(term in line_clean.lower() for term in [
            "timeout", "exception", "failed", "refused", "denied",
            "exhausted", "not found", "broken pipe", "terminating", "null"
        ]):
            if len(line_clean) <= 250 and line_clean not in evidence:
                evidence.append(line_clean)
        if len(evidence) >= 5:
            break

    if not evidence and lines:
        evidence.append(lines[0][:200])

    return {
        "error_message": error_msg,
        "log_level": log_level,
        "timestamp": timestamp,
        "component": component,
        "lines_count": len(lines),
        "raw_log": clean_content,
        "evidence": evidence
    }


def parse_csv_logs(csv_text: str) -> List[Dict[str, Any]]:
    """
    Parses CSV-formatted logs, extracting standard fields when available.
    """
    results = []
    reader = csv.DictReader(io.StringIO(csv_text))
    for idx, row in enumerate(reader):
        if idx >= 100:  # Bound preview limit
            break
        content = row.get("Content") or row.get("message") or row.get("log") or str(row)
        level = row.get("Level") or row.get("level") or extract_log_level(content)
        comp = row.get("Component") or row.get("component") or extract_component(content)
        ts = row.get("Date", "") + " " + row.get("Time", "") if "Date" in row and "Time" in row else extract_timestamp(content)

        results.append({
            "error_message": extract_error_signature(content),
            "log_level": level,
            "component": comp,
            "timestamp": ts.strip() if ts else datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "raw_log": content,
            "evidence": [content[:200]]
        })
    return results
