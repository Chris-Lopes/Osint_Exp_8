from typing import Any, Dict
from datetime import datetime, timezone

def to_stix_like(raw: Dict[str, Any], source: str) -> Dict[str, Any]:
    """Transform arbitrary raw items into a small STIX-like shape."""
    now = datetime.now(timezone.utc).isoformat()
    return {
        "indicator": raw.get("indicator") or raw.get("ioc") or "",
        "indicator_type": raw.get("type") or "",
        "first_seen": raw.get("first_seen") or now,
        "last_seen": raw.get("last_seen") or now,
        "source": source,
        "confidence": raw.get("confidence") or "medium",
        "references": raw.get("references") or [],
    }