from typing import Dict, Tuple

SOURCE_WEIGHT = {"firewall": 10, "av": 8, "edr": 6, "iam": 5, "arm": 3}

CRITICAL_MARKERS = [
    "VPN_LOGIN_FAIL", "PORTSCAN", "AV_DETECT", "MALWARE_DETECT",
    "credential_dumping", "ransom", "C2",
    "4688", "4697", "GROUP_ADD", "ACCOUNT_LOCK",
]

def score(payload: Dict) -> Tuple[int, str, bool]:
    src = (payload.get("source_type") or "unknown").lower()
    base = SOURCE_WEIGHT.get(src, 2)

    data = payload.get("data")
    text = " ".join(map(str, data.values())) if isinstance(data, dict) else str(data or "")

    hits = sum(1 for m in CRITICAL_MARKERS if m.lower() in text.lower())
    risk = min(100, base * 6 + hits * 12)

    if risk >= 70:
        priority = "critical"
    elif risk >= 45:
        priority = "high"
    elif risk >= 25:
        priority = "medium"
    else:
        priority = "low"

    return risk, priority, priority in ("high", "critical")
