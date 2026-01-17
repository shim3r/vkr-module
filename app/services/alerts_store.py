from collections import deque
from typing import Deque, Dict, List

_ALERTS: Deque[Dict] = deque(maxlen=500)

def add_alert(alert: Dict) -> None:
    _ALERTS.appendleft(alert)

def list_alerts(limit: int = 50) -> List[Dict]:
    return list(_ALERTS)[:limit]

def clear_alerts() -> None:
    _ALERTS.clear()

def count_alerts() -> int:
    return len(_ALERTS)