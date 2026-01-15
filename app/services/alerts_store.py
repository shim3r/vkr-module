from collections import deque
from typing import Deque, Dict, List

_ALERTS: Deque[Dict] = deque(maxlen=200)

def add_alert(event: Dict) -> None:
    _ALERTS.appendleft(event)

def list_alerts(limit: int = 50) -> List[Dict]:
    return list(_ALERTS)[:limit]
