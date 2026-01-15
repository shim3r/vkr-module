from collections import deque
from typing import Deque, Dict, List

_INCIDENTS: Deque[Dict] = deque(maxlen=200)

def add_incident(inc: Dict) -> None:
    _INCIDENTS.appendleft(inc)

def list_incidents(limit: int = 50) -> List[Dict]:
    return list(_INCIDENTS)[:limit]
