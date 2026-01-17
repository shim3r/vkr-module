from collections import deque
from typing import Deque, Dict, List

_EVENTS: Deque[Dict] = deque(maxlen=1000)

def add_event(event: Dict) -> None:
    _EVENTS.appendleft(event)

def list_events(limit: int = 100) -> List[Dict]:
    return list(_EVENTS)[:limit]

def all_events() -> List[Dict]:
    return list(_EVENTS)

def count_events() -> int:
    return len(_EVENTS)

def clear_events() -> None:
    _EVENTS.clear()