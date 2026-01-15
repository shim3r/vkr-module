from collections import deque
from typing import Deque, Dict, List

# Храним последние N нормализованных событий (для корреляции)
_EVENTS: Deque[Dict] = deque(maxlen=5000)

def add_event(evt: Dict) -> None:
    _EVENTS.append(evt)

def list_events(limit: int = 200) -> List[Dict]:
    return list(_EVENTS)[-limit:]

def all_events() -> List[Dict]:
    return list(_EVENTS)
