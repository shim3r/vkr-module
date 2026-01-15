from collections import deque
from typing import Deque, Dict, List

# In-memory store for incidents (demo mode)
_INCIDENTS: Deque[Dict] = deque(maxlen=200)


def add_incident(inc: Dict) -> None:
    """Add a new incident to the store."""
    _INCIDENTS.appendleft(inc)


def list_incidents(limit: int = 50) -> List[Dict]:
    """Return latest incidents (most recent first)."""
    return list(_INCIDENTS)[:limit]


def clear_incidents() -> None:
    """Clear all stored incidents (in-memory)."""
    _INCIDENTS.clear()
