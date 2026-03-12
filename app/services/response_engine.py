"""
Active Response Engine — движок активного реагирования на инциденты.

TO-BE: после создания инцидента pipeline вызывает auto_respond(),
который определяет действие (блокировка IP, изоляция хоста, деактивация
пользователя) и применяет его.

Архитектура симулированная: реальная блокировка производится через адаптер
(iptables, AD API и т.п.) — заменить _apply_block_ip / _apply_isolate_host /
_apply_disable_user в одной точке без изменения остального кода.

Действия применяются только для инцидентов с severity critical/high.
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Set
from uuid import uuid4

logger = logging.getLogger("siem.response_engine")

# ---------------------------------------------------------------------------
# State stores (in-memory, thread-safe via lock)
# ---------------------------------------------------------------------------

_LOCK = threading.Lock()

_BLOCKED_IPS: Set[str] = set()
_BLOCKED_USERS: Set[str] = set()
_ISOLATED_HOSTS: Set[str] = set()

_ACTIONS: Deque[Dict[str, Any]] = deque(maxlen=500)


# ---------------------------------------------------------------------------
# Mapping: incident type → list of (action_type, target_field)
# ---------------------------------------------------------------------------

# target_field — ключ в инциденте, из которого берём цель действия
_INCIDENT_RESPONSE_MAP: Dict[str, List[tuple]] = {
    # Сетевые атаки / брутфорс → блокировать атакующий IP
    "BRUTEFORCE_VPN":       [("block_ip", "src_ip")],
    "PORT_SCAN":            [("block_ip", "src_ip")],
    "IAM_PASSWORD_SPRAY":   [("block_ip", "src_ip")],
    "ENDPOINT_BRUTEFORCE":  [("block_ip", "src_ip")],

    # Вредоносная активность → изолировать хост
    "MALWARE_DETECTED":     [("isolate_host", "host")],
    "AV_TAMPER":            [("isolate_host", "host")],
    "AV_CLEAN_FAILED":      [("isolate_host", "host")],
    "RANSOMWARE_BEHAVIOR":  [("isolate_host", "host"), ("block_ip", "src_ip")],

    # Компрометация учётных данных → блокировать IP + деактивировать учётку
    "CREDENTIAL_DUMP":       [("isolate_host", "host"), ("disable_user", "user")],
    "LATERAL_MOVEMENT":      [("block_ip", "src_ip"), ("disable_user", "user")],
    "EDR_LATERAL_ACTIVITY":  [("block_ip", "src_ip"), ("disable_user", "user")],
    "SUSPICIOUS_PROCESS":    [("isolate_host", "host")],

    # Многоэтапные цепочки — сразу и IP и хост
    "VPN_BRUTE_CHAIN":      [("block_ip", "src_ip"), ("isolate_host", "host")],
}

# severity при которых реагирование происходит автоматически
_AUTO_RESPOND_SEVERITIES = {"critical", "high"}


# ---------------------------------------------------------------------------
# Internal: симулированные адаптеры (заменить реальной реализацией)
# ---------------------------------------------------------------------------

def _apply_block_ip(ip: str) -> bool:
    """Заблокировать IP-адрес (симуляция — iptables / ACL)."""
    logger.warning("[RESPONSE] BLOCK IP: %s — команда применена (симуляция)", ip)
    _BLOCKED_IPS.add(ip)
    return True


def _revoke_block_ip(ip: str) -> bool:
    """Снять блокировку IP."""
    logger.info("[RESPONSE] UNBLOCK IP: %s", ip)
    _BLOCKED_IPS.discard(ip)
    return True


def _apply_isolate_host(host: str) -> bool:
    """Изолировать хост (симуляция — NAC / firewall policy)."""
    logger.warning("[RESPONSE] ISOLATE HOST: %s — хост изолирован (симуляция)", host)
    _ISOLATED_HOSTS.add(host)
    return True


def _revoke_isolate_host(host: str) -> bool:
    """Снять изоляцию хоста."""
    logger.info("[RESPONSE] UNISOLATE HOST: %s", host)
    _ISOLATED_HOSTS.discard(host)
    return True


def _apply_disable_user(user: str) -> bool:
    """Деактивировать учётную запись пользователя (симуляция — AD / IAM)."""
    logger.warning("[RESPONSE] DISABLE USER: %s — учётная запись деактивирована (симуляция)", user)
    _BLOCKED_USERS.add(user)
    return True


def _revoke_disable_user(user: str) -> bool:
    """Восстановить учётную запись пользователя."""
    logger.info("[RESPONSE] ENABLE USER: %s", user)
    _BLOCKED_USERS.discard(user)
    return True


# ---------------------------------------------------------------------------
# Internal: построение + применение одного действия
# ---------------------------------------------------------------------------

_ACTION_APPLY_FN = {
    "block_ip":      (_apply_block_ip,      _revoke_block_ip),
    "isolate_host":  (_apply_isolate_host,  _revoke_isolate_host),
    "disable_user":  (_apply_disable_user,  _revoke_disable_user),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_action(
    incident: Dict[str, Any],
    action_type: str,
    target: str,
    status: str,
    notes: str = "",
) -> Dict[str, Any]:
    return {
        "action_id":   f"RA-{uuid4().hex[:10].upper()}",
        "incident_id": incident.get("incident_id", ""),
        "incident_type": incident.get("type", ""),
        "action_type": action_type,
        "target":      target,
        "status":      status,  # applied | failed | skipped | revoked
        "created_at":  _now(),
        "revoked_at":  None,
        "notes":       notes,
    }


def _execute_action(incident: Dict[str, Any], action_type: str, target_field: str) -> Optional[Dict[str, Any]]:
    """Применить одно действие. Возвращает ResponseAction или None если цель не найдена."""
    # Извлечь цель (строка или список)
    raw = incident.get(target_field)
    if not raw:
        # fallback: пробуем смежные поля
        if target_field == "src_ip":
            raw = incident.get("src_ip") or incident.get("host")
        elif target_field == "host":
            raw = incident.get("host") or incident.get("src_ip")
        elif target_field == "user":
            users = incident.get("users") or []
            raw = users[0] if users else incident.get("user")

    if not raw:
        logger.debug("[RESPONSE] no target for action=%s field=%s incident=%s",
                     action_type, target_field, incident.get("incident_id"))
        return None

    # Если список — берём первый элемент
    target = raw if isinstance(raw, str) else str(raw[0]) if raw else None
    if not target:
        return None

    try:
        apply_fn, _ = _ACTION_APPLY_FN[action_type]
        success = apply_fn(target)
        status = "applied" if success else "failed"
        notes = f"Auto-response to {incident.get('type')} [{incident.get('severity')}]"
    except Exception as exc:
        logger.exception("[RESPONSE] Failed to apply %s on %s: %s", action_type, target, exc)
        status = "failed"
        notes = str(exc)

    action = _build_action(incident, action_type, target, status, notes)
    return action


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def auto_respond(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Определить и применить все подходящие действия для инцидента.

    Правила:
    - Применяется только для severity critical/high
    - Для medium/low — записывается рекомендация без применения
    - Результаты записываются в журнал _ACTIONS

    Returns: список словарей ResponseAction
    """
    severity = str(incident.get("severity") or "").lower()
    inc_type  = str(incident.get("type") or "")
    inc_id    = incident.get("incident_id", "?")

    actions: List[Dict[str, Any]] = []

    # Определить набор действий для данного типа
    response_spec = _INCIDENT_RESPONSE_MAP.get(inc_type)
    if not response_spec:
        logger.debug("[RESPONSE] No response spec for incident type=%s id=%s", inc_type, inc_id)
        return []

    if severity not in _AUTO_RESPOND_SEVERITIES:
        # Записываем рекомендацию, но не применяем
        action = _build_action(
            incident,
            action_type="recommend",
            target=incident.get("src_ip") or incident.get("host") or "?",
            status="skipped",
            notes=f"Auto-response skipped: severity={severity} (threshold: critical/high)",
        )
        with _LOCK:
            _ACTIONS.appendleft(action)
        logger.info("[RESPONSE] Skipping auto-response for %s (severity=%s)", inc_type, severity)
        return [action]

    for action_type, target_field in response_spec:
        action = _execute_action(incident, action_type, target_field)
        if action:
            actions.append(action)
            with _LOCK:
                _ACTIONS.appendleft(action)
            logger.info(
                "[RESPONSE] Applied: %s on %s for incident %s [%s]",
                action_type, action["target"], inc_id, severity,
            )

    return actions


def manually_block_ip(ip: str, reason: str = "manual", actor: str = "analyst") -> Dict[str, Any]:
    """Ручная блокировка IP без привязки к инциденту."""
    _apply_block_ip(ip)
    action = {
        "action_id":    f"RA-{uuid4().hex[:10].upper()}",
        "incident_id":  None,
        "incident_type": None,
        "action_type":  "block_ip",
        "target":       ip,
        "status":       "applied",
        "created_at":   _now(),
        "revoked_at":   None,
        "notes":        f"Manual block by {actor}: {reason}",
    }
    with _LOCK:
        _ACTIONS.appendleft(action)
    return action


def manually_isolate_host(host: str, reason: str = "manual", actor: str = "analyst") -> Dict[str, Any]:
    """Ручная изоляция хоста без привязки к инциденту."""
    _apply_isolate_host(host)
    action = {
        "action_id":    f"RA-{uuid4().hex[:10].upper()}",
        "incident_id":  None,
        "incident_type": None,
        "action_type":  "isolate_host",
        "target":       host,
        "status":       "applied",
        "created_at":   _now(),
        "revoked_at":   None,
        "notes":        f"Manual isolate by {actor}: {reason}",
    }
    with _LOCK:
        _ACTIONS.appendleft(action)
    return action


def manually_disable_user(user: str, reason: str = "manual", actor: str = "analyst") -> Dict[str, Any]:
    """Ручная деактивация учётной записи пользователя."""
    _apply_disable_user(user)
    action = {
        "action_id":    f"RA-{uuid4().hex[:10].upper()}",
        "incident_id":  None,
        "incident_type": None,
        "action_type":  "disable_user",
        "target":       user,
        "status":       "applied",
        "created_at":   _now(),
        "revoked_at":   None,
        "notes":        f"Manual disable by {actor}: {reason}",
    }
    with _LOCK:
        _ACTIONS.appendleft(action)
    return action


def revoke_action(action_id: str) -> Optional[Dict[str, Any]]:
    """
    Отозвать примененное действие (снять блокировку/изоляцию).

    Returns: обновлённый ResponseAction или None если не найден.
    """
    with _LOCK:
        for action in _ACTIONS:
            if action.get("action_id") == action_id:
                if action["status"] == "revoked":
                    return action  # уже отозвано

                action_type = action["action_type"]
                target = action["target"]

                try:
                    _, revoke_fn = _ACTION_APPLY_FN.get(action_type, (None, None))
                    if revoke_fn and target:
                        revoke_fn(target)
                except Exception as exc:
                    logger.exception("[RESPONSE] Revoke failed for action %s: %s", action_id, exc)

                action["status"] = "revoked"
                action["revoked_at"] = _now()
                logger.info("[RESPONSE] Revoked action %s (%s on %s)", action_id, action_type, target)
                return action

    return None


def list_actions(limit: int = 100) -> List[Dict[str, Any]]:
    """Вернуть список последних действий реагирования."""
    with _LOCK:
        return list(_ACTIONS)[:limit]


def get_block_status() -> Dict[str, Any]:
    """Вернуть текущие активные блокировки."""
    with _LOCK:
        return {
            "blocked_ips":     sorted(_BLOCKED_IPS),
            "isolated_hosts":  sorted(_ISOLATED_HOSTS),
            "blocked_users":   sorted(_BLOCKED_USERS),
            "total_blocked":   len(_BLOCKED_IPS) + len(_ISOLATED_HOSTS) + len(_BLOCKED_USERS),
        }


def clear_all() -> None:
    """Сбросить всё состояние (используется в тестах)."""
    with _LOCK:
        _BLOCKED_IPS.clear()
        _BLOCKED_USERS.clear()
        _ISOLATED_HOSTS.clear()
        _ACTIONS.clear()
