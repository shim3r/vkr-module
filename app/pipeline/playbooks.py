"""
SOAR Playbooks Engine — движок автоматизированного реагирования.

Загружает сценарии реагирования (playbooks) из JSON/YAML,
сопоставляет их с инцидентами и вызывает Response Engine для блокировки.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from app.config import DATA_ROOT
from app.services.response_engine import _execute_action, _build_action, _ACTIONS, _LOCK

logger = logging.getLogger("siem.playbooks")

PLAYBOOKS_DIR = DATA_ROOT / "playbooks"
PLAYBOOKS_DIR.mkdir(parents=True, exist_ok=True)

# Базовый набор плейбуков для ТЭК-модуля
DEFAULT_PLAYBOOKS = [
    {
        "id": "pb_isolate_malware",
        "name": "Изоляция при заражении",
        "description": "Автоматическая изоляция хоста при обнаружении ВПО или Ransomware.",
        "enabled": True,
        "condition": {
            "type_in": ["MALWARE_DETECTED", "RANSOMWARE_BEHAVIOR", "AV_TAMPER", "AV_CLEAN_FAILED"],
            "severity_in": ["high", "critical"]
        },
        "actions": [
            {"type": "isolate_host", "target_field": "host"}
        ]
    },
    {
        "id": "pb_block_bruteforce",
        "name": "Блокировка атакующего IP (Bruteforce / Скан)",
        "description": "Периметровая блокировка IP-адреса, с которого идет перебор паролей или сканирование.",
        "enabled": True,
        "condition": {
            "type_in": ["BRUTEFORCE_VPN", "PORT_SCAN", "IAM_PASSWORD_SPRAY", "ENDPOINT_BRUTEFORCE"],
            "severity_in": ["high", "critical", "medium"]
        },
        "actions": [
            {"type": "block_ip", "target_field": "src_ip"}
        ]
    },
    {
        "id": "pb_compromise_chain",
        "name": "Комплексное реагирование на компрометацию",
        "description": "Блокировка IP, изоляция целевого хоста и отзыв сессии пользователя.",
        "enabled": True,
        "condition": {
            "type_in": ["CREDENTIAL_DUMP", "LATERAL_MOVEMENT", "EDR_LATERAL_ACTIVITY", "VPN_BRUTE_CHAIN"],
            "severity_in": ["critical"]
        },
        "actions": [
            {"type": "block_ip", "target_field": "src_ip"},
            {"type": "disable_user", "target_field": "user"},
            {"type": "isolate_host", "target_field": "host"}
        ]
    }
]


class PlaybooksDB:
    def __init__(self):
        self.playbooks: List[Dict[str, Any]] = []
        self._init_db()

    def _init_db(self):
        pb_file = PLAYBOOKS_DIR / "playbooks.json"
        
        # Если файла нет — создаем дефолтные плейбуки
        if not pb_file.exists():
            pb_file.write_text(json.dumps(DEFAULT_PLAYBOOKS, ensure_ascii=False, indent=2), encoding="utf-8")
            self.playbooks = DEFAULT_PLAYBOOKS
            logger.info("[PLAYBOOKS] Created %d default playbooks", len(self.playbooks))
        else:
            try:
                self.playbooks = json.loads(pb_file.read_text(encoding="utf-8"))
                logger.info("[PLAYBOOKS] Loaded %d playbooks from disk", len(self.playbooks))
            except Exception as exc:
                logger.error("[PLAYBOOKS] Failed to load playbooks.json: %s", exc)
                self.playbooks = DEFAULT_PLAYBOOKS
                
    def save(self):
        pb_file = PLAYBOOKS_DIR / "playbooks.json"
        pb_file.write_text(json.dumps(self.playbooks, ensure_ascii=False, indent=2), encoding="utf-8")

    def get_all(self) -> List[Dict[str, Any]]:
        return self.playbooks
        
    def add(self, pb: Dict[str, Any]):
        self.playbooks.append(pb)
        self.save()
        
    def delete(self, pb_id: str):
        self.playbooks = [p for p in self.playbooks if p.get("id") != pb_id]
        self.save()
        
    def update(self, pb_id: str, updates: Dict[str, Any]):
        for p in self.playbooks:
            if p.get("id") == pb_id:
                p.update(updates)
                break
        self.save()


_DB = PlaybooksDB()


def execute_playbooks_for_incident(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Основная логика SOAR. 
    Принимает инцидент, ищет подходящие активные плейбуки по условиям.
    Выполняет их Actions (через Response Engine).
    
    Returns: список применённых Responseactions.
    """
    inc_type = str(incident.get("type") or "")
    inc_sev = str(incident.get("severity") or "").lower()
    
    applied_actions = []
    
    for pb in _DB.get_all():
        if not pb.get("enabled", False):
            continue
            
        cond = pb.get("condition", {})
        type_in = cond.get("type_in", [])
        sev_in = [s.lower() for s in cond.get("severity_in", [])]
        
        # Проверяем condition
        match_type = (not type_in) or (inc_type in type_in)
        match_sev = (not sev_in) or (inc_sev in sev_in)
        
        if match_type and match_sev:
            logger.info("[PLAYBOOKS] Incident %s matched playbook '%s'", incident.get("incident_id"), pb.get("name"))
            
            # Выполняем действия
            for act_def in pb.get("actions", []):
                act_type = act_def.get("type")
                target_field = act_def.get("target_field")
                
                if not act_type or not target_field:
                    continue
                    
                # Итоговая интеграция с response_engine (прямой вызов логики)
                # _execute_action - функция из response_engine.py
                action_result = _execute_action(incident, act_type, target_field)
                if action_result:
                    action_result["notes"] += f" (Triggered by Playbook: {pb.get('name')})"
                    applied_actions.append(action_result)
                    with _LOCK:
                        _ACTIONS.appendleft(action_result)
                        
    return applied_actions

