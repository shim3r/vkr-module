
# VKR SIEM Module (Prototype)
Прототип модуля автоматизации обработки событий информационной безопасности (ИСБ) для ВКР.  
Проект демонстрирует упрощённый SIEM/SOAR-подход: **сбор событий → нормализация → риск-оценка → алерты → корреляция → инциденты → веб-панель мониторинга**.

## Что уже реализовано

### Источники событий
- Firewall (VPN, Portscan)
- Antivirus / Malware (AV_DETECT)
- EDR (process/network)
- IAM/AD (login fail/success, account)
- ARM/Endpoints (как источник для демо)

### Пайплайн (по блок-схеме)
1. **Collectors / Ingest API**: приём событий через REST или загрузку файла.
2. **Raw Events Store**: сохранение сырых событий в `data/raw/*.json`.
3. **Normalization**: разбор CEF/CSV/JSON/text в единую схему `NormalizedEvent`.
4. **Risk scoring / Prioritization**: расчёт `risk` и `priority` по источнику и маркерам.
5. **Alerts feed**: критичные события попадают в ленту алертов.
6. **Correlation rules**: правила SOC-уровня для выявления атак и создания инцидентов.
7. **Incidents store**: инциденты складываются в in-memory очередь и отображаются в UI.

### Корреляция (текущий минимум)
- **VPN bruteforce**: серия `VPN_LOGIN_FAIL` от одного `src_ip` за окно времени.

### Способ запуска проекта

**Обязательно** запускайте из корня репозитория (где лежит `app/` и `requirements.txt`):

```bash
cd ~/Desktop/vkr-module
pip install -r requirements.txt
python3 -m venv .venv
source .venv/bin/activate   # или: .venv/bin/activate на Windows в Git Bash
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Если порт 8000 занят, укажите другой: `--port 8001`. Или используйте скрипт:

```bash
./run.sh
```
### Структура проекта

```
app/
  main.py                 # FastAPI приложение
  api/
    ingest.py             # /api/ingest, /api/ingest-file
    alerts.py             # /api/alerts
    incidents.py          # /api/incidents
    sim.py                # /api/sim/* (генератор и демо-атаки)
    ui.py                 # UI панель (GET /)
  pipeline/
    collector.py          # orchestrator: raw -> normalize -> score -> correlate
    normalize.py          # разбор форматов + приведение к NormalizedEvent
    scoring.py            # risk / priority
    correlate.py          # правила корреляции (инциденты)
  schemas/
    event.py              # NormalizedEvent (Pydantic)
  services/
    events_store.py       # in-memory хранилище нормализованных событий
    alerts_store.py       # in-memory хранилище алертов
    incidents_store.py    # in-memory хранилище инцидентов
  simulator/
    attack_catalog.py     # сценарии атак
    generator.py          # непрерывная генерация (опционально)
    run_attack.py         # утилиты симуляции

data/raw/                 # сырые события (json)
requirements.txt
README.md
```
