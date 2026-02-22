# VKR SIEM Module (Prototype)
Прототип модуля автоматизации обработки событий информационной безопасности (ИБ) для ВКР.  
Проект демонстрирует современный SIEM/SOAR-подход на базе асинхронной очереди (Async Queue-based pipeline): **сбор событий → нормализация → обогащение → агрегация → риск-оценка → алерты → корреляция → инциденты → интеграции/отчетность → веб-панель мониторинга**.

## Что уже реализовано

### Источники событий
- Firewall (VPN, Portscan)
- Antivirus / Malware (AV_DETECT)
- EDR (process/network)
- IAM/AD (login fail/success, account)
- ARM/Endpoints (как источник для демо)

### Пайплайн (по блок-схеме)
Обработка событий происходит в виде конвейера, где каждая стадия является выделенным асинхронным воркером:
1. **Collectors / Ingest API**: приём событий через REST (`/api/ingest`) или загрузку файла.
2. **Raw Events Store**: сохранение сырых (неизменяемых) событий в `data/raw/*.json` (forensic archive).
3. **Normalization**: разбор CEF/CSV/JSON/text в единую схему `NormalizedEvent`.
4. **Enrichment**: обогащение событий данными из Asset DB (CMDB), GeoIP и списками индикаторов компрометации (IOCs).
5. **Aggregation**: группировка схожих событий (T=5 минут, дедупликация) для снижения нагрузки.
6. **Risk scoring / Prioritization**: расчёт `risk` и `priority` по источнику, маркерам и критичности актива.
7. **Alerts feed**: автоматическое создание алертов по высококритичным событиям (priority=HIGH/CRITICAL).
8. **Correlation rules**: правила SOC-уровня для выявления многошаговых атак и автоматического создания инцидентов.
9. **Incidents Manager**: управление инцидентами (статусы, SLA, assignee).
10. **Reporting & Integrations**: вычисление метрик SOC (FP-rate, MTTR), дашборды, webhook-уведомления (Telegram/ServiceDesk).

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

### Запуск через Docker (рекомендуется для Production / VPS)

Проект использует фоновые асинхронные задачи (asyncio) и локальную файловую систему, поэтому **он не подходит для Serverless-платформ** (таких как Vercel). 
Для деплоя используйте Docker или облачные платформы на базе контейнеров (Render, Railway, Fly.io, DigitalOcean).

```bash
# 1. Сборка образа
docker build -t vkr-siem .

# 2. Запуск контейнера (проброс порта 8000 и монтирование данных наружу)
docker run -d -p 8000:8000 -v $(pwd)/data:/app/data --name siem-instance vkr-siem
```

После запуска интерфейс будет доступен по адресу: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)

### Структура проекта

```
app/
  main.py                 # FastAPI приложение (entrypoint)
  config.py               # Конфигурация приложения
  api/                    # REST API Endpoints
    alerts.py             # /api/alerts
    incidents.py          # /api/incidents
    ingest.py             # /api/ingest
    integrations.py       # API для интеграций и webhook'ов
    reporting.py          # /api/reports, /api/metrics
    sim.py                # /api/sim/* (генератор и демо-атаки)
    ui.py                 # UI панель мониторинга (GET /)
  pipeline/               # Обработка событий (Async Workers)
    pipeline.py           # Оркестратор очереди (Pipeline)
    collector.py          # Точка входа событий (Raw Store)
    normalize.py          # Приведение к схеме
    enrich.py             # Обогащение (CMDB, GeoIP, IOC)
    aggregate.py          # Агрегация и дедупликация (T=5m)
    scoring.py            # Расчет Risk и Priority
    correlate.py          # Корреляция и генерация инцидентов
  schemas/                # Pydantic схемы
    event.py              # Схема NormalizedEvent
  services/               # Бизнес-логика и In-Memory хранилища
    aggregates_store.py   # Хранилище агрегированных событий
    alerts_store.py       # Хранилище алертов
    events_store.py       # Хранилище нормализованных событий
    incidents_store.py    # Хранилище инцидентов
    metrics_service.py    # Расчет метрик дашборда
    reporting.py          # Формирование отчетов (SOC Metrics)
  simulator/              # Симулятор активности
    attack_catalog.py     # Сценарии атак (из MITRE ATT&CK)
    generator.py          # Continuous генерация фона
    run_attack.py         # Утилиты запуска симуляций

data/
  raw/                    # Сырые события (json)
  normalized/             # Нормализованные события
  cmdb/                   # Данные активов и IOCs
tests/                    # Юнит и e2e тесты
requirements.txt
README.md
```
