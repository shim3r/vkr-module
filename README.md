# VKR SIEM Module Prototype

Прототип модуля автоматизации обработки событий информационной безопасности
для ВКР.

## Функциональность
- Прием событий (firewall, EDR, AV, IAM, ARM)
- Хранение сырых событий
- Нормализация
- Обогащение (Asset DB)
- Агрегация и дедупликация
- Риск-скоринг
- Корреляция и инциденты

## Структура
- app/ — основной код
- logs_examples/ — тестовые логи

### Способ запуска проекта
cd ~/Desktop/vkr-module
source .venv/bin/activate
python -m uvicorn app.main:app --reload