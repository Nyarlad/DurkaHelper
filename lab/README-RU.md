<a id="synthetic-local-defense-lab"></a>
# Синтетическая локальная лаборатория защиты

[English](README.md) | Русский

Этот сервис использует только стандартную библиотеку, намеренно мал и доступен только через loopback. Он не подключается к инфраструктуре соревнования. Запускайте из корня репозитория с Python 3.10+.

Свидетельство: `REVIEWED`; эффект `SERVICE-CHANGE` (один локальный процесс). Ожидается: loopback listener без внешнего bind. Секреты: используйте только предоставленные синтетические fixtures. Rollback: Ctrl-C останавливает процесс.

```bash
python3 lab/health_service.py
```

Порт по умолчанию: 8080. Используйте --port 8081 для другого явно выбранного порта или --port 0 для временного порта, фактический URL которого будет напечатан. Соответственно обновите профиль probe. fixtures/service.json демонстрирует резервное копирование конфигурации; сервер его не загружает.

| Запрос | Ответ |
|---|---|
| GET /health or /health?check=1 | 200 и {"status": "ok"} |
| GET /version | 200 и {"version": "demo"} |
| HEAD /health | Заголовки GET без тела |
| GET /missing | 404 |
| POST /health | 405; Allow: GET, HEAD |

Сервис пишет в stderr JSONL-записи level/status без URL или содержимого запросов.

В другом терминале: свидетельство `REVIEWED`, эффект `READ-ONLY`, тот же рабочий каталог; ожидается код выхода probe 0 и сводка лога с двумя HTTP-ошибками в предоставленном fixture из четырёх записей:

```bash
python3 scripts/http_probe.py config/services.example.json
python3 scripts/log_summary.py lab/fixtures/events.jsonl
```

Unit tests создают и останавливают собственные временные loopback-серверы; отдельно запущенная лаборатория не нужна. Эффект: временный `WORKSPACE-WRITE`; ожидается успешное прохождение набора.

```bash
python3 -m unittest discover -s tests -p 'test_defense*.py' -v
```

DEMO_ONLY_DO_NOT_COPY в fixtures/service.json — безвредное тестовое значение, а не действующий пароль. Внешние контейнерные тесты — отдельный запускаемый по выбору [integration fixture](../integration/README-RU.md).
