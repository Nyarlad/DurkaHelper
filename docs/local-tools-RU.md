<a id="local-tools-and-cli-reference"></a>
# Локальные инструменты и справочник CLI

[English](local-tools.md) | Русский

Расширенный справочник CLI, Python 3.10+, только стандартная библиотека. Для обычной установки используйте [полную инструкцию](MACOS_FULL_DEPLOYMENT_AND_TESTING-RU.md), для scan — [справочник сканера](offline-scanner-RU.md). Результаты храните приватно. См. [возможности и ограничения](CAPABILITY_INVENTORY-RU.md).

<a id="defense-operations"></a>
## Защитные операции

`scripts/defense_ops.py` 2.2.0 использует декларативный [profile.v1](../schemas/profile.v1.schema.json); профили не содержат shell-команд. Начните с [синтетического примера](../config/defense-profile.example.json) и явно выберите свои root, files, checks и limits.


```bash
python3 scripts/defense_ops.py preflight --profile config/defense-profile.example.json
python3 scripts/defense_ops.py snapshot --profile config/defense-profile.example.json \
  --root . --output ../private-results/baseline.json
python3 scripts/defense_ops.py compare ../private-results/baseline.json ../private-results/current.json
```

Адаптеры охватывают platform, processes, listeners, services и ограниченные Compose metadata там, где это поддерживается. Отсутствующие инструменты/права или неполный сбор означают partial, а не свидетельствуют об отсутствии изменений. Сравнение baseline требует одинакового scope.

Health проверяет только явно настроенные HTTP GET endpoints, без неявных proxies или redirects. Он проверяет status и ограниченное содержимое, а не полное поведение приложения.


```bash
python3 scripts/defense_ops.py health --profile config/defense-profile.example.json
```

<a id="backup-and-staging-restore"></a>
## Backup и восстановление в staging

Копируются только явно выбранные regular files/trees и заранее созданные native database dumps. Живые файлы БД не являются поддерживаемым способом backup. Инструмент ограничивает количество и объём, проверяет стабильность источника и SHA-256.


```bash
python3 scripts/defense_ops.py backup create --profile config/defense-profile.example.json \
  --root . --output ../private-results/backup-01
python3 scripts/defense_ops.py backup verify ../private-results/backup-01
python3 scripts/defense_ops.py restore-stage ../private-results/backup-01 \
  --target ../private-results/restore-01
python3 scripts/defense_ops.py restore-stage ../private-results/backup-01 \
  --target ../private-results/restore-01 --apply --approval-id restore-rehearsal-01
```

Staging target должен быть новым/пустым согласно prechecks; перезапись production отсутствует. Symlinks, traversal, специальные файлы, tampering, нестабильные входы и неподдерживаемая безопасная публикация приводят к отказу. Windows не поддерживает POSIX-путь изменения данных.

<a id="deployment-audit"></a>
## Аудит deployment

`audit-deployment` проверяет заявленные allowlisted metadata по явной policy: roles, image pins/architecture, ports, mounts, privileges и требования health/resources. Он не запускает Compose, не исследует live daemon и не разбирает произвольный YAML. Используйте [deployment kit](../deployment/README-RU.md), чтобы создать очищенные model/policy из доверенной конфигурации.


```bash
python3 scripts/defense_ops.py audit-deployment \
  --model ../private-deployment/run-01/runtime-model.json \
  --policy ../private-deployment/run-01/runtime-policy.json
```

Не редактируйте model вручную, чтобы скрыть риски. Post-build source hash связывает точные bytes runtime Compose; policy намеренно показывает нерешённые проблемы root-user, отсутствия health и эмуляции.

<a id="patch-evidence-timelines-and-export"></a>
## Свидетельства патча, timeline и экспорт

[Проверка патчей](patch-validation-RU.md) объясняет строгую привязку evidence. Статусы Validation-record — значения schema в нижнем регистре: pass, fail, partial, blocked, not_run и skipped_not_applicable. Запись not_run не является pass.

Timeline принимает нормализованные записи [event.v1](../schemas/event.v1.schema.json), а не произвольные raw application logs. Evidence export копирует только поддерживаемые structured/sanitized records, исключает raw PCAP/config/credentials и проверяет checksums.


```bash
python3 scripts/defense_ops.py timeline --events ../private-results/events.jsonl \
  --output ../private-results/timeline.json
python3 scripts/defense_ops.py evidence --profile config/defense-profile.example.json \
  --input ../private-results/baseline.json --output ../private-results/evidence-01
```

<a id="small-standalone-utilities"></a>
## Небольшие самостоятельные утилиты

| Утилита | Назначение / ограничения |
|---|---|
| [http_probe.py](../scripts/http_probe.py) | Явные одноразовые GET; по умолчанию четыре workers, socket timeout три секунды, body 1 MiB; без proxies/redirects, обычная TLS verification |
| [log_summary.py](../scripts/log_summary.py) | Только ограниченные JSONL-счётчики; необязательные поля level/integer status, число malformed records, без вывода message/header/body |
| [backup_config.py](../scripts/backup_config.py) | Allowlisted scalar JSON fields и SHA-256; без databases, volumes или полного восстановления |
| [health_service.py](../lab/health_service.py) | Синтетический loopback-сервис /health и /version |

Эффект: probes `READ-ONLY`, log summary `READ-ONLY`, config backup `WORKSPACE-WRITE`. Рабочий каталог — корень. Это демонстрационные входы; для probe сначала [запустите лабораторию](../lab/README-RU.md).

```bash
python3 scripts/http_probe.py config/services.example.json
python3 scripts/log_summary.py lab/fixtures/events.jsonl
python3 scripts/backup_config.py config/backup.example.json --root lab/fixtures
```

HTTP probe завершается кодом 0/все ожидаемые ответы, 1/провал проверки, 2/неверная конфигурация. Log summary возвращает 1 при malformed input, а не просто при HTTP error statuses. Config backup создаёт новый каталог artifacts/config-backups/config-*; никогда не заменяйте полную конфигурацию сервиса этим частичным экспортом. Секрет под произвольным именем поля нельзя надёжно обнаружить — локально проверяйте allowlist и значения.
