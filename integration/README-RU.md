# Синтетические интеграционные тесты

[English](README.md) | Русский

<a id="synthetic-integration-tests"></a>

Это developer fixtures, **не инструкция развёртывания**. Для рабочего командного стека используйте [durka.py и инструкцию администратора](../deployment/README-RU.md).

<a id="isolation-and-prerequisites"></a>
## Изоляция и prerequisites

Opt-in Docker-тесты запускаются только в отдельном приватном workspace с синтетическими credentials/data. Нужны разрешённый Linux Docker Engine, кешированные закреплённые образы, уникальные project names и свободные ресурсы. Recovery и fault-injection требуют snapshot хоста. Чужие workloads не исследуются.

<a id="prepare-and-run"></a>
## Подготовка и запуск

Прочитайте help fixture, просмотрите preview, затем примените осознанно. В профилях нет shell-команд. Запускайте из корня репозитория. Результаты остаются в выбранном приватном workspace, а не в Git.

```bash
python3 integration/stack_smoke.py --help
python3 integration/packmate_smoke.py --help
```

<a id="rollback-and-failures"></a>
## Откат и ошибки

Используйте shutdown самого fixture; не глобальный prune или удаление общих volumes. При сбое локальные результаты/данные сохраняются для диагностики. Проверьте точечную очистку перед повтором в новом workspace.

<a id="evidence-boundaries"></a>
## Границы проверки

Синтетический тест не сертифицирует Docker Desktop, захват на соревновании или доступ реальных участников. CI logs и приватные outputs заменяют закоммиченные исторические отчёты. См. [возможности и ограничения](../docs/CAPABILITY_INVENTORY-RU.md).

<a id="packmate-file-only-fixture"></a>
## Fixture Packmate FILE

`packmate_smoke.py` проверяет импорт закрытого синтетического PCAP, authentication и известные потоки. Непрерывный захват он не подтверждает.

<a id="native-postgresql-recovery-drill"></a>
## Нативное восстановление PostgreSQL

`recovery_smoke.py` проверяет native dump/restore в изолированные базы. Не подменяйте его синтетические inputs игровыми volumes.

<a id="published-neo-release-client"></a>
## Опубликованный Neo client

`neo_release_smoke.py` проверяет закреплённый опубликованный client с закреплённым server; latest автоматически не выбирается.

<a id="harmless-neo-task-lifecycle"></a>
## Безвредный цикл Neo

`neo_lifecycle_smoke.py` проверяет безвредную задачу, результат, reconnect и disable. Workers исполняют доверенный код; не передавайте произвольные задачи.

<a id="native-redis-recovery"></a>
## Нативное восстановление Redis

`component_recovery_smoke.py` проверяет persistence/recovery в изолированном fixture. Для настоящих очередей отправки отдельно решают, можно ли replay.

<a id="packmate-authentication-logger-canary"></a>
## Canary логирования Packmate

`packmate_logger_smoke.py` проверяет подавление failed-auth logger через конфигурацию: одноразовый canary и positive control. Все возможные пути логирования этим не сертифицируются.

<a id="whole-stack-synthetic-recovery"></a>
## Восстановление синтетического стека

`stack_recovery_smoke.py` восстанавливает синтетические Farm, Neo и Packmate в новые projects с отключённой автоматической отправкой. Это не разрешение перезаписывать существующий deployment.

<a id="synthetic-live-capture"></a>
## Синтетический LIVE

`packmate_live_smoke.py` наблюдает только свою синтетическую Linux network/namespace. Проверяет TCP/UDP, timeout и restart, но не видимость настоящего Vulnbox или длительную нагрузку.

<a id="network-isolated-offline-runtime-rehearsal"></a>
## Изолированная офлайн-репетиция

`offline_runtime_smoke.py` делает cold start Linux-стека из подготовленных образов и проверяет network denial плюс сохранение синтетических данных. Полный toolchain на пустой ноутбук он не устанавливает. Для обычной подготовки см. [офлайн-работу](../docs/offline-bundles-RU.md).

Аргументы каждого fixture доступны через `--help`; низкоуровневые защитные флаги нужны разработчикам, а не как формы для обычного оператора.

<a id="portable-synthetic-vulnbox-handoff"></a>
## Перенос синтетического PCAP с Vulnbox

`vulnbox_handoff.py` получает небольшой закрытый synthetic PCAP по loopback HTTP,
проверяет формат, отклоняет обрезанный файл и запускает проверку Docker-исходников
до/после ручных изменений тестовых примеров. Privileged containers он не запускает.
macOS workflow принимает необязательный ограниченный synthetic PCAP в base64;
без него файл генерируется локально. Реальный трафик и секреты передавать нельзя.
Это проверка переносимости файлового пути и CLI сканера, **не** прямого доступа к VM,
обработки Packmate, LIVE-видимости или Docker Desktop. Их проверяют отдельно на
разрешённом Linux-узле и настоящем Mac.

<a id="release-candidate-acceptance"></a>
## Приёмка release candidate

Одна последовательность использует fixtures выше; второй инфраструктуры нет. **Это подготовленная процедура, не новый выполненный runtime-прогон.** Запускайте из корня repo под обычным пользователем на разрешённом **native Linux AMD64** Docker host. Это не первая установка Mac; её маршрут — [первый запуск Mac](../docs/MACOS_FIRST_RUN-RU.md). Выполнение этих Linux fixtures через Desktop/эмуляцию — NOT VERIFIED. Published release probe использует Linux client, не native Darwin client.

Нужно заранее: закреплённые clean checkouts в `local/sources/s4dfarm`, `local/sources/neo`, `local/sources/packmate`; кеш Linux AMD64 images из integration/deployment locks; закреплённый Linux Neo archive в `local/downloads/neo_client_2.4.2_linux_amd64.tar.gz`. Подготовка/build зависимостей требует отдельной разрешённой online-фазы. Не подставляйте operator/competition workspace. Недостающие зависимости означают BLOCKED, не разрешение скачать latest.

Выполняйте команды по порядку и остановитесь при первом ненулевом результате; применённые fixtures должны выдавать PASS. Исключение — находка сканера в уязвимом lab (ожидается `1`). Workspace/project IDs и synthetic markers генерируются автоматически; заполнять evidence-карточки и переписывать хеши не нужно. Synthetic-флаги получает только созданный внутренний mock receiver; **реальная отправка выключена**.

```bash
set -euo pipefail
umask 077
mkdir -p local
RC_RUN="$(mktemp -d "$PWD/local/rc-acceptance.XXXXXX")"
PM_DB="$(python3 -c 'import durka; print(durka.kit.PACKMATE_DB)')"
python3 integration/stack_smoke.py prepare --workspace "$RC_RUN/stack" --s4dfarm-source local/sources/s4dfarm --neo-source local/sources/neo --images config/integration-images.lock.json --apply --approval-id rc-synthetic
python3 integration/stack_smoke.py build --workspace "$RC_RUN/stack" --apply --approval-id rc-synthetic
python3 integration/packmate_smoke.py prepare --workspace "$RC_RUN/packmate" --source local/sources/packmate --postgres-image "$PM_DB" --apply --approval-id rc-synthetic
python3 integration/neo_release_smoke.py prepare --workspace "$RC_RUN/client" --archive local/downloads/neo_client_2.4.2_linux_amd64.tar.gz --apply --approval-id rc-synthetic
python3 integration/neo_lifecycle_smoke.py prepare --workspace "$RC_RUN/task" --apply --approval-id rc-synthetic
```

Build может скачивать compiler/package dependencies; закончите его **до** offline-фазы. Одного кеша base images недостаточно. Пути fixture, sources и API проверяются существующими скриптами. Не нужны LIVE capture, privilege, host networking и настоящая цель.

```bash
python3 integration/stack_smoke.py up --workspace "$RC_RUN/stack" --apply --approval-id rc-synthetic
python3 integration/stack_smoke.py smoke --workspace "$RC_RUN/stack" --apply --approval-id rc-synthetic
python3 integration/neo_release_smoke.py smoke --workspace "$RC_RUN/client" --stack-workspace "$RC_RUN/stack" --apply --approval-id rc-synthetic
python3 integration/neo_lifecycle_smoke.py smoke --workspace "$RC_RUN/task" --release-workspace "$RC_RUN/client" --stack-workspace "$RC_RUN/stack" --apply --approval-id rc-synthetic
python3 integration/packmate_smoke.py up --workspace "$RC_RUN/packmate" --apply --approval-id rc-synthetic
python3 integration/packmate_smoke.py smoke --workspace "$RC_RUN/packmate" --apply --approval-id rc-synthetic
python3 scripts/defense_ops.py preflight --profile config/defense-profile.example.json
python3 integration/vulnbox_handoff.py
```

Ожидаем: authenticated API/config Farm и отказ missing/wrong auth; exact release auth Neo, безвредный disabled-first `printf`, single execution, принятие Farm/mock receiver и reconnect worker; auth Packmate, один synthetic stream с точными request/response/directions; Defense CLI и source review/сравнение ручного fixture-патча. Worker-тесты доказывают только свои shell-зависимости, не произвольные Python/JS scripts. Не повторяйте fresh-database Packmate smoke на уже обработанных данных; persistence проверяется отдельно ниже.

Сначала корректно остановите templates, чтобы ограничить одновременную нагрузку; данные/образы остаются в приватных каталогах:

```bash
python3 integration/packmate_smoke.py down --workspace "$RC_RUN/packmate" --apply --approval-id rc-synthetic
python3 integration/stack_smoke.py down --workspace "$RC_RUN/stack" --apply --approval-id rc-synthetic
```

После подтверждения snapshot этого test host выполните recovery в **новые** synthetic projects. Никогда не передавайте `--snapshot-confirmed` без настоящего snapshot. Operator data не копируются. Автоматические submission/capture replay остаются выключенными в восстановленных targets.

```bash
python3 integration/stack_recovery_smoke.py prepare --workspace "$RC_RUN/recovery" --stack-workspace "$RC_RUN/stack" --packmate-workspace "$RC_RUN/packmate" --release-workspace "$RC_RUN/client" --apply --approval-id rc-synthetic
python3 integration/stack_recovery_smoke.py run --workspace "$RC_RUN/recovery" --apply --approval-id rc-synthetic --snapshot-confirmed
```

Ожидаем сохранность settings, synthetic flags, disabled Neo task/state, Packmate services/patterns/streams после контролируемой остановки, native dumps/cold copies и isolated restore. `result.json` содержит время (цели: RPO 300s / RTO 600s), проверки и scoped shutdown. Data/backups остаются. FAIL/PARTIAL/BLOCKED или неудачный cleanup запрещает приёмку.

Для полного **offline startup** используйте `offline_runtime_smoke.py`, не build fixture с доступной сетью. Задайте `RC_TEMPLATE` — ранее подготовленный native Linux AMD64 synthetic deployment из `deployment/toolkit.py` (не competition workspace), и `RC_IMAGES` — его проверенный полный приватный image bundle. Используйте существующие [offline cache utilities](../docs/offline-bundles-RU.md); нужны все runtime/helper images. Без bundle offline acceptance остаётся BLOCKED. Сохраните snapshot host и согласованный local Docker context.

```bash
RC_DAEMON="$(docker info --format '{{.ID}}')"
python3 integration/offline_runtime_smoke.py prepare --workspace "$RC_RUN/offline" --template "$RC_TEMPLATE" --image-bundle "$RC_IMAGES" --daemon-id "$RC_DAEMON" --apply --approval-id rc-synthetic
python3 integration/offline_runtime_smoke.py run --workspace "$RC_RUN/offline" --apply --approval-id rc-synthetic --snapshot-confirmed
python3 integration/offline_runtime_smoke.py down --workspace "$RC_RUN/offline" --apply --approval-id rc-synthetic
```

Ожидаем только подготовленные immutable images, запрет внешней сети внутри своих test resources, полный synthetic Farm/Neo/Packmate cycle, restart/persistence и чистую scoped-остановку. Host/router network не меняются; это не доказывает установку на пустой ноутбук. На Mac выполните отдельную disconnected Desktop rehearsal из first-run guide.

При ошибке остановите только точный owned project через `down` его fixture. Recovery/offline fixtures записывают automatic cleanup; при неудаче проверьте приватный result и точные labelled resources до повтора. Нельзя `prune`, `down -v` и удаление run directory вместо cleanup. Храните результаты приватно; не коммитьте logs/PCAP и не объявляйте Mac ready по Linux PASS.
