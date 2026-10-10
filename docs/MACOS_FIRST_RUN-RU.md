<a id="first-mac-run"></a>
# Первый запуск на Mac

[English](MACOS_FIRST_RUN.md) | Русский

Это короткий маршрут оператора, а не заявление о готовности ноутбука. Все шаги с runtime Mac ниже имеют статус **PENDING: требуется проверка на реальном Mac**. Выполняйте их только после согласования Docker Desktop, локальных сервисов, Ethernet. Подробная установка, поля конфигурации и backup описаны в [полном руководстве](MACOS_FULL_DEPLOYMENT_AND_TESTING-RU.md).

<a id="1-read-only-preflight"></a>
## 1. Preflight без изменений

Из корня репозитория, через нативный ARM64 Python:

```bash
python3 durka.py doctor
```

`doctor` не устанавливает, не скачивает, не выполняет pull/build, не запускает сервисы, не меняет конфигурацию и не исполняет Neo. Он проверяет фактическую macOS/архитектуру, Python 3.10+, Git 2.30+, локальный Desktop Engine, Compose v2+, ресурсы, нужные порты и подготовленные образы. Пароли и имена процессов не выводятся. `READY` относится к конкретной проверке, не ко всему соревнованию.

Коды: `0` — все проверки готовы; `1` — предупреждения/неподтверждённые проверки; `2` — блокер. До setup отсутствие конфига/образов/клиента ожидаемо. Эмуляция Packmate остаётся предупреждением, offline/LAN — `NOT VERIFIED` даже при совпадении кеша. Занятые порты могут принадлежать уже поднятому стеку; не убивайте чужой процесс ради снятия предупреждения.

Если Python/Git отсутствуют, сначала подготовьте согласованные установки. Сверьте реальные версии macOS и Docker Desktop с требованиями разрешённой установки; ранее названная версия не является проверкой. Запустите Desktop вручную после согласования. Начните с 4 CPU / 8 ГиБ RAM и бюджета диска 96 ГиБ, затем измерьте нагрузку.

<a id="2-first-setup-while-online"></a>
## 2. Первая подготовка с Интернетом

Этот шаг записывает приватный конфиг и подготавливает зависимости. Держите конфиг/пароли приватными.

```bash
python3 durka.py init
```

Отредактируйте `local/durka.json`: оставьте `bind_address` равным `127.0.0.1`, выберите Darwin ARM64/Desktop, режим FILE и задайте `profile.packmate.local_ip` равным `192.0.2.20` для synthetic PCAP ниже. Оставьте пример URL/token фермы; **не выполняйте `submit`**. Поддерживаемый adapter — `ructf_http`, что не означает совместимость с любым соревнованием. Другие протоколы требуют отдельной проверки.

После согласования, при доступном Интернете:

```bash
python3 durka.py setup
```

Подготовьте закреплённый Neo **v2.4.2 Darwin ARM64** по [инструкции Neo](neo-RU.md). Разместите executable в `local/neo-client/neo` либо укажите настоящий путь через `doctor --neo-client PATH`. Сохраните release/config/tasks офлайн. Doctor проверяет executable Mach-O ARM64 header, но не аутентифицирует клиент и не доказывает его версию. Используйте закреплённый release, не произвольный бинарник с подходящим header.

<a id="3-start-and-check-the-tools"></a>
## 3. Поднять и проверить инструменты

```bash
python3 durka.py doctor
python3 durka.py up
python3 durka.py status
```

Порядок задаёт kit: базы → S4DFarm → координатор Neo → Packmate. Worker и отправка на соревнование остаются выключены. Ожидаем работающие сервисы и адреса Farm/Packmate. Neo — координатор скриптов, не веб-панель. Ферма собирает флаги, не раскатывает патчи. Packmate FILE ищет в закрытом capture, не снимает трафик LAN.

Войдите в Farm с данными из приватного конфига и проверьте team/config view. Startup уже аутентифицирует `/api/get_config`; одна login-страница не проверяет API. Войдите в Packmate. Не выводите `neo info`, expanded Compose config или raw logs на трансляцию.

<a id="4-synthetic-end-to-end-checks"></a>
## 4. Synthetic-проверки полного пути

Создайте новый закрытый capture существующим fixture и импортируйте. Команды записывают только локальный synthetic-файл и меняют input Packmate этого deployment; старый input/data сохраняются.

```bash
python3 -c 'from integration.synthetic_pcap import make_pcap; from pathlib import Path; p = Path("local/first-run.pcap"); f = p.open("xb"); f.write(make_pcap("0123456789abcdef01234567")); f.close(); p.chmod(0o600)'
python3 durka.py traffic import local/first-run.pcap
python3 durka.py scan lab --patches
python3 scripts/defense_ops.py preflight --profile config/defense-profile.example.json
python3 integration/vulnbox_handoff.py
```

В Packmate добавьте сервис на порту **18080**, substring pattern `0123456789abcdef01234567`, затем один раз нажмите жёлтую кнопку разбора FILE со стрелкой вниз в боковой панели, а не ищите надпись «Start». Найдите GET `/durkahelper-smoke/…` и ответ `DURKAHELPER_RESPONSE_…` с верными направлениями. На намеренно уязвимом lab scanner ожидаемо возвращает `1`, это не поломка установки; Defense preflight и handoff должны вернуть `0`/PASS.

Выполните [безвредную readiness-задачу Neo](neo-RU.md#first-harmless-task), затем явно запустите `python3 durka.py worker` и однократно выполните эту disabled-задачу. Ожидайте readiness-сообщение в ограниченном `tail`; нет запроса к цели и принятого флага. В выбранном worker image должны быть реальные зависимости скрипта: default light image не является универсальной средой Python/Sage. После проверки остановите worker вместе с deployment.

[Изолированная complete-stack процедура](../integration/README-RU.md#release-candidate-acceptance) дополнительно проверяет synthetic Neo→Farm→mock receiver, отказ auth, native restore и точные payload Packmate. Это Linux AMD64 fixture, не доказательство Desktop или нативного Darwin client. Не направляйте его в операторский workspace или реальный endpoint отправки.

<a id="5-offline-restart-and-workload-rehearsal"></a>
## 5. Offline, restart и нагрузка

Сохраните Ethernet/LAN, но отключите Интернет согласованным способом. Не сбрасывайте Desktop и не чистите образы. Выполните cold start подготовленных сервисов:

```bash
python3 durka.py down
python3 durka.py up
python3 durka.py status
```

Ожидаем отсутствие downloads/builds; сохраняются настройки Farm, disabled-задача Neo и service/pattern/старые streams Packmate. FILE parsing не возобновляется автоматически: нажимайте кнопку разбора FILE только для намеренной обработки текущего capture. Повторите безвредную задачу Neo после явного запуска worker. Новые PCAP импортируются отдельно, это не бесконечный FILE pipe. Следуйте [offline-инструкции](offline-bundles-RU.md) и [native backup/recovery](MACOS_FULL_DEPLOYMENT_AND_TESTING-RU.md) до появления ценных данных; сохранённый каталог не является backup.

Запустите подготовленный стек под обычной нагрузкой минимум на 60 минут; проверьте отзывчивость, рост диска, memory pressure и повторный импорт PCAP. Hosted macOS CI не доказывает Docker Desktop, LAN и совместимость с локальными правилами.

<a id="6-failures-and-safe-shutdown"></a>
## 6. Ошибки и безопасная остановка

При ошибке не идите дальше: `status`, затем `doctor`; откройте [troubleshooting](MACOS_FULL_DEPLOYMENT_AND_TESTING-RU.md). Изменение конфига после setup требует `down` → edit → `configure` → `up`; при прерванной конфигурации может понадобиться `configure --rollback`. Недостающие образы подготовьте при Интернете, не во время игры. Клиент неверной архитектуры замените проверенным клиентом, не запускайте через непроверенный обход.

```bash
python3 durka.py down
```

Останавливается только свой deployment, включая worker; данные и образы остаются. Нельзя `down -v`, общий `prune`, широкое удаление и Desktop reset. Native dumps или консистентную остановленную копию восстанавливают в новое изолированное окружение, не поверх live database files.

<a id="remaining-manual-gates"></a>
## Оставшиеся ручные gates

- Реальный Mac: согласованная установка, auth/execution нативного клиента, полный стек в Desktop, offline start, recovery и обычная нагрузка.
- Домашний Ethernet: Mac и второй PC должны войти и выполнить полезные действия в Farm/Neo/Packmate, затем reconnect после restart; localhost/TCP connect недостаточны. Используйте [шпаргалку админа](TEAM_LAN_ADMIN_CHEATSHEET-RU.md).
- Только на площадке: повторите доступ участников и доступность checker по офлайн [game-day checklist](game-day-RU.md). AI и изменения кода не должны требоваться.
- Capture: подготовьте и [разрешённый Linux LIVE, и передачу закрытого PCAP](traffic-capture-RU.md). Mac на коммутаторе не видит трафик Vulnbox автоматически. Один FILE fallback не закрывает continuous-capture requirement.
- Протокол: проверьте adapter настоящего соревнования до включения отправки; replay восстановленных очередей остаётся выключен до проверки.
