<a id="administrator-workflows"></a>
# Рабочие процессы администратора

[English](ADMIN_WORKFLOWS.md) | Русский

Практический маршрут для одного администратора и доверенной команды. Карточки и ручное переписывание hashes не требуются. Сохраните этот checkout, русские инструкции и приватные зависимости для офлайн-работы. [Короткая памятка для печати](TEAM_LAN_ADMIN_CHEATSHEET-RU.md).

<a id="roles-and-command-conventions"></a>
## Роли и правила выполнения команд

DurkaHelper готовит и управляет стеком. S4DFarm собирает результаты и отправляет их жюри. Координатор Neo хранит задания и планирует исполнение; **workers выполняют их и отправляют совпадающие с форматом значения stdout прямо в ферму**. Участники подключают управляющие клиенты к одному координатору; отдельный worker каждому не нужен. Packmate анализирует трафик. Сканер проверяет локальные копии исходников; патчи применяются вручную штатным механизмом развёртывания сервиса.

Команды ниже выполняются **из корня DurkaHelper на Mac/Linux администратора**, кроме явно обозначенного терминала Neo. Выберите один конфиг и указывайте его во всех командах стека:

```bash
DURKA_CONFIG=local/competition.json
```

В каждом новом терминале задайте переменную снова. `local/durka.json` — конфиг CLI по умолчанию, встречающийся в старых тематических примерах; не запустите случайно второе окружение. Примерные адреса предназначены для документации, а не работы на соревновании. `doctor`, `status` и `scan` — read-only; `init`, `setup`, `configure`, `up`, `worker`, `submit`, импорт и `down` меняют приватные файлы или собственные сервисы. Не используйте общий prune, Docker reset или `down -v`.

<a id="workflow-01--deploy-and-prepare-offline"></a>
## Workflow 01 — Развёртывание и подготовка офлайн

**Нужно заранее:** одобренные Python 3.10+, Git 2.30+, Docker Desktop/Engine с Compose v2; свободные диск и RAM; список команд, IP сервисов, формат флага, параметры жюри и разрешённый LAN-адрес от организаторов. Первая подготовка требует Интернета. Время: 30–60 минут впервые; около 5 минут для подготовленного запуска. [Первый запуск Mac](MACOS_FIRST_RUN-RU.md) описывает установку; [полный гайд](MACOS_FULL_DEPLOYMENT_AND_TESTING-RU.md) служит справочником.

Только для новой установки:

```bash
python3 durka.py --config "$DURKA_CONFIG" init
```

Откройте этот приватный JSON редактором. Сохраните сгенерированные credentials. В `profile.bind_address` укажите настоящий LAN IPv4 администратора для команды/native workers; выберите свободные `profile.ports.farm/neo/packmate`. Заполните `profile.farm.teams`, `flag_format`, `protocol_settings.SYSTEM_URL/SYSTEM_TOKEN`, `submit_limit`, `submit_period` и `flag_lifetime` по данным организаторов. `protocol: ructf_http` подходит только совместимому HTTP-интерфейсу. FILE `profile.packmate.local_ip` — **IP стороны сервиса в захваченных пакетах**, не адрес администратора. После подготовки не меняйте пути sources/workspace и платформу.

```bash
python3 durka.py --config "$DURKA_CONFIG" doctor
python3 durka.py --config "$DURKA_CONFIG" setup
python3 durka.py --config "$DURKA_CONFIG" up
python3 durka.py --config "$DURKA_CONFIG" status
```

`setup` скачивает/собирает закреплённые зависимости: выполните его до поездки, не во время офлайн-игры. `up` использует подготовленные образы и запускает БД → Farm → координатор Neo → Packmate. Worker и отправка включаются отдельно. Откройте напечатанные URL Farm/Packmate, войдите, проверьте список команд и повторите с другого устройства. Внутренние БД не являются интерфейсами команды. У Neo нет web-dashboard. Передавайте UI credentials и ключ Neo приватно, вне публичных скриншотов.

**Уже подготовлено:** пропустите `init/setup`. Чтобы применить настройки организаторов, остановите native worker и собственный стек, измените тот же JSON, затем:

```bash
python3 durka.py --config "$DURKA_CONFIG" configure
python3 durka.py --config "$DURKA_CONFIG" up
python3 durka.py --config "$DURKA_CONFIG" status
```

`configure` требует остановленного стека и не меняет credentials, платформу или структуру хранилищ. При ошибке обновления оставьте стек остановленным и используйте `configure --rollback`. При проблемах LAN проверяйте фактические bind/IP, порты и согласованные настройки application firewall; не отключайте защиту сети целиком.

**Офлайн-проверка:** сохраните кеш исходников, образы/данные Docker, приватные конфиг/workspace, совместимый Neo binary и все зависимости скриптов. Отдельный Linux LIVE bundle готовится в Workflow 05. Разрешённым способом уберите Интернет, оставив нужную LAN; выполните `down`, `up`, `status`, войдите в оба UI, запустите безвредное задание Neo, просканируйте локальную копию и импортируйте закрытый PCAP. Это проверка перезапуска подготовленной машины, не установки на пустую машину. [Офлайн-подготовка и чистое окружение игры](offline-bundles-RU.md).

<a id="workflow-02--scan-patch-and-verify"></a>
## Workflow 02 — Сканирование, патч и проверка

**Нужно:** разрешённая локальная копия исходников, порядок запуска/checker сервиса и ответственный за rollback. Рабочий каталог — корень репозитория; время 10–30 минут на небольшой патч, в зависимости от сервиса.

```bash
python3 durka.py scan /path/to/service --patches
```

Exit `1` — сигналы для разбора; `2` — неполный/некорректный вход. Прочитайте связанную рекомендацию, подтвердите применимость, сохраните оригиналы изменяемых файлов и при необходимости консистентный native backup БД. Примените один минимальный патч **вручную**. Прогоните regression tests сервиса, обычные login/read/write сценарии, старые данные и настоящий checker соревнования; повторите скан. Чистый скан или `/health` недостаточны. Единой restart-команды для всех Vulnbox нет: используйте механизм конкретного сервиса, а не `down/up` тулсета.

При регрессии восстановите предыдущие код/образ с сохранением текущих игровых данных. Не накатывайте старую БД поверх записей новых раундов. [Проверка патча](patch-validation-RU.md) содержит подробности; расширенные records для `patch-check` необязательны в этом ручном маршруте. [Backup/recovery](../deployment/README-RU.md#native-backup-and-quarantine-restore) относится к стеку тулсета, а не любому защищаемому сервису.

<a id="workflow-03--prepare-scripts-and-neo-execution"></a>
## Workflow 03 — Скрипты и исполнение Neo

**Нужно:** совместимый Neo v2.4.2 client, приватный конфиг с реальными host/key координатора, согласованные ID заданий и разрешённый список команд. У каждого worker должны быть настоящий интерпретатор, пакеты, вспомогательные файлы и маршруты к Farm и разрешённым сервисам. Встроенный light-worker предоставляет shell, не произвольные Python/Sage packages. Время: 10–15 минут для первого безвредного задания. [Установка Neo и полные примеры](neo-RU.md).

В **отдельном терминале**, из корня репозитория, можно запустить shell-only worker:

```bash
python3 durka.py --config "$DURKA_CONFIG" worker
```

Или из каталога распакованного **Neo client** запустите один подготовленный native worker; для администрирования заданий оба одновременно не нужны:

```bash
./neo --verbose=false --config client_config.yml run --jobs 1 --endless-jobs 0
```

Используйте приватный клиентский конфиг с уникальным worker `client_id` и корректным каталогом заданий. В чистом deployment можно вместо него использовать с подготовленным binary сгенерированный `config/neo-native.yml`; после смены LAN исправьте host либо передайте `--host LAN_IP:NEO_PORT`. Внешним workers недоступно внутреннее имя Farm из loopback-профиля.

В каталоге **Neo client автора** создайте безвредный `exploits/ready.sh` из гайда Neo, затем:

```bash
chmod u+x exploits/ready.sh
./neo --verbose=false --config client_config.yml add --id ready-author-a --disabled --interval 1m --timeout 3s exploits/ready.sh
./neo --verbose=false --config client_config.yml single ready-author-a
./neo --verbose=false --config client_config.yml tail --count 20 ready-author-a
```

Перед `single` дождитесь скачивания нового задания worker и перезапуска его execution loops. Ожидается `worker ready for ...`, не флаг. `single` охватывает **все настроенные команды**, не включает повторение. Каждый автор использует отдельный общий ID. После успешного разрешённого одиночного прогона намеренно проверьте расписание:

```bash
./neo --verbose=false --config client_config.yml enable ready-author-a
./neo --verbose=false --config client_config.yml tail --count 20 ready-author-a
./neo --verbose=false --config client_config.yml disable ready-author-a
```

Дождитесь следующих запусков с интервалом в минуту перед отключением. Cron не нужен; закрытие управляющего клиента не отключает задание. После отключения новых запусков остановите native worker через Ctrl+C; уже исполняемые задания могут завершиться. При сбое сначала проверьте наличие/скачивание worker, интерпретатор и маршруты. Не показывайте raw `neo info` или debug logs на экране: они могут раскрыть credentials.

<a id="workflow-04--farm-and-jury-submission"></a>
## Workflow 04 — Ферма и отправка жюри

**Нужно:** согласованные endpoint/token жюри, точные regex флага, lifetime и rate limits; легитимное синтетическое либо предоставленное организаторами тестовое значение. Время: 5–10 минут. С placeholders отправку не включайте. [Справочник фермы](s4dfarm-RU.md).

Совместимый интерфейс ForcAD использует **HTTP PUT `/flags`**, JSON-массив флагов и заголовок `X-Team-Token`. Настройте полный URL организатора и приватный token через Workflow 01; не переносите путь, лимиты или token с другого соревнования. Поддерживаемый adapter — `ructf_http`; другой протокол требует отдельной проверки, не непроверенной подмены адаптера.

Убедитесь, что разрешённый тестовый stdout worker появился в Farm, затем из корня репозитория включите отправку:

```bash
python3 durka.py --config "$DURKA_CONFIG" submit
```

`QUEUED` подтверждает только приём в ферму. Проверьте окончательный статус **и ответ receiver**, а также жюри/scoreboard, если доступно. Invalid, duplicate и expired проверяйте на контролируемом синтетическом жюри; не делайте массовую повторную отправку на реальном событии. Deduplication Farm может подавить второе одинаковое значение до HTTP-запроса. `SKIPPED` бывает локальной политикой очереди, не ответом ForcAD. Если очередь зависла, проверьте включение отправки, endpoint/token, lifetime, rate limits и связь worker → Farm. Не печатайте tokens при диагностике.

Чтобы безопасно остановить отправку, отключите новые задания Neo, остановите native workers и выполните `down` выбранного стека. После `up` отправка включается явно снова. Перед включением проверьте восстановленные очереди: нельзя слепо переотправлять просроченные данные.

<a id="workflow-05--packmate-live-or-file"></a>
## Workflow 05 — Packmate LIVE или FILE

**Нужно:** разрешённый источник трафика. Mac на обычном Ethernet не видит весь трафик Vulnbox. FILE анализирует закрытые файлы, **не является непрерывным LIVE**. Время: 10–20 минут для подготовленного Linux LIVE; 3–5 минут на FILE import. [Варианты трафика](traffic-capture-RU.md) и [инструкция удалённого LIVE](packmate-remote-RU.md).

На машине администратора при наличии Интернета один раз подготовьте **отдельную пару Linux AMD64 образов**. ARM64-образ БД с Mac не заменяет её:

```bash
python3 durka.py traffic live bundle --output local/packmate-live-ready --download --apply
```

Уже успешный bundle сохраните; команда требует нового output path. Python на целевой машине не нужен. Linux LIVE требует rootful Docker/Compose, проверенную SSH identity, явно разрешённый **интерфейс целиком** и согласие на host networking + NET_RAW. Privileged container, NET_ADMIN и Docker socket mount не нужны. Сначала выполните read-only discovery с настоящими разрешёнными host/key:

```bash
python3 durka.py traffic live doctor --host example@vulnbox.example --key ~/.ssh/ctf_capture
```

`--docker /absolute/approved-wrapper` нужен только если обычный `docker` недоступен пользователю; passwordless sudo не выбирается автоматически. Doctor не меняет права/firewall. Проверьте SSH fingerprint по доверенному каналу. Затем создайте новый приватный конфиг цели с фактическими результатами doctor:

```bash
python3 durka.py traffic live init --host example@vulnbox.example --key ~/.ssh/ctf_capture --remote-dir /home/example/durka-packmate-live --interface eth0 --service-ip 192.0.2.10 --bind 192.0.2.20 --ui-port 65000 --db-port 55432
```

**Конфигурация заполняется здесь, до `up`:** при необходимости измените `local/packmate-remote.json`. В его `profile` находятся interface, IP стороны сервиса, Linux UI bind/ports, TCP/UDP timeouts и retention. `bind` назначен Linux, не Mac. БД доступна только через loopback. **Названия сервисов, порты и шаблоны поиска регистрируются отдельно в UI Packmate**. Сгенерированные application properties/Compose не редактируйте. Правка JSON после deployment не перенастраивает работающую установку; перед созданием замены прочитайте удалённый гайд.

```bash
python3 durka.py traffic live doctor --bundle local/packmate-live-ready
python3 durka.py traffic live up --bundle local/packmate-live-ready --apply --host-network-approved --interface-scope-approved
python3 durka.py traffic live status
```

Это переносит и загружает готовые образы без Интернета на цели, затем запускает только собственный project. Меняются удалённые приватные файлы/контейнеры, используются одобренные capture privileges. Откройте напечатанный URL, войдите с данными приватного конфига; на Mac `traffic live password` копирует пароль, не печатая его. Зарегистрируйте реальные порты обоих сервисов. Выполните обычный известный запрос: проверьте запрос/ответ, направление относительно сервиса, timestamps и checker health, затем перезапуск capture через собственные `down --apply` / `up ...`. Retention ограничивает возраст, не жёсткий размер диска; следите за диском. Readiness/authentication PASS сами по себе не доказывают захват.

Для FILE получите **закрытый** PCAP разрешённым порядком захвата/передачи. Из checkout администратора:

```bash
python3 durka.py --config "$DURKA_CONFIG" traffic import /path/to/closed-capture.pcap
python3 durka.py --config "$DURKA_CONFIG" status
```

Выберите/зарегистрируйте сервис в локальном UI Packmate и один раз нажмите **жёлтую кнопку обработки со стрелкой вниз**; не ищите подпись Start или Load PCAPs. Дождитесь обработки, найдите известный запрос и ответ, затем повторите с другим закрытым файлом. Import сохраняет предыдущий файл и перезапускает только Packmate. Пусто: проверьте IP сервиса, порт/шаблон, известный marker, состояние обработки и timestamps потоков; не предполагается наличие фильтра времени. На Apple Silicon Packmate использует AMD64 emulation; измерьте задержку локально.

**Остановка/восстановление:** остановите новые входные данные, сохраните нужные приватные данные, выполните `traffic live down --apply` только для этого настроенного Linux capture; `durka.py --config "$DURKA_CONFIG" down` — для локального стека. Оба сохраняют данные/образы. Не удаляйте live-файлы БД. Если LIVE запрещён или трафик не виден, используйте FILE как резерв и отмечайте отсутствие continuous capture. [Native recovery и отдельный restore](../deployment/README-RU.md#native-backup-and-quarantine-restore) и [офлайн-гайд](offline-bundles-RU.md) описывают восстановление; restore нужно проверить отдельно, прежде чем полагаться на него.

<a id="final-operator-checks"></a>
## Финальные проверки оператора

Войдите с каждого участвующего устройства; выполните полезное действие UI и переподключение. Проверьте фактическую среду каждого скрипта, приём Farm → жюри, разрешённый LIVE либо closed FILE, офлайн-перезапуск под обычной нагрузкой. Маршруты события, capture permission и настройки организаторов проверяются на конкретном соревновании. Linux tests и hosted macOS CI не доказывают совместимость Docker Desktop, командной LAN или локальных правил. Невыполненные проверки — **NOT TESTED**, не готовность.
