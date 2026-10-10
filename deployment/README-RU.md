<a id="deployment-kit"></a>
# Deployment kit

[English](README.md) | Русский

Для обычной работы используйте `durka.py`. Он связывает поддерживаемый deployment S4DFarm/Neo/Packmate, генерирует приватные пароли и автоматически обрабатывает внутренние ID/checksum образов.

<a id="configure-and-start"></a>
## Настроить и запустить

```bash
python3 durka.py init
```

Заполните `local/durka.json`: Ethernet bind, список команд, формат флага, receiver/token и IP сервиса для Packmate. Подготовьте при доступном Интернете:

```bash
python3 durka.py setup
python3 durka.py up
python3 durka.py status
```

`setup` получает закреплённые исходники/образы и собирает четыре поддерживаемых source-компонента. `up` поднимает ферму, координатор Neo и Packmate FILE UI. Отправку и исполнение Neo не включает.

```bash
python3 durka.py worker
python3 durka.py submit
```

Worker включайте после подготовки доверенных скриптов/зависимостей. Отправку — после проверки адаптера/receiver соревнования. Поддерживается только `ructf_http`; это не выбор протокола для неизвестного соревнования.

<a id="change-event-settings"></a>
## Изменить настройки площадки

Если изменились LAN-адреса, команды, отправка или IP сервиса Packmate, остановите стек, отредактируйте конфиг, примените настройки и снова запустите:

```bash
python3 durka.py down
python3 durka.py configure
python3 durka.py up
```

Редактируйте `local/durka.json` между первой и второй командой. Данные сохраняются, используются кешированные образы; скачивания/пересборки нет. Замена платформы или учётных данных требует отдельной подготовки.

<a id="traffic-and-shutdown"></a>
## Трафик и остановка

```bash
python3 durka.py traffic import /path/to/closed-capture.pcap
python3 durka.py down
```

Импорт заменяет **закрытый** PCAP, сохраняет предыдущий и перезапускает только Packmate. Зарегистрируйте сервис/шаблон и один раз нажмите жёлтую кнопку обработки со стрелкой вниз в UI. `down` сохраняет данные и образы.

На Apple Silicon текущий Packmate работает через amd64-эмуляцию. LAN и скорость проверяются на целевой машине. Разрешённый Linux LIVE и ручной capture описаны в [трафике](../docs/traffic-capture-RU.md). Обычный Docker Desktop deployment — только FILE.

<a id="advanced-tools"></a>
## Расширенные инструменты

Они остаются для специальных операций, автоматизации и диагностики; это не дополнительные шаги знакомства с тулсетом:

| Скрипт | Назначение |
|---|---|
| `toolkit.py` | Прямой preview/prepare/build/preflight/start/stop |
| `packmate_file.py` | Ограниченная замена PCAP с сохранением старого файла и app-only restart |
| `packmate_host.py` | Разрешённый native Linux host-interface LIVE |
| `packmate_live.py` | Разрешённый существующий Linux container-namespace LIVE |
| `recovery.py` | Native backup стека, проверка и изолированный restore БД |
| `recovery_activation.py` | Restore/check/activation нового приложения-кандидата |

Прямые скрипты записи имеют явные `--apply`/confirmation-параметры; точные входы смотрите в help операции. Общий prune хоста не выполняется.

<a id="native-backup-and-quarantine-restore"></a>
<a id="backup-and-recovery"></a>
## Backup и recovery

Backup стека содержит секреты и native данные/состояние; храните вне Git и трансляции. Нужны окно обслуживания без параллельной записи и восстанавливаемый snapshot машины.

```bash
python3 deployment/recovery.py backup --help
python3 deployment/recovery.py verify --help
python3 deployment/recovery.py restore-native-stage --help
```

Backup останавливает запись, делает PostgreSQL native dumps, Redis snapshots и копирует остановленное состояние Neo/Redis. **Исходный стек остаётся остановленным для записи**, в том числе после прерывания. Restore создаёт новое изолированное хранилище, а не переписывает source. Образы и входной PCAP сохраняйте отдельно.

<a id="application-recovery-and-explicit-activation"></a>
<a id="application-recovery"></a>
## Восстановление приложений

```bash
python3 deployment/recovery_activation.py recover --help
python3 deployment/recovery_activation.py verify --help
python3 deployment/recovery_activation.py activate --help
```

Процедура берёт проверенные backup/stage, восстанавливает PostgreSQL и Neo в нового кандидата, проверяет вход/restart и оставляет его остановленным. **Все Redis-очереди/кеш/сессии кандидата удаляются**, чтобы не повторить старую работу; оригинальные RDB остаются в backup. Не используйте этот вариант, если эти значения должны сохраниться.

Activation отделена от restore и ничего не запускает. После принятия поднимите только выбранного кандидата, проверьте полезные действия и включите отправку/worker отдельно. Не запускайте source и замену на одинаковых endpoint.

<a id="approved-linux-container-namespace-live"></a>
<a id="linux-container-namespace-live"></a>
## Linux container-namespace LIVE

`packmate_live.py` работает с разрешённым существующим, запущенным single-bridge container namespace на native Linux amd64 Engine. У owner/network должны быть capture-label и опубликованный UI. Используется NET_RAW, а не privileged; БД доступна соседям bridge. Mirroring и общий захват хоста Vulnbox он не настраивает.

Для разрешённого host/mirror интерфейса используйте `packmate_host.py`. [Инструкция захвата](../docs/traffic-capture-RU.md) объясняет выбор и профиль. Ни один launcher не добавляет видимость пакетов Docker Desktop.

[Установка админа](../docs/MACOS_FULL_DEPLOYMENT_AND_TESTING-RU.md) · [Шпаргалка админа](../docs/TEAM_LAN_ADMIN_CHEATSHEET-RU.md)
