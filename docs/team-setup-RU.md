<a id="how-the-teams-tools-connect"></a>
# Как связаны командные инструменты

[English](team-setup.md) | Русский

Один администратор поднимает общий стек. Участники открывают его LAN-интерфейсы и подключают клиенты Neo. Защищаемые сервисы остаются на Vulnbox.

```text
Teammates ──Ethernet──> Farm UI/API ──> competition flag receiver
         ├───────────> Neo coordinator ──> workers ──> permitted targets
         └───────────> Packmate UI
Vulnbox traffic ──> approved Linux LIVE, or closed PCAP ──> Packmate FILE
Service source copy ──> DurkaHelper scan ──> reviewed patch ──> Vulnbox
```

<a id="who-owns-what"></a>
## Кто за что отвечает

Админ отвечает за общий конфиг, запуск, учётные данные, отправку и backups. Защитники — за review, патчи и regression-тесты сервиса. Авторы — за свои скрипты/зависимости и результаты в ферме. Workers Neo выполняют доверенный командный код.

Ферма отправляет **флаги**, Neo распределяет **скрипты**. Патчи сервисов они автоматически не развёртывают. Используйте обычный доступ/деплой Vulnbox вашей команды.

Автор загружает скрипт в общий координатор Neo; подготовленный worker исполняет его и передаёт подходящие результаты stdout прямо в ферму. Несколько авторов могут пользоваться одним worker: каждому запускать свой не обязательно. См. [workflow клиентов/workers и примеры разового запуска и расписания](neo-RU.md#team-workflow-clients-coordinator-and-workers). Отправка из фермы включается отдельно; попадание в очередь ещё не подтверждает приём жюрейкой.

<a id="addresses"></a>
## Адреса

Используйте Ethernet IPv4 админа и порты из `python3 durka.py status`. По умолчанию: ферма 8080, Neo 5005, Packmate 65000. Участникам не нужны `localhost`, Docker DNS и `host.docker.internal`.

Database, Redis и Docker остаются приватными. Клиентам/workers Neo нужен доступ к координатору и ферме; workers также нужны разрешённые маршруты до целей. Используйте только разрешённые площадкой порты и доступ.

<a id="first-check"></a>
## Первая проверка

Дома проверьте машину админа и отдельный ПК. На площадке каждый участник должен войти, выполнить полезное действие и переподключиться. Ethernet link или открытого TCP-порта недостаточно.

Ноутбук не видит автоматически весь трафик коммутируемой LAN. Выберите [разрешённый LIVE или импорт PCAP](traffic-capture-RU.md).

[Установка админа](MACOS_FULL_DEPLOYMENT_AND_TESTING-RU.md) · [Шпаргалка админа](TEAM_LAN_ADMIN_CHEATSHEET-RU.md) · [Инструкция участника](participant-guide-RU.md)
