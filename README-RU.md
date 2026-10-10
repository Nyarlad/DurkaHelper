<a id="durkahelper"></a>
# DurkaHelper

[English](README.md) | Русский

Офлайн-инструменты Defense для Attack/Defense CTF: разбор исходников, исследование трафика, проверка патчей и запуск общих командных инструментов из одного репозитория.

<a id="what-does-what"></a>
## Что за что отвечает

| Инструмент | Для чего нужен |
|---|---|
| **Сканер DurkaHelper** | Найти подозрительный код/конфигурацию в **локальной копии исходников** и открыть инструкцию исправления. Удалённые хосты не сканирует, патчи не применяет. |
| **Packmate** | Смотреть запросы/ответы и искать по трафику. На Docker Desktop — закрытые PCAP; LIVE — на разрешённом Linux-узле, который видит нужный трафик. |
| **S4DFarm** | Собирать флаги, показывать их статус и отправлять в систему соревнования. |
| **Neo** | Распределять командные скрипты между исполнителями и целями; передавать найденные флаги в S4DFarm. |

Защищаемые сервисы остаются на Vulnbox. Проверенные патчи применяйте там обычным способом развёртывания сервиса. Ферма обслуживает флаги, а не распространение патчей.

<a id="quick-start"></a>
## Быстрый старт

Для разбора исходников достаточно Python 3.10+; устанавливать пакеты через pip не нужно:

```bash
git clone https://github.com/Nyarlad/DurkaHelper.git
cd DurkaHelper
python3 durka.py scan /path/to/service --patches
```

Код завершения 1 означает находки для проверки. Начните с одного сервиса и [базы исправлений](docs/vulnerabilities/README-RU.md). Находка — повод проверить код, а не доказанная уязвимость.

Чтобы поднять общие инструменты, запустите Docker Desktop на macOS или Docker Engine с Compose на Linux:

```bash
python3 durka.py init
```

Заполните `local/durka.json`: LAN-адрес для доступа команды, адреса команд/сервисов, формат флага и настройки отправки соревнования. Пароли и ключ Neo генерируются автоматически. Файл приватный; `local/` исключён из Git.

Для участников и native workers Neo нужен реальный Ethernet IPv4. Loopback подходит для демо на одном ноутбуке со встроенным worker.

```bash
python3 durka.py setup
python3 durka.py up
python3 durka.py status
```

`setup` скачивает закреплённые исходники/образы и собирает стек; выполните его до отключения Интернета. `up` поднимает ферму, координатор Neo и Packmate. Исполнение скриптов и отправка флагов включаются отдельно, когда всё готово:

```bash
python3 durka.py worker
python3 durka.py submit
```

Перед отправкой прочитайте [инструкцию администратора](docs/MACOS_FULL_DEPLOYMENT_AND_TESTING-RU.md). Поддерживаемый адаптер — `ructf_http`; для другого протокола нужен совместимый адаптер. На Apple Silicon Packmate работает через эмуляцию amd64: прогоните стек на своём ноутбуке.

<a id="during-the-game"></a>
## Во время игры

1. Админ поднимает инструменты и передаёт LAN-адреса и учётные данные.
2. Защитники копируют исходники сервиса, сканируют их и изучают подозрительный трафик.
3. Применяют небольшой патч на Vulnbox, проверяют сервис/checker и повторяют скан.
4. Авторы скриптов тестируют работу, загружают её в Neo и смотрят флаги в S4DFarm.
5. Админ следит за доступностью, диском и backup. Для завершения — `python3 durka.py down`.

Основные маршруты: [workflow администратора 01–05](docs/ADMIN_WORKFLOWS-RU.md), [инструкция участника](docs/participant-guide-RU.md), [памятка админа для печати](docs/TEAM_LAN_ADMIN_CHEATSHEET-RU.md). Справочники: [индекс документации](docs/README-RU.md).

<a id="find-fix-and-verify"></a>
## Найти, исправить и проверить

**294 раздела, 174 правила сканера.** Это число рецептов проверки и сигналов, а не отдельных доказанных эксплойтов.

| Язык / уровень | Разделов |
|---|---:|
| [Python](docs/vulnerabilities/python-RU.md) | 40 |
| [JavaScript / TypeScript](docs/vulnerabilities/javascript-RU.md) | 28 |
| [PHP](docs/vulnerabilities/php-RU.md) | 23 |
| [Go](docs/vulnerabilities/go-RU.md) | 19 |
| [Java](docs/vulnerabilities/java-RU.md) | 18 |
| [C# / .NET](docs/vulnerabilities/csharp-RU.md) | 20 |
| [C / C++](docs/vulnerabilities/c-cpp-RU.md) | 28 |
| [Ruby / Rails](docs/vulnerabilities/ruby-RU.md) | 18 |
| [Rust](docs/vulnerabilities/rust-RU.md) | 18 |
| [SQL / базы данных](docs/vulnerabilities/sql-RU.md) | 18 |
| [Конфигурация / границы доверия](docs/vulnerabilities/configuration-RU.md) | 64 |

<a id="development"></a>
## Разработка

Тесты и synthetic-стенды нужны разработчикам; перед каждым игровым действием полный suite запускать не требуется.

```bash
python3 -m unittest discover -s tests
python3 scripts/scanner_coverage.py --check
```

[Вклад в проект](CONTRIBUTING-RU.md) · [Безопасность](SECURITY-RU.md) · [Изменения](CHANGELOG-RU.md) · [Возможности](docs/CAPABILITY_INVENTORY-RU.md)

Работайте только с разрешёнными системами. Учётные данные, исходники, флаги и PCAP держите приватно. DurkaHelper распространяется по [MIT](LICENSE), внешние инструменты — по [своим лицензиям](THIRD_PARTY_NOTICES-RU.md).
