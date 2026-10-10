<a id="documentation"></a>
# Документация

[English](README.md) | Русский

Начните со своей роли. У английских страниц есть русский перевод рядом; обе версии доступны офлайн.

<a id="main-routes"></a>
## Основные маршруты

| Ваша задача | Что читать |
|---|---|
| Поднять общие инструменты | [Последовательные workflow 01–05](ADMIN_WORKFLOWS-RU.md) → [памятка для печати](TEAM_LAN_ADMIN_CHEATSHEET-RU.md); [первый запуск Mac](MACOS_FIRST_RUN-RU.md) для установки |
| Защищать сервис или писать скрипты | [Инструкция участника](participant-guide-RU.md) → [шпаргалка защитника](defense-cheatsheet-RU.md) |
| Разобраться с трафиком | [Захват/импорт](traffic-capture-RU.md) → [Packmate](packmate-RU.md) |
| Запустить Linux LIVE с ноутбука | [SSH doctor, офлайн-образы и запуск](packmate-remote-RU.md) |
| Проверить находку | [Справочник сканера](offline-scanner-RU.md) → [база исправлений](vulnerabilities/README-RU.md) |

<a id="how-the-stack-fits-together"></a>
## Как связан стек

[Схема команды](team-setup-RU.md) объясняет связи. [S4DFarm](s4dfarm-RU.md) собирает/отправляет флаги; [Neo](neo-RU.md) распределяет скрипты; [Packmate](packmate-RU.md) помогает разбирать трафик. Патчи Vulnbox применяются обычным способом развёртывания сервиса.

Основная точка входа — `python3 durka.py`. Конфигурация хранится в исключённом из Git `local/durka.json`; обязательных evidence-форм и ручного переписывания checksum в этом маршруте нет.

<a id="references"></a>
## Справочники

| Тема | Страницы |
|---|---|
| Defense | [Процесс](defense-RU.md), [разбор исходников](code-review-RU.md), [проверка патчей](patch-validation-RU.md), [игровой день](game-day-RU.md) |
| Развёртывание | [Справочник kit](../deployment/README-RU.md), [подготовка офлайн](offline-bundles-RU.md), [локальные утилиты](local-tools-RU.md) |
| Разработка | [Вклад в проект](../CONTRIBUTING-RU.md), [новые правила](development-RU.md), [synthetic lab](../lab/README-RU.md), [integration-стенды](../integration/README-RU.md), [релиз](release-checklist-RU.md) |
| Проект | [Текущие возможности](CAPABILITY_INVENTORY-RU.md), [правила соревнований](competition-rules-RU.md), [лицензии](../THIRD_PARTY_NOTICES-RU.md) |

Расширенные скрипты сохраняют preview и явные параметры для записи/restore. Открывайте эти справочники по необходимости; это не дополнительные шаги для каждого участника.
