<a id="administrator-cheat-sheet"></a>
# Шпаргалка администратора

[English](TEAM_LAN_ADMIN_CHEATSHEET.md) | Русский

Вы поднимаете общую ферму, координатор Neo и Packmate. После настройки для обычной работы нужны эти команды, а не форма валидации. Распечатайте страницу и сохраните [workflow 01–05](ADMIN_WORKFLOWS-RU.md) офлайн.

<a id="start"></a>
## Запуск

Запустите Docker Desktop/Engine и подключите Ethernet. Из корня репозитория:

```bash
DURKA_CONFIG=local/competition.json
python3 durka.py --config "$DURKA_CONFIG" up
python3 durka.py --config "$DURKA_CONFIG" status
```

Откройте ферму и Packmate. Войдите, затем повторите с отдельного ПК или устройства участника. URL используют реальный Ethernet-адрес; `localhost` работает только для вас. В каждом терминале задайте переменную с настоящим путём подготовленного конфига. Смена игровых настроек: остановить native workers, down, изменить этот конфиг, configure, затем up; всегда с тем же --config.

<a id="share-access"></a>
## Выдать доступ

| Что передать участникам | Откуда взять |
|---|---|
| URL и пароль фермы | URL из `status`; `credentials.farm_password` в выбранном приватном конфиге |
| Neo host:port и ключ | Адрес из `status`; `credentials.neo_key` |
| URL, логин и пароль Packmate | URL из `status`; `credentials.packmate_user / packmate_password` |
| Доступ к Vulnbox/сервису | Разрешённый команде порядок доступа к сервисам |

Передайте учётные данные приватно, отдельно от трансляции/скриншотов. Пароли БД и Docker-доступ участникам не нужны. Их страница — [инструкция участника](participant-guide-RU.md).

<a id="enable-work"></a>
## Включить работу

Когда скрипты/зависимости готовы:

```bash
python3 durka.py --config "$DURKA_CONFIG" worker
```

Когда протокол, endpoint/token и список команд соревнования правильные:

```bash
python3 durka.py --config "$DURKA_CONFIG" submit
```

Координатор раздаёт задания; workers выполняют и отправляют совпадающий stdout в Farm; Farm отправляет жюри. Встроенный worker — shell-only. Авторы используют один координатор и разные ID: регистрация выключенным → дождаться скачивания worker → single → проверить → намеренно включить → отключить. [Точные примеры Neo](neo-RU.md#one-shot-and-scheduled-harmless-example). QUEUED не означает приём жюри. Патчи применяются штатным механизмом сервиса.

<a id="traffic"></a>
## Трафик

Для закрытого PCAP:

```bash
python3 durka.py --config "$DURKA_CONFIG" traffic import /path/to/closed-capture.pcap
```

В Packmate зарегистрируйте сервис/порт/шаблон и один раз нажмите жёлтую кнопку обработки со стрелкой вниз. [Workflow 05](ADMIN_WORKFLOWS-RU.md#workflow-05--packmate-live-or-file) описывает LIVE doctor, офлайн-bundle и развёртывание. Capture settings — в приватном local/packmate-remote.json; порты/шаблоны сервисов — в UI. Ethernet на Mac не обеспечивает видимость; FILE не является LIVE.

<a id="check-the-team"></a>
## Проверить команду

Дома используйте Mac и отдельный ПК. На соревновании повторите с каждым рабочим устройством:

- Войти в ферму и Packmate по LAN-адресам.
- Найти один и тот же известный запрос/ответ в Packmate.
- Подключить клиент Neo, выполнить согласованный безвредный скрипт и увидеть результат.
- Переподключиться после обрыва клиента или перезапуска своего приложения.
- Держать обычную нагрузку; следить за памятью и диском.

Заполнять форму не требуется. Исправьте ошибки до использования этого устройства/маршрута.

<a id="if-something-breaks"></a>
## Если что-то сломалось

| Симптом | Что проверить |
|---|---|
| Все UI недоступны | `status`, Ethernet IP/bind, Docker и опубликованные порты |
| Не работает только одно устройство | Его URL, маршрут, учётные данные и версия клиента |
| Флаги ждут в ферме | Отправка включена? Адаптер/token/expiry правильные? |
| Скрипты Neo падают | Есть worker? Интерпретатор/зависимости? Маршруты? |
| Packmate пустой | Известный трафик, правильный IP сервиса, регистрация и источник файла/LIVE |
| Быстро растёт диск | Остановить новый capture; сохранить нужное и удалить только выбранные старые приватные данные |

Перед рискованными изменениями нужен backup. [Native recovery стека](../deployment/README-RU.md#native-backup-and-quarantine-restore) останавливает запись и восстанавливает в новое хранилище; не копируйте live-файлы БД обычным backup.

<a id="finish"></a>
## Завершение

Остановите новые скрипты/захват, сохраните backups, затем:

```bash
python3 durka.py --config "$DURKA_CONFIG" down
```

Данные и образы сохраняются. Не используйте общий prune и `down -v`. [Полная установка](MACOS_FULL_DEPLOYMENT_AND_TESTING-RU.md).
