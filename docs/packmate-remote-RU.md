<a id="packmate-live-deploy-from-the-laptop-over-ssh"></a>
# Packmate LIVE: запуск с ноутбука по SSH

[English](packmate-remote.md) | Русский

Все команды ниже выполняются **на ноутбуке из корня DurkaHelper**. На Vulnbox
Python не нужен: программа переносит готовые конфиги и запускает Docker Compose.
Это не заменяет [FILE import](traffic-capture-RU.md#file-on-the-laptop) на Mac.

<a id="requirements"></a>
## Что требуется

- На ноутбуке: Python 3.10+, SSH; Docker нужен только для подготовки образов.
  Для комплекта требуется Docker CLI/Engine API 1.49+ с явным
  [выбором платформы](https://docs.docker.com/reference/cli/docker/image/inspect/).
- На источнике трафика: native Linux **amd64**, локальный rootful Docker Engine,
  Compose v2, `sh`, `tar`, `ip`, `ss`, `stat`, `df`, `sha256sum`, `cut`, `awk`.
- Работающий доступ по ключу и заранее проверенный SSH host key. Программа не
  принимает новый host key автоматически. Для ключа с passphrase сначала выполните
  `ssh-add ~/.ssh/ctf_capture` — парольная фраза не передаётся программе.
- Разрешение на **весь выбранный интерфейс**, host networking и NET_RAW.
  Не используются privileged, NET_ADMIN, Docker socket mounts или установка пакетов.
- Минимум 3 GiB доступной RAM и 5 GiB свободного диска перед запуском. Контейнеры
  ограничены суммарно 2 CPU / 2 GiB RAM. Очистка по возрасту — не жёсткая disk quota.

Неизменённый upstream Packmate кратко использует широкий TCP/UDP startup filter.
Mac на обычном switch не видит автоматически трафик Vulnbox. Выбор интерфейса
определяет разрешённый источник трафика; программа не создаёт зеркало и не меняет
firewall или маршруты вручную. Docker создаёт только сети своего deployment.

<a id="1-read-only-doctor-before-configuration"></a>
## 1. Read-only doctor — до настройки

Замените example hostname и путь ключа. Если используется уже одобренный Docker
wrapper, передайте его абсолютный путь через `--docker`; shell-команды не допускаются.

```bash
python3 durka.py traffic live doctor \
  --host example@vulnbox.example --key ~/.ssh/ctf_capture \
  --ui-port 65000 --db-port 55432
```

Doctor собирает Engine ID, архитектуру, интерфейсы/IP, RAM, диск, доступность
Compose/утилит, наличие amd64-образов и занятость двух портов. **Ничего не пишет
на Vulnbox, не скачивает и не запускает.** PASS означает пригодность проверенных
предпосылок, а не доказанную видимость трафика. WARNING для отсутствующих образов
исправляется офлайн-комплектом. BLOCKED означает проблему доступа, платформы,
ресурсов или портов; чужие процессы/контейнеры не останавливайте.

<a id="2-prepare-offline-images-before-the-event"></a>
## 2. Подготовить офлайн-образы до соревнования

При доступном Интернете на ноутбуке и запущенном Docker:

```bash
python3 durka.py traffic live bundle \
  --output local/packmate-live-images --download --apply
```

Скачиваются **два закреплённых Linux amd64 образа**, даже на ARM64 Mac. Если они
уже кешированы, уберите `--download`. Каталог должен быть новым. В нём находятся
`images.tar` и автоматический manifest; вручную SHA заполнять не нужно. Сохраните
оба файла вместе. Обычный ARM64 PostgreSQL из Mac-стека не заменяет amd64 образ.
Проверка и экспорт явно выбирают Linux amd64, даже если в кеше одновременно
есть ARM64-вариант; работающий Mac-стек не изменяется.
Команда изменяет только локальные файлы и image cache, не запускает контейнеры.
Не коммитьте архивы образов; перед публичным распространением отдельно проверьте upstream licenses.

<a id="3-create-one-private-configuration"></a>
## 3. Создать один приватный конфиг

Примерные значения заменяются результатом doctor и правилами площадки:

```bash
python3 durka.py traffic live init \
  --host example@vulnbox.example --key ~/.ssh/ctf_capture \
  --remote-dir /home/example/durka-packmate-live \
  --interface eth0 --service-ip 192.0.2.10 --bind 192.0.2.20 \
  --ui-port 65000 --db-port 55432
```

`--service-ip` — IP стороны защищаемого сервиса **в захватываемом трафике**;
`--bind` — назначенный Linux-хосту IP для UI. Они могут различаться.
Interface index/MAC и Engine ID подставляются автоматически. Создаётся только
локальный `local/packmate-remote.json` с новыми паролями; источник не меняется.
Не публикуйте этот файл и не показывайте его публично. Повторный init не перезаписывает
конфиг. Другой deployment: отдельные `--config` и `--remote-dir`.

<a id="where-the-deployment-configuration-lives"></a>
## Где находится deployment-конфиг

На ноутбуке: `local/packmate-remote.json` (либо файл из `--config`).
Он отдельный от farm/FILE-конфига. Пароли внутри: не показывайте файл публично
и не коммитьте его. В секции `profile` находятся:

| Поле | Назначение | Значение по умолчанию при init |
|---|---|---|
| `interface` | Разрешённый Linux-интерфейс захвата | Выбирается через `--interface` |
| `local_ip` | IP стороны сервиса в пакетах; определяет направление | `--service-ip` |
| `bind_address`, `ui_port` | Linux-адрес и порт веб-интерфейса | `--bind`, порт 65000 |
| `db_port` | PostgreSQL, только IPv4 loopback | 55432 |
| `tcp_timeout_seconds`, `udp_timeout_seconds` | Таймауты потоков | 30 / 10 секунд |
| `timeout_check_seconds` | Период проверки таймаутов | 5 секунд |
| `retention_minutes`, `cleanup_interval_minutes` | Возраст удаления и период очистки | 60 / 1 минут |

Порты приложений и поисковые patterns задаются отдельно [в UI](packmate-RU.md#ui-services-and-patterns).
На Linux `workspace/application.properties` и `runtime-compose.json` генерируются
из этого конфига автоматически. Вручную на источнике их не редактируйте.

Адреса/порты/интерфейс выбирайте при `init`; таймауты и retention в `profile`
можно настроить **до первого up**, сохранив права файла 0600. Engine ID,
index/MAC интерфейса, project и images — автоматические проверки, не параметры
для обхода ошибки doctor. Credentials не меняйте отдельно от существующей БД.

После deployment конфиг и runtime проверяются на точное соответствие.
Изменение локального JSON **не обновляет** работающий Packmate: текущий launcher
не поддерживает in-place reconfiguration. Сохраните исходный конфиг для безопасного
`down`; другое deployment создавайте через отдельные `--config` и новый
`--remote-dir`, проверив свободные порты и разрешения. Старые данные сохраняются,
но история БД автоматически в новый workspace не переносится.

<a id="4-check-and-start"></a>
## 4. Проверить и запустить

```bash
python3 durka.py traffic live doctor --bundle local/packmate-live-images
python3 durka.py traffic live up --bundle local/packmate-live-images \
  --apply --host-network-approved --interface-scope-approved
```

Вторая команда **изменяет источник**: при необходимости загружает переданные
образы, создаёт только новый приватный workspace и два своих контейнера.
Интернет на Vulnbox не используется: нет pull/build/install, запуск всегда
`--no-build --pull never`. Если закреплённые образы уже есть на источнике,
`--bundle` можно убрать. Непроверенные/изменившиеся образы не принимаются.

Ожидается `status: PASS`, `authenticated_capture_started: true`, адрес UI.
Авторизованная готовность проверяется через временный SSH tunnel; SSH forwarding
должен быть разрешён. **Это ещё не подтверждение корректности трафика.**
Проверка интерфейса/Engine повторяется; старый workspace не перезаписывается.

<a id="5-login-and-inspect-a-transaction"></a>
## 5. Войти и проверить транзакцию

На Mac скопировать пароль, не выводя его на экран:

```bash
python3 durka.py traffic live password
```

Логин `operator`, пароль вставьте из буфера в UI по адресу из `up`. Команда
изменяет только буфер Mac. На других ОС используйте приватное поле
`credentials.password` без трансляции экрана. Зарегистрируйте сервисы/шаблоны
в UI [по пошаговой инструкции](packmate-RU.md#ui-services-and-patterns), найдите известные **request и response**, проверьте направление, время,
повторный запрос и доступность приложения. Статус контейнера этого не заменяет.

<a id="6-stop-and-start-again"></a>
## 6. Остановка и повторный старт

```bash
python3 durka.py traffic live status
python3 durka.py traffic live down --apply
python3 durka.py traffic live up --bundle local/packmate-live-images \
  --apply --host-network-approved --interface-scope-approved
```

`down` останавливает только проект этого конфига и сохраняет PostgreSQL/настройки.
Не использует `down -v`, `prune` или удаление каталогов. Проверки ownership не дают
ему остановить чужой проект. Старый запуск другим helper не присваивается автоматически.

<a id="troubleshooting"></a>
## Если не получилось

- SSH failed: сначала проверьте обычный SSH, fingerprint и `ssh-add`; ключ не
  копируйте на Vulnbox. Программа работает без интерактивных password prompts.
- Порты заняты: выберите свободные при init или самостоятельно остановите
  **только известный свой** старый deployment. Firewall автоматически не меняется.
- Missing/wrong-platform images: подготовьте комплект именно Linux amd64.
- Interface/Engine changed: заново проверьте источник и разрешённый scope;
  не обходите проверку редактированием идентификаторов наугад.
- Readiness timeout: свои контейнеры могли уже запуститься. Выполните `status`,
  затем при необходимости `down --apply`; данные сохраняются.
- Неполный перенос: каталог сохраняется для диагностики, автоматически не
  удаляется и не перезаписывается. Новый workspace допустим только после проверки
  частичных ресурсов. Нет автоматической переустановки.
- Нет Docker/Compose или разрешения: LIVE этим путём BLOCKED. Используйте FILE
  только при наличии разрешённого закрытого PCAP; это не continuous capture.

Python-free target обеспечивается отсутствием вызовов Python на источнике.
Успешный Linux deployment не подтверждает Docker Desktop LIVE, реальную
сеть площадки, нагрузку или disk quota. Проверка известной транзакции остаётся
ручным обязательным шагом.

[Выбор LIVE/FILE](traffic-capture-RU.md) · [Packmate](packmate-RU.md)
