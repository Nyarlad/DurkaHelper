<a id="traffic-live-or-pcap-import"></a>
# Трафик: LIVE или импорт PCAP

[English](traffic-capture.md) | Русский

Подготовьте оба пути до соревнования. На месте выберите разрешённый организаторами; обычный FILE import не требует изменения кода.

<a id="choose-a-route"></a>
## Выбрать вариант

| Что доступно | Использовать |
|---|---|
| Разрешено запустить capture на Vulnbox/native Linux и виден трафик его интерфейса | Packmate LIVE на этом Linux-узле |
| Предоставлен разрешённый Linux mirror/capture интерфейс | Packmate LIVE там; зеркало дают организаторы |
| Только закрытые PCAP или разрешённый SSH/tcpdump | Передать закрытые файлы и использовать Packmate FILE на ноутбуке |
| Разрешённого источника нет | Продолжить разбор исходников; анализ трафика недоступен |

Mac на том же Ethernet switch не видит автоматически пакеты Vulnbox. Поддерживаемый маршрут Docker Desktop — только FILE. Бесконечный FILE pipe не заменяет LIVE: upstream привязывает timeout незавершённых потоков и periodic cleanup к LIVE.

<a id="file-on-the-laptop"></a>
## FILE на ноутбуке

Поднимите стек, получите **закрытый** capture и импортируйте:

```bash
python3 durka.py up
python3 durka.py traffic import /path/to/closed-capture.pcap
python3 durka.py status
```

Команда сама проверяет файл, сохраняет предыдущий capture и перезапускает только Packmate. БД и другие инструменты продолжают работать. Ручные SHA/карточки не нужны.

В Packmate зарегистрируйте сервис/шаблон, проверьте IP стороны сервиса в конфиге и один раз нажмите жёлтую кнопку разбора FILE со стрелкой вниз в боковой панели. Найдите известные запрос/ответ. Подробности и отличие от загрузки файла — в [инструкции UI](packmate-RU.md#file-on-the-laptop). Каждый новый файл — той же import-командой и кнопкой разбора. EOF не сбрасывает upstream parser; не копируйте новый capture поверх активного FILE.

Передача на носителе тоже подходит. Captures приватные: внутри могут быть cookies, учётные данные и флаги.

<a id="capture-a-closed-file-on-linux"></a>
## Получить закрытый файл на Linux

Лучше использовать файлы организаторов. Если capture разрешён и `tcpdump`/`timeout` уже установлены, запускайте в приватном каталоге источника. Замените все placeholders разрешённым интерфейсом/сервисом/портами и **новым** именем файла:

```bash
umask 077
timeout --signal=INT 60 tcpdump -i <APPROVED_INTERFACE> -p -nn -s 65535 \
  -c 1000 -w <NEW_PRIVATE_PREFIX>.pcap \
  'host <SERVICE_IPV4> and (tcp port <TCP_PORT> or udp port <UDP_PORT>)'
```

Дождитесь завершения процесса до передачи. Это до 60 секунд или 1 000 пакетов, примерно 66 MB плюс overhead формата. Код `timeout` 124 может быть ожидаемым; другие ошибки захвата нужно проверить. Рецепт основан на [tcpdump manual](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in); это проверенная по инструкции процедура, а не тест интерфейса вашей площадки.

При существующем разрешённом SSH identity и доверенном host key:

```bash
scp -o StrictHostKeyChecking=yes -P <SSH_PORT> \
  <USER>@<SOURCE_HOST>:<EXACT_CLOSED_FILE> ./incoming-01.pcap
python3 durka.py traffic import ./incoming-01.pcap
```

Эти две команды запускаются на ноутбуке из корня репозитория. Сохраните source до успешного импорта/использования. Файл, в который ещё идёт запись, не передавайте.

<a id="host-interface-live"></a>
## Host-interface LIVE

Для обычного запуска с ноутбука используйте [SSH deployment с doctor и офлайн-образами](packmate-remote-RU.md).
Python на Vulnbox не требуется. Ниже — низкоуровневый Linux helper для расширенных ручных процедур.

Это ветка Linux-админа, отдельная от Docker Desktop. Требуются native Linux amd64, стандартный локальный rootful Docker Engine, кешированные закреплённые образы Packmate/PostgreSQL и разрешение на **весь выбранный интерфейс**. Закреплённый upstream при запуске кратко применяет широкий TCP/UDP filter.

Launcher использует host networking и NET_RAW; не privileged и не NET_ADMIN. БД остаётся на IPv4 loopback; firewall, маршруты и switch не меняются.

Посмотрите нужные Engine/interface:

```bash
docker info --format '{{.ID}}'
ip -json link show
```

Укажите увиденные Engine ID/interface name/index/MAC и реальные адреса в приватном `local/packmate-host.json`:

```json
{
  "schema": "durkahelper.packmate-host.v1",
  "daemon_id": "REPLACE_ENGINE_ID",
  "interface": "eth0", "ifindex": 2, "interface_mac": "02:00:00:00:00:01",
  "local_ip": "192.0.2.10", "bind_address": "192.0.2.20",
  "ui_port": 65000, "db_port": 55432,
  "tcp_timeout_seconds": 30, "udp_timeout_seconds": 10,
  "timeout_check_seconds": 5, "retention_minutes": 60,
  "cleanup_interval_minutes": 1
}
```

Это примеры значений. `local_ip` — IP стороны сервиса в трафике; `bind_address` — адрес UI для команды. Отдельный приватный credentials JSON содержит `username`, `password`, `db_password`; пароли — разные сгенерированные safe ASCII длиной 20–128. Файлы должны лежать в owner-only каталоге.

На разрешённом Linux-хосте подготовьте новый workspace и запустите:

```bash
python3 deployment/packmate_host.py prepare \
  --workspace ../private-deployment/host-live-01 \
  --profile local/packmate-host.json \
  --credentials local/packmate-host-credentials.json \
  --apply --approval-id host-live-prepare
python3 deployment/packmate_host.py up \
  --workspace ../private-deployment/host-live-01 \
  --capture-approval '<INTERFACE>:<IFINDEX>:<MAC>' \
  --host-network-approved --interface-scope-approved \
  --apply --approval-id host-live-start
```

Зарегистрируйте сервисы/шаблоны в UI и проверьте известные TCP/UDP запросы/ответы, направление, задержку, незавершённые потоки и restart. Видимость пакетов обеспечивается разрешённым размещением host/mirror. Очистка по возрасту — не жёсткая disk quota: следите за ростом хранилища.

Остановить только этот capture deployment с сохранением данных:

```bash
python3 deployment/packmate_host.py down \
  --workspace ../private-deployment/host-live-01 \
  --apply --approval-id host-live-stop
```

Для разрешённого существующего container namespace — отдельный [container LIVE reference](../deployment/README-RU.md#approved-linux-container-namespace-live). Прямые helpers поддерживают контролируемые cache/bootstrap операции; для другого offline-хоста смотрите их `--help`.

<a id="check-before-relying-on-traffic"></a>
## Проверить до использования

Найдите известную транзакцию, а не только работающий UI. Проверьте оба направления, время, характерные TCP/UDP, рост диска и restart. Остановите capture при неверном scope, утечке секретов или приближении к пределу диска.

FILE — отложенный анализ. Если необходим непрерывный анализ, одних закрытых файлов недостаточно. Прогоните оба разрешённых пути и подготовьте capture-зависимости/образы до выезда.

[Packmate](packmate-RU.md) · [Шпаргалка админа](TEAM_LAN_ADMIN_CHEATSHEET-RU.md)
