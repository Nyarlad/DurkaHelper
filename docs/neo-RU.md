<a id="neo-distribute-and-run-team-scripts"></a>
# Neo: распределить и выполнить командные скрипты

[English](neo.md) | Русский

Neo хранит командные скрипты на координаторе и распределяет исполнение между подключёнными workers и командами из списка фермы. Workers передают подходящие флаги в S4DFarm. Это полезно, когда одному ноутбуку не нужно запускать каждый скрипт против каждой цели. Защитные патчи Neo не развёртывает.

<a id="administrator"></a>
## Администратор

`python3 durka.py up` запускает координатор. `python3 durka.py worker` — встроенный light-worker. Участникам передайте LAN-адрес координатора из `status` и приватный `credentials.neo_key`.

Из окружения worker должны быть доступны координатор, ферма и разрешённые цели. Light-image содержит shell; для Python/Sage и других зависимостей нужны отдельно подготовленные совместимые workers. Ферму запускайте перед Neo.

Перед выдачей native clients/workers настройте настоящий Ethernet bind. Loopback-демо использует встроенный worker и внутренний URL фермы; внешним workers этот container-only адрес недоступен.

<a id="install-a-client"></a>
## Установить клиент

Используйте [релиз v2.4.2](https://github.com/C4T-BuT-S4D/neo/releases/tag/v2.4.2), совпадающий с поддерживаемой версией клиента/worker:

| Машина | Файл |
|---|---|
| Apple Silicon Mac | `neo_client_2.4.2_darwin_arm64.zip` |
| Intel Mac | `neo_client_2.4.2_darwin_amd64.zip` |
| Linux amd64 | `neo_client_2.4.2_linux_amd64.tar.gz` |
| Linux arm64 | `neo_client_2.4.2_linux_arm64.tar.gz` |

Скачайте/распакуйте до соревнования. В архиве есть `neo`, `client_config.yml` и каталог `exploits`. Команды ниже запускаются из распакованного каталога. Нативного клиента Windows в релизе нет; используйте разрешённое Linux-окружение/worker.

Отредактируйте `client_config.yml`:

```yaml
host: "<ADMIN_ETHERNET_IPV4>:5005"
grpc_auth_key: "<PRIVATE_NEO_KEY_FROM_ADMIN>"
exploit_dir: "exploits"
```

Замените placeholders; конфиг приватный. Если macOS запросит разрешение, используйте обычную процедуру допуска приложений. Не показывайте ключ в скриншотах и аргументах shell.

```bash
./neo --verbose=false --config client_config.yml --help
```

<a id="first-harmless-task"></a>
## Первое безвредное задание

Создайте в редакторе `exploits/ready.sh`:

```sh
#!/bin/sh
# flush=True: printf writes immediately; this task makes no target request.
printf 'worker ready for %s\n' "$1"
```

Разрешите исполнение и запустите локально:

```bash
chmod u+x exploits/ready.sh
./exploits/ready.sh 192.0.2.1
```

Зарегистрируйте **выключенным**, чтобы не запустить периодическую работу:

```bash
./neo --verbose=false --config client_config.yml add \
  --id ready --disabled --interval 1h --timeout 3s exploits/ready.sh
```

Попросите админа включить worker, затем единичный прогон:

```bash
./neo --verbose=false --config client_config.yml single ready
./neo --verbose=false --config client_config.yml tail --count 20 ready
```

`single` выполняется один раз на **всех настроенных командах**. Пример только печатает readiness и не обращается к ним. Это не флаг; accepted flags в ферме появляться не должны. Ищите ready-сообщение; периодическое исполнение остаётся выключенным.

<a id="real-scripts-and-recurring-execution"></a>
## Настоящие скрипты и периодическое исполнение

Скрипт получает IP цели первым аргументом. Нужны доступный interpreter/shebang и flush stdout; флаги нужного формата идут в ферму. Сначала локальный тест. Не загружайте недоверенные скрипты в workers.

Зарегистрируйте скрипт с явными ID, interval и timeout той же disabled-first командой `add`. После успешного разрешённого single-прогона включите или выключите этот ID:

```bash
./neo --verbose=false --config client_config.yml enable <TASK_ID>
./neo --verbose=false --config client_config.yml disable <TASK_ID>
```

При добавлении существующего ID Neo спрашивает перед заменой версии. До периодического исполнения проверьте реальные зависимости worker, scope и правила соревнования. CLI задают [upstream-команды](https://github.com/C4T-BuT-S4D/neo/tree/2f2a4eb63f9715155844284f253ba786d330c9ae/cmd/client).

Собственный совместимый native-worker:

```bash
./neo --verbose=false --config client_config.yml run --jobs 1
```

Команда работает на переднем плане; остановка Ctrl+C. Сначала подготовьте зависимости этого окружения. Поведение native Mac/runtime нужно прогнать на самой машине.

<a id="team-workflow-clients-coordinator-and-workers"></a>
## Командный workflow: клиенты, координатор и workers

Один бинарник `neo` выполняет две роли: команды `add`, `single`, `enable`, `disable`, `tail` — это управляющий клиент; `run` превращает процесс в исполняющий worker. Координатор хранит скрипты/настройки и распределяет цели между workers. Сам сервер скрипты не исполняет.

```text
Author A's client ──┐
Author B's client ──┼──> coordinator ──> connected worker(s) ──> script stdout
Admin's client ────┘                         │
                                            └──> S4DFarm queue ──> jury
```

Worker выделяет из stdout значения, подходящие под настроенный формат флага, и отправляет их прямо в ферму. Адрес/данные входа фермы и настройки команд он получает от координатора. Поэтому одного доступа к координатору недостаточно: исполняющий worker должен видеть ещё и ферму. Приём в ферму и отправка из неё жюрейке — отдельные действия; `QUEUED` не означает `ACCEPTED`.

1. **Админ:** из корня DurkaHelper запускает существующий стек через `python3 durka.py up`. Приватно выдаёт адрес/ключ координатора. Запускает один подготовленный worker: встроенный `python3 durka.py worker` либо native `./neo ... run` ниже. Для управления заданиями оба одновременно не нужны. Light Docker-worker не содержит произвольные зависимости скриптов.
2. **Каждый автор:** использует приватный клиентский конфиг с тем же координатором. Выбирает разные ID заданий, например `ready-author-a` и `ready-author-b`: ID общие, а не отдельные для каждого участника. Каждому worker задаёт отдельный `client_id`. Общий ключ даёт доступ доверенной команде, а не персональную read-only роль.
3. **Регистрация:** загружает скрипт выключенным. До единичного прогона ждёт загрузки скрипта worker и перезапуска его рабочих циклов. Зависимости и вспомогательные файлы нужны в окружении worker, а не только на ноутбуке автора.
4. **Наблюдение:** проверяет вывод задания, затем запись и статус в ферме. Закрытие управляющего клиента автора не останавливает включённое задание, пока координатор и worker работают. Выключать нужно конкретное задание явно.
5. **Отправка:** админ отдельно включает согласованный receiver фермы. Успех подтверждается ответом жюрейки; напечатанного значения или записи в очереди недостаточно.

<a id="one-shot-and-scheduled-harmless-example"></a>
### Безвредный пример: один раз и по расписанию

Используйте `ready.sh` из [первого безвредного задания](#first-harmless-task). Команды выполняются из распакованного каталога клиента Neo на машине админа **или** участника, с её приватным `client_config.yml`. Они меняют общие задания, поэтому используйте свой согласованный ID.

```bash
./neo --verbose=false --config client_config.yml add \
  --id ready-author-a --disabled --interval 1m --timeout 3s exploits/ready.sh
```

Админ запускает совместимый worker в **отдельном терминале**, из его распакованного каталога клиента:

```bash
./neo --verbose=false --config client_config.yml run --jobs 1 --endless-jobs 0
```

После сообщений о загрузке скрипта и готовности рабочих циклов автор или админ запускает один прогон:

```bash
./neo --verbose=false --config client_config.yml single ready-author-a
./neo --verbose=false --config client_config.yml tail --count 20 ready-author-a
```

Ожидается `worker ready for ...`; это не флаг. `single` охватывает настроенный список команд и не включает расписание. Для осознанной проверки периодического запуска:

```bash
./neo --verbose=false --config client_config.yml enable ready-author-a
# Observe subsequent runs; the configured interval is one minute.
./neo --verbose=false --config client_config.yml tail --count 20 ready-author-a
./neo --verbose=false --config client_config.yml disable ready-author-a
```

Cron не нужен. Интервал относится к зарегистрированному заданию, а не к терминалу автора. Native-worker останавливается через Ctrl+C; выключение задания прекращает будущие периодические прогоны, но уже начатая работа может завершиться. Чтобы выполнять на физической машине координатора, запустите там отдельный worker: один сервер исполнителем не является.

<a id="troubleshooting"></a>
## Диагностика

| Симптом | Что проверить |
|---|---|
| Не проходит вход | Точный LAN-адрес/порт координатора и общий ключ |
| Задание ждёт | Worker запущен и его job slots не исчерпаны |
| Только что добавленное задание не найдено | Дождитесь загрузки worker и перезапуска рабочих циклов, затем повторите единичный прогон |
| Ошибка скрипта/interpreter | Shebang, executable file и зависимости именно исполняющего worker |
| Результат есть, флагов нет | Формат флага и route/authentication worker→farm |
| Ферма rejected/expired | Receiver adapter, token, tick/lifetime и актуальный список команд |

Сырой `info` и debug могут содержать пароль фермы. Используйте `--verbose=false` и не показывайте диагностику в трансляции/публичных reports. Логи скриптов тоже могут содержать приватные данные.

[Инструкция участника](participant-guide-RU.md) · [Ферма](s4dfarm-RU.md) · [Установка админа](MACOS_FULL_DEPLOYMENT_AND_TESTING-RU.md)
