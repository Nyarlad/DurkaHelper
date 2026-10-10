<a id="s4dfarm-flags-and-submission"></a>
# S4DFarm: флаги и отправка

[English](s4dfarm.md) | Русский

S4DFarm собирает флаги команды, ставит их в очередь отправки и показывает accepted/rejected/expired. Neo автоматически передаёт найденные флаги. **Патчи сервисов ферма не распространяет.**

<a id="start-through-durkahelper"></a>
## Запуск через DurkaHelper

```bash
python3 durka.py up
python3 durka.py status
```

Откройте URL фермы; пароль — `credentials.farm_password` в приватном `local/durka.json`. Передайте участникам LAN URL/пароль, а не конфигурацию PostgreSQL/Redis.

<a id="configure-the-competition"></a>
## Настроить соревнование

В `local/durka.json` задайте реальные команды, regex флага, лимиты/время отправки и URL/token в `profile.farm.protocol_settings`. Kit поддерживает `ructf_http`; отсутствующий upstream default adapter не используется.

Отправка изначально выключена. После проверки соответствия receiver соревнованию:

```bash
python3 durka.py submit
```

Смотрите конечный статус легитимного флага. Работающий UI, очередь или успешный вход Neo ещё не доказывают принятие. Если очередь стоит: отправка включена, адаптер/token, expiry и ответы receiver.

<a id="change-configuration-or-recover"></a>
## Изменить конфиг или восстановить

Настройки площадки: остановить, отредактировать приватный конфиг, выполнить `python3 durka.py configure`, затем запустить. Не переотправляйте старые/просроченные очереди после recovery. [Native recovery](../deployment/README-RU.md#native-backup-and-quarantine-restore) восстанавливает в новое хранилище и намеренно очищает Redis кандидата.

Точные версии — в [toolchain lock](../config/toolchain.lock.json); подготовка DurkaHelper использует их автоматически. [Установка админа](MACOS_FULL_DEPLOYMENT_AND_TESTING-RU.md) · [Neo](neo-RU.md) · [Upstream](https://github.com/C4T-BuT-S4D/S4DFarm)
