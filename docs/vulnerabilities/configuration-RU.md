<a id="configuration-and-trust-boundaries-find-fix-and-verify"></a>

# Общие мисконфиги и границы доступа: поиск и исправление

[English](configuration.md) | Русский

[Вся база](README-RU.md) · [Сканер](../offline-scanner-RU.md) · [Проверка патча](../patch-validation-RU.md)

64 разделов. Формат: **Поиск → Уязвимый вариант → Исправление → Проверка**.
Команды `rg` выполняются в корне локальной копии сервиса и только читают файлы. Субъект/владелец определяется по проверенной сессии, а не данным запроса. Примеры нужно адаптировать к реальным API и контракту.

Автоматические находки — ограниченные синтаксические сигналы для проверки. AST-анализ не разрешает типы и не отслеживает данные между функциями; regex не заменяет парсер языка. Комментарии, строки и одноимённые пользовательские API могут давать совпадения. Проверьте фактическое исполнение, входные данные, авторизацию и границы доверия.

<a id="contents"></a>

## Содержание

- [CFG-SECRET — Литерал секрета/default key](#cfg-secret)
- [CFG-DEBUG — Debug в конфигурации](#cfg-debug)
- [CFG-CORS — Широкая CORS-политика](#cfg-cors)
- [CFG-DOCKER-PRIV — Привилегированный контейнер](#cfg-docker-priv)
- [CFG-DOCKER-SOCKET — Docker socket доступен сервису](#cfg-docker-socket)
- [CFG-DOCKER-ROOT — Явный USER root](#cfg-docker-root)
- [CFG-WORLD-WRITE — Широкие права записи](#cfg-world-write)
- [CFG-NGINX-LIST — Листинг каталога nginx](#cfg-nginx-list)
- [CFG-NGINX-ALIAS — Проверить границы nginx alias](#cfg-nginx-alias)
- [CFG-POSTGRES-TRUST — PostgreSQL trust](#cfg-postgres-trust)
- [CFG-REDIS-PROTECTION — Отключён protected-mode Redis](#cfg-redis-protection)
- [TPL-RAW — Неэкранированный вывод шаблона](#tpl-raw)
- [SRC-MIXED-IDENTIFIER — Смешение Latin/Cyrillic/Greek в одном слове](#src-mixed-identifier)
- [SRC-BIDI-CONTROL — Управление направлением текста в исходнике](#src-bidi-control)
- [CFG-REDIS-ACL — Redis ACL-пользователь без пароля](#cfg-redis-acl)
- [CFG-MONGO-NOAUTH — MongoDB authorization явно отключена](#cfg-mongo-noauth)
- [CFG-CAPABILITIES — Широкие capabilities контейнера](#cfg-capabilities)
- [CFG-BUILD-SECRET — Секрет в ARG/ENV Dockerfile](#cfg-build-secret)
- [CFG-NGINX-AUTH-OFF — Вложенный location отключает auth_request](#cfg-nginx-auth-off)
- [CFG-FILE-MODE — Права конфигов, каталога данных и ACL](#cfg-file-mode)
- [CFG-BIND-MOUNT — Writable mount раскрывает хост или соседние данные](#cfg-bind-mount)
- [CFG-K8S-RBAC — ServiceAccount и wildcard RBAC](#cfg-k8s-rbac)
- [CFG-NGINX-LOCATION — Нормализация URI и разные location](#cfg-nginx-location)
- [CFG-STATIC-SECRETS — Static root публикует .git, backup, БД и логи](#cfg-static-secrets)
- [CFG-COOKIE-FLAGS — Явно ослабленные флаги session cookies](#cfg-cookie-flags)
- [CFG-TRUSTED-HEADERS — Backend доверяет клиентскому user/role/IP](#cfg-trusted-headers)
- [CFG-CACHE-AUTH — Общий HTTP cache сохраняет персональный ответ](#cfg-cache-auth)
- [CFG-DEBUG-ENDPOINT — Диагностика доступна как публичный API](#cfg-debug-endpoint)
- [CFG-ERROR-SECRET — Логи содержат credentials/тела приватных запросов](#cfg-error-secret)
- [CFG-RESOURCE-LIMITS — Лимиты тела, decompression и multipart](#cfg-resource-limits)
- [CFG-UPLOAD-EXEC — Upload становится исполняемым или active content](#cfg-upload-exec)
- [CFG-HTTP-PARSER — Proxy и backend расходятся в framing](#cfg-http-parser)
- [CFG-CORS-CREDENTIALS — CORS отражает Origin вместе с credentials](#cfg-cors-credentials)
- [CFG-RESET-TOKEN — Recovery/share token без purpose и одноразовости](#cfg-reset-token)
- [CFG-OBJECT-POLICY — Прямой доступ к объекту через альтернативный endpoint](#cfg-object-policy)
- [CFG-DEPLOYED-CONFIG — Проверен пример, запущен другой конфиг](#cfg-deployed-config)
- [CFG-MEDIA-CONVERTER — Загрузка ресурсов из медиадокумента](#cfg-media-converter)
- [CFG-FORMAT-TRANSITION — Инъекция через промежуточный YAML](#cfg-format-transition)
- [CFG-PRINCIPAL-CONTEXT — Клиент изменяет контекст авторизации](#cfg-principal-context)
- [CFG-AUTH-TOCTOU — TOCTOU и повторное использование ID](#cfg-auth-toctou)
- [CFG-CUSTOM-CRYPTO — Алгебраическая утечка самодельной криптографии](#cfg-custom-crypto)
- [CFG-SHARED-BACKEND-KEY — Один служебный credential для всех дочерних окружений](#cfg-shared-backend-key)
- [CFG-WINDOWS-NAMES — Имя файла имеет иной смысл в Windows](#cfg-windows-names)
- [CFG-PROXY-REDIRECT — Reverse proxy следует redirect внутрь доверенного сервиса](#cfg-proxy-redirect)
- [CFG-PROTOCOL-KEY — Вырожденное значение в криптопротоколе](#cfg-protocol-key)
- [CFG-AGGREGATE-KEY — Некорректная агрегация публичных ключей](#cfg-aggregate-key)
- [CFG-K8S-HOST — Контейнер разделяет host namespace](#cfg-k8s-host)
- [CFG-UNCONFINED — Отключён профиль seccomp/AppArmor](#cfg-unconfined)
- [CFG-PRIV-ESCALATION — Разрешено повышение привилегий процесса](#cfg-priv-escalation)
- [CFG-ACTUATOR — Spring Actuator публикует все endpoints](#cfg-actuator)
- [CFG-H2-CONSOLE — Веб-консоль H2 включена](#cfg-h2-console)
- [CFG-TLS-UPSTREAM — Proxy не проверяет TLS upstream](#cfg-tls-upstream)
- [CFG-SSH-EMPTY-PASSWORD — SSHD допускает пустой пароль](#cfg-ssh-empty-password)
- [CFG-SUDO-ALL — Неограниченный sudo без пароля](#cfg-sudo-all)
- [CFG-JWT-KEY-SELECTION — Недоверенный kid/jku выбирает ключ проверки](#cfg-jwt-key-selection)
- [CFG-SIGNED-REQUEST — Подпись не связана с действием или допускает повтор](#cfg-signed-request)
- [CFG-RATE-LIMIT-IDENTITY — Ключ rate limit выбирает отправитель](#cfg-rate-limit-identity)
- [CFG-TOKEN-REVOCATION — Смена пароля или роли не отзывает полномочия](#cfg-token-revocation)
- [CFG-FAIL-OPEN — Ошибка проверки превращается в разрешение](#cfg-fail-open)
- [CFG-LDAP-FILTER — Строковая сборка LDAP filter или DN](#cfg-ldap-filter)
- [CFG-CI-TRUST — Недоверенные данные и код пересекают границу CI](#cfg-ci-trust)
- [CFG-DOCKER-TCP — Docker daemon слушает на всех TCP-интерфейсах](#cfg-docker-tcp)
- [CFG-FLOATING-IMAGE — Явный тег образа latest](#cfg-floating-image)
- [TPL-AUTOESCAPE-OFF — Блок шаблона отключает автоматическое экранирование](#tpl-autoescape-off)

<a id="cfg-secret"></a>

<a id="cfg-secret-literal-secret-or-default-key"></a>

## CFG-SECRET. Литерал секрета/default key

**Поиск:** скрипт, правило CFG-SECRET. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-SECRET. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~text
JWT_SECRET = "development"
~~~

**Исправление:** Проверить, используется ли fallback; секрет из защищённого конфига. Ротация только с планом для текущих сессий/данных.

~~~text
JWT_SECRET = load_existing_secret()
~~~

**Проверка:** Нет общего fallback; законные данные/сессии сохранены.

**Вариант A/D:** Общий секрет подписи. **Основание:** lost_museum, авторский разбор RuCTF: фиксированный общий JWT key.
**Искать:** литералы ключей, defaults, одинаковые ключи разных ролей/команд.
Сканер: CFG-SECRET, частичное покрытие имён.

**Патч:** собственный секрет через конфиг и явная политика ротации.
Нельзя просто сменить ключ и потерять все легитимные сессии. При временном
чтении старого ключа учитывать, что его компрометация остаётся действующей:
потребуется безопасная серверная миграция/перепроверка, а не бесконечный fallback.
**Тест:** новая и старая сессия по плану перехода, неверная подпись, срок,
назначение; не выводить ключ в логи.

[исходник/разбор 1](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/lost_museum/README.md).

**Вариант A/D:** Default key и смешение назначений токенов. **Основание:** explorers CTF Cup, наблюдения по config/auth/API.
В настройках есть буквальный jwt_key по умолчанию; env мог его заменить.
Один JWT-помощник используется для разных схем claims. Это повод проверить
границы, не воспроизведённый обход авторизации.

**Патч:** обязательный конфиг ключа; проверять typ/purpose/audience и обязательные
поля на каждом принимающем маршруте. Нельзя трактовать отсутствие user_id как
валидного субъекта. **Тест:** токен общего доступа не становится auth-токеном
и наоборот; неверный/пустой subject отклоняется; штатный share работает.
Сканер: CFG-SECRET для литерала, назначение токена — ручной анализ.

[исходник/разбор 1](https://github.com/C4T-BuT-S4D/ctfcup-2023-ad/blob/53d6b9b7369448ac6c5d7d8e9458f66b25271e8a/services/explorers/src/app/config.py); [исходник/разбор 2](https://github.com/C4T-BuT-S4D/ctfcup-2023-ad/blob/53d6b9b7369448ac6c5d7d8e9458f66b25271e8a/services/explorers/src/app/auth.py).

<a id="cfg-debug"></a>

<a id="cfg-debug-debug-enabled-in-configuration"></a>

## CFG-DEBUG. Debug в конфигурации

**Поиск:** скрипт, правило CFG-DEBUG. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-DEBUG. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~text
DEBUG=true
~~~

**Исправление:** Отключить debug в игровом профиле; серверные логи без секретов.

~~~text
DEBUG=false
~~~

**Проверка:** Ошибки не раскрывают консоль/stack trace.

<a id="cfg-cors"></a>

<a id="cfg-cors-broad-cors-policy"></a>

## CFG-CORS. Широкая CORS-политика

**Поиск:** правило сканера CFG-CORS. Подробности: `--explain CFG-CORS`. Старый поиск wildcard в headers/config без определения типа. JS-токены дополнительно распознают default import/require cors с inline origin:true и credentials:true, строковыми ключами и учётом последних присваиваний. Наблюдаемые shadows/reassignments отключают новую подсказку. Вычисляемые ключи, переменные, wrappers, фактическая политика ответа и другие языки требуют ручной проверки.

**Уязвимый вариант:**

~~~text
Access-Control-Allow-Origin: *
~~~

**Исправление:** Явные разрешённые origins и Vary: Origin, если нужен cross-origin; auth/CSRF отдельно. Звёздочка сама по себе не обходит auth.

~~~text
Access-Control-Allow-Origin: https://ui.example.invalid
~~~

**Проверка:** Разрешённый браузерный клиент работает; чужой origin не читает приватный ответ.

<a id="cfg-docker-priv"></a>

<a id="cfg-docker-priv-privileged-container"></a>

## CFG-DOCKER-PRIV. Привилегированный контейнер

**Поиск:** скрипт, правило CFG-DOCKER-PRIV. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-DOCKER-PRIV. Regex: privileged:true и cap_add с SYS_ADMIN/ALL, включая quoted JSON keys. Block capabilities покрывает CFG-CAPABILITIES; эффективный Docker/Kubernetes config проверить вручную.

**Уязвимый вариант:**

~~~text
privileged: true
~~~

**Исправление:** Определить необходимые capabilities; ограничивать только разрешённый собственный сервис, не инфраструктуру организаторов.

~~~text
privileged: false
~~~

**Проверка:** Сервис/checker работает без лишних полномочий.

<a id="cfg-docker-socket"></a>

<a id="cfg-docker-socket-docker-socket-exposed-to-a-service"></a>

## CFG-DOCKER-SOCKET. Docker socket доступен сервису

**Поиск:** скрипт, правило CFG-DOCKER-SOCKET. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-DOCKER-SOCKET. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~text
- /var/run/docker.sock:/var/run/docker.sock
~~~

**Исправление:** Убрать ненужный mount после проверки зависимости и правил; не менять служебные контейнеры автоматически.

~~~text
- app-data:/srv/data
~~~

**Проверка:** Штатная функция и разрешённые инструменты работают.

<a id="cfg-docker-root"></a>

<a id="cfg-docker-root-explicit-docker-user-root"></a>

## CFG-DOCKER-ROOT. Явный USER root

**Поиск:** скрипт, правило CFG-DOCKER-ROOT. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-DOCKER-ROOT. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~text
USER root
~~~

**Исправление:** Подготовленный непривилегированный пользователь и права на необходимые каталоги; отсутствие USER правило не проверяет.

~~~text
USER app
~~~

**Проверка:** Тома, порты, запись данных и restart работают.

<a id="cfg-world-write"></a>

<a id="cfg-world-write-broad-write-permissions"></a>

## CFG-WORLD-WRITE. Широкие права записи

**Поиск:** скрипт, правило CFG-WORLD-WRITE. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-WORLD-WRITE. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~text
chmod -R 777 /srv/app
~~~

**Исправление:** Определить владельца/группу и минимальные права; без рекурсивной замены вслепую.

~~~text
chmod 750 /srv/app
~~~

**Проверка:** Процесс пишет нужные данные; посторонние не меняют код.

<a id="cfg-nginx-list"></a>

<a id="cfg-nginx-list-nginx-directory-listing"></a>

## CFG-NGINX-LIST. Листинг каталога nginx

**Поиск:** скрипт, правило CFG-NGINX-LIST. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-NGINX-LIST. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~text
autoindex on;
~~~

**Исправление:** Отключить ненужный листинг, если он не является частью функциональности.

~~~text
autoindex off;
~~~

**Проверка:** Загрузка файла работает; служебный каталог не раскрывается.

<a id="cfg-nginx-alias"></a>

<a id="cfg-nginx-alias-review-nginx-alias-boundaries"></a>

## CFG-NGINX-ALIAS. Проверить границы nginx alias

**Поиск:** скрипт, правило CFG-NGINX-ALIAS. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-NGINX-ALIAS. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~text
location /files { alias /srv/files/; }
~~~

**Исправление:** Согласовать location /files/ и alias /srv/files/; проверить нормализацию/auth. Корректный alias также даёт сигнал.

~~~text
location /files/ { root /srv; } # verify mapping and auth
~~~

**Проверка:** Граничные URL не выходят из корня; старые URL работают.

<a id="cfg-postgres-trust"></a>

<a id="cfg-postgres-trust-postgresql-trust"></a>

## CFG-POSTGRES-TRUST. PostgreSQL trust

**Поиск:** скрипт, правило CFG-POSTGRES-TRUST. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-POSTGRES-TRUST. Regex: POSTGRES_HOST_AUTH_METHOD=trust, включая JSON; pg_hba local/host/hostssl/hostnossl/hostgssenc/hostnogssenc с trust, CIDR или отдельной IPv4-маской. Проверить порядок HBA и какие записи реально применяются.

**Уязвимый вариант:**

~~~text
POSTGRES_HOST_AUTH_METHOD: trust
~~~

**Исправление:** Поддержанный метод auth и согласованные credentials своего приложения; не менять сеть/аккаунты организаторов.

~~~text
POSTGRES_HOST_AUTH_METHOD: scram-sha-256
~~~

**Проверка:** Сервис подключается; неизвестные credentials не принимаются.

<a id="cfg-redis-protection"></a>

<a id="cfg-redis-protection-redis-protected-mode-disabled"></a>

## CFG-REDIS-PROTECTION. Отключён protected-mode Redis

**Поиск:** скрипт, правило CFG-REDIS-PROTECTION. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-REDIS-PROTECTION. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~text
protected-mode no
~~~

**Исправление:** Проверить ACL/credentials/bind и необходимый доступ; инфраструктурные изменения сверить с правилами, не блокировать игровой трафик.

~~~text
protected-mode yes
~~~

**Проверка:** Приложение подключается с нужными правами.

<a id="tpl-raw"></a>

<a id="tpl-raw-unescaped-template-output"></a>

## TPL-RAW. Неэкранированный вывод шаблона

**Поиск:** скрипт, правило TPL-RAW. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain TPL-RAW. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~text
{{ message | safe }}
~~~

**Исправление:** Штатный экранированный вывод текста; для богатого HTML sanitizer и тест контекста.

~~~text
{{ message }}
~~~

**Проверка:** Разметка пользователя — текст; штатная верстка сохранена.

<a id="src-mixed-identifier"></a>

<a id="src-mixed-identifier-mixed-latincyrillicgreek-identifier"></a>

## SRC-MIXED-IDENTIFIER. Смешение Latin/Cyrillic/Greek в одном слове

**Поиск:** скрипт, правило SRC-MIXED-IDENTIFIER. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain SRC-MIXED-IDENTIFIER. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~text
uuіd = input_value
~~~

**Исправление:** Проверить code points и все ссылки на переменную; дать различимые имена и использовать проверенное значение. Не переименовывать слепой заменой по файлу.

~~~text
validated_uuid = parse_uuid(input_value)
~~~

**Проверка:** Ветвь валидации и потребитель используют одно значение; тест с недопустимым вводом. Совпадения в строках/комментариях могут быть безвредны.

**Вариант A/D:** Unicode-двойник и использование непроверенного ID. **ENOWARS / replme, автор + патч.** Похожая буква в имени переменной оставляла
оригинальный UUID необработанным; файловая операция использовала его вместо
объекта, уже проверенного middleware.

**Патч:** использовать ID из авторизованного объекта, однозначные имена переменных,
проверку имени файла/корня. **Тест:** другой query-ID не меняет разрешённый объект;
некорректный UUID отвергается. **Поиск:** SRC-MIXED-IDENTIFIER;
SRC-BIDI-CONTROL — дополнительная общая проверка, не факт об этом сервисе.

[исходник/разбор 1](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/main.tex); [исходник/разбор 2](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/path-traversal.patch); [исходник/разбор 3](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/crc.patch); [исходник/разбор 4](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/backend/util/encoding.go); [исходник/разбор 5](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/backend/controller/repl.go); [исходник/разбор 6](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/image/service/user.go).

<a id="src-bidi-control"></a>

<a id="src-bidi-control-bidirectional-text-control-in-source"></a>

## SRC-BIDI-CONTROL. Управление направлением текста в исходнике

**Поиск:** скрипт, правило SRC-BIDI-CONTROL. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain SRC-BIDI-CONTROL. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~text
# direction ‮ marker
~~~

**Исправление:** Показать Unicode code points и реальный порядок токенов, убрать ненужные управляющие символы. Легитимный текст локализации проверить отдельно.

~~~text
# explicit plain-text comment
~~~

**Проверка:** Реальный поток управления совпадает с отображением; символ не восстановился при копировании.

<a id="cfg-redis-acl"></a>

<a id="cfg-redis-acl-redis-acl-user-without-a-password"></a>

## CFG-REDIS-ACL. Redis ACL-пользователь без пароля

**Поиск:** скрипт, правило CFG-REDIS-ACL. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-REDIS-ACL. Regex выбирает строку user, затем ограниченный разбор полной физической строки до 8192 символов: lowercase user, один ASCII space перед непустым username, обычные spaces между модификаторами. on/off/reset и nopass/resetpass/>password/#64lowerhex учитываются по порядку; сигнал только когда обе итоговые flags явно true. Имена, пароли и key/channel patterns не считаются flags. Кавычки, escapes, внутренние tabs, selectors и неизвестные операции остаются ручными; длинная строка даёт partial. Это не эффективный ACL: строки/include/runtime, валидность grants, сила пароля и существующие соединения проверяются вручную.

**Уязвимый вариант:**

~~~text
user default on nopass ~* &* +@all
~~~

**Исправление:** Сначала подготовить именованного пользователя приложения с
отдельным сгенерированным credential и минимальными командами/ключами/каналами.
Передать credential клиентам защищённым способом, переключить их на явную
аутентификацию и проверить переподключение всех пулов. Только после этого
отключать ненужный `default`. Для сервиса, который должен сохранить `default`,
согласованно настроить его пароль и обновить клиентов вместо отключения.
Финальная строка после перехода клиентов на подготовленного пользователя `app`:

~~~text
user default off
~~~

Само `off` запрещает новую аутентификацию, но уже аутентифицированные соединения
не обрывает. Их судьбу предусмотреть в переходе, сохранив административный доступ
и возможность отката. У `default on nopass` новое соединение уже аутентифицировано;
для именованного пользователя `nopass` допускает любой пароль при AUTH.
[Redis: ACL и поведение on/off](https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/).

**Проверка:** Штатный клиент успешно проходит AUTH и переподключается; аноним
и соседний namespace не получают защищённые данные. Проверить команды,
транзакции, Pub/Sub и фоновые процессы, затем старые соединения и перезапуск.
Отсутствие CFG-REDIS-ACL означает только отсутствие распознанного сочетания
`on` + `nopass`, а не надёжный пароль или корректные полномочия.

ACL-директивы применяются последовательно. `off` после `on`, `resetpass`
после `nopass` или `reset` меняют итог; `nopass` после добавления пароля вновь
разрешает вход без проверки пароля. `>password` и корректный `#` с 64 строчными
hex-символами снимают `nopass`. Даже токен `>` с пустым паролем его снимает:
исчезновение сигнала не является исправлением аутентификации.
`~nopass` — шаблон ключа, а не парольная директива.
[Реализация ACL Redis 7.2.7](https://github.com/redis/redis/blob/7.2.7/src/acl.c).

Сканер разбирает ограниченное общее подмножество строк `redis.conf` и aclfile.
Полные токены и их порядок учитываются внутри одной строки; состояние между
строками и фактическая успешность загрузки не устанавливаются. Кавычки,
экранирование, внутренние TAB и selectors требуют ручного просмотра:
токенизация основного конфига и aclfile различается. Не дописывать inline
комментарий к ACL-строке: `#` может начинать токен хеша, а не комментарий.
Также проверить include,
`requirepass`, повторные определения и runtime `ACL SETUSER`/`ACL LOAD`.
[Парсер конфигурации Redis 7.2.7](https://github.com/redis/redis/blob/7.2.7/src/config.c).

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -o -e '(^[[:blank:]]*(user|aclfile|include|requirepass)[[:blank:]])|ACL[[:blank:]]+(SETUSER|LOAD|SAVE|GETUSER|LIST)' .
~~~

Команда выводит только имена директив и позиции, без аргументов с credentials.
Локально проследить загружаемые файлы и все изменения нужного пользователя.
В разрешённом окружении администратору сверить эффективные flags/команды/ключи/
каналы через `ACL GETUSER app` и отдельную проверку нового подключения с верным
и неверным паролем. Ответ GETUSER содержит также хеши: не переносить их и поля
паролей в отчёт, логи и shell history. Наличие `requirepass` в одном файле
не доказывает, что оно действует в запущенном процессе.
[Redis: ACL GETUSER](https://redis.io/docs/latest/commands/acl-getuser/).

<a id="cfg-mongo-noauth"></a>

<a id="cfg-mongo-noauth-mongodb-authorization-disabled"></a>

## CFG-MONGO-NOAUTH. MongoDB authorization явно отключена

**Поиск:** скрипт, правило CFG-MONGO-NOAUTH. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-MONGO-NOAUTH. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~text
security:
  authorization: disabled
~~~

**Исправление:** Для своего сервиса подготовить роли/учётные данные до включения auth; приложению только нужная БД и действия.

~~~text
security:
  authorization: enabled
~~~

**Проверка:** Перезапуск, переподключение, обычные CRUD; анониму отказ. Не менять аккаунты организаторов.

**Основание:** [первичный материал](https://www.mongodb.com/docs/manual/core/authorization/).

<a id="cfg-capabilities"></a>

<a id="cfg-capabilities-broad-container-capabilities"></a>

## CFG-CAPABILITIES. Широкие capabilities контейнера

**Поиск:** скрипт, правило CFG-CAPABILITIES. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-CAPABILITIES. Regex: cap_add или capabilities.add с SYS_ADMIN/ALL, flow/block list. capabilities.drop:[ALL] сам по себе не является выдачей прав. Это ограниченное текстовое окно, не YAML parser; вложенность, merge/anchor и применённый securityContext вручную.

**Уязвимый вариант:**

~~~text
cap_add: [SYS_ADMIN]
~~~

**Исправление:** У своего сервиса удалить лишние capabilities, вернуть только доказанно необходимые. Проверить uid, порты и права томов до выкладки.

~~~text
cap_drop: [ALL]
~~~

**Проверка:** Запуск и checker после изменения; required syscall не сломан. Не применять к launcher/инфраструктуре организаторов.

**Основание:** [первичный материал](https://docs.docker.com/engine/security/).

<a id="cfg-build-secret"></a>

<a id="cfg-build-secret-secret-in-dockerfile-argenv"></a>

## CFG-BUILD-SECRET. Секрет в ARG/ENV Dockerfile

**Поиск:** скрипт, правило CFG-BUILD-SECRET. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-BUILD-SECRET. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~text
ARG API_TOKEN=example
~~~

**Исправление:** Build secret mount вместо ARG/ENV/слоя; уже опубликованный секрет заменить согласованно, удаление следующей инструкцией не очищает прошлый слой.

~~~text
RUN --mount=type=secret,id=api_token build-with-secret
~~~

**Проверка:** Сборка без утечки в history/logs; runtime получает свой секрет отдельно. Команда в примере — placeholder.

**Основание:** [первичный материал](https://docs.docker.com/build/building/secrets/).

<a id="cfg-nginx-auth-off"></a>

<a id="cfg-nginx-auth-off-nested-nginx-location-disables-auth_request"></a>

## CFG-NGINX-AUTH-OFF. Вложенный location отключает auth_request

**Поиск:** скрипт, правило CFG-NGINX-AUTH-OFF. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-NGINX-AUTH-OFF. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~text
location /export/ { auth_request off; }
~~~

**Исправление:** Проверить effective location и одинаковую политику для download/export/internal redirect. Публичные пути оставлять по контракту.

~~~text
location /export/ { auth_request /verify; }
~~~

**Проверка:** Авторизованный экспорт работает, анонимный/чужой — нет. Не менять сетевую схему.

**Основание:** [первичный материал](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html).

<a id="cfg-file-mode"></a>

<a id="cfg-file-mode-configuration-data-directory-and-acl-permissions"></a>

## CFG-FILE-MODE. Права конфигов, каталога данных и ACL

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'chmod|chown|umask|setfacl|mode:|permissions' .
~~~

В локальном/разрешённом окружении проверить ls -ld для файла и всех родителей; на Linux также getfacl. Сопоставить uid/gid процесса.

**Уязвимый вариант:**

Секрет читается соседним пользователем или parent dir позволяет заменить защищённый файл.

**Исправление:** Минимальные права файла и родителей, отдельный writable data dir, private temp; не делать chmod -R 777 и не ломать uid тома.

**Проверка:** Приложение читает нужное/пишет данные после restart; посторонний local user доступа не получает.

<a id="cfg-bind-mount"></a>

<a id="cfg-bind-mount-writable-mounts-expose-hosts-or-neighboring-data"></a>

## CFG-BIND-MOUNT. Writable mount раскрывает хост или соседние данные

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'volumes:|bind|source:|target:|read_only|hostPath' .
~~~

Сопоставить Compose/K8s mount со своим runtime inventory: host source, container target, ro/rw и propagation.

**Уязвимый вариант:**

Приложение может менять код, конфиги или каталог хоста через ненужный writable mount.

**Исправление:** Только необходимые пути, read-only где запись не нужна, отдельный data volume; сохранить runtime permissions.

**Проверка:** Старт/запись/checker и restart работают; код/чужой каталог не меняется.

**Основание:** [первичный материал](https://docs.docker.com/engine/storage/bind-mounts/).

<a id="cfg-k8s-rbac"></a>

<a id="cfg-k8s-rbac-workload-bound-to-cluster-admin"></a>

## CFG-K8S-RBAC. ServiceAccount и wildcard RBAC

**Поиск:** скрипт, правило CFG-K8S-RBAC. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-K8S-RBAC. Regex: name:cluster-admin. Не связывает roleRef с subjects и не ищет эквивалентную wildcard роль; остальные RBAC случаи искать вручную.

Дополнительный ручной поиск для непокрытых форм:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'automountServiceAccountToken|serviceAccountName|ClusterRole|verbs:|resources:' .
~~~

Найти pod → serviceAccount → RoleBinding/ClusterRoleBinding; проверить доступ к secrets, exec и bind/escalate.

**Уязвимый вариант:**

Бизнес-pod получает административный token, хотя Kubernetes API не нужен.

**Исправление:** Для своей управляемой установки — Role с минимальными правами и RoleBinding в нужном namespace. Проверить subjects, verbs, resources, names и полномочия impersonate/bind/escalate. Выключить ненужный automount; ограничения admission отдельно.

**Проверка:** Runtime-пользователь выполняет только нужные операции, не читает чужие Secrets и не выдаёт права; приложение запускается. Не менять cluster организаторов.

**Основание:** [первичный материал](https://kubernetes.io/docs/concepts/security/rbac-good-practices/).


**Сигнал сканера — пример до:**

~~~config
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
~~~

**Шаблон исправления:**

~~~config
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: notes-read-config
~~~

Первичная документация: [документация 1](https://kubernetes.io/docs/reference/access-authn-authz/rbac/).

<a id="cfg-nginx-location"></a>

<a id="cfg-nginx-location-uri-normalization-and-location-selection"></a>

## CFG-NGINX-LOCATION. Нормализация URI и разные location

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'location|alias|root|try_files|rewrite|proxy_pass' .
~~~

Для своего конфига пройти выбор exact/prefix/regex location и internal redirect; сравнить URI, увиденный backend.

**Уязвимый вариант:**

Auth проверяет один путь, proxy/filesystem получает иной после нормализации или fallback.

**Исправление:** Однозначные маршруты/границы root и auth на реальном ресурсе; согласованные правила decoding между слоями.

**Проверка:** Slash/encoding/normal path, regex location и fallback не меняют права.

**Основание:** [первичный материал](https://nginx.org/en/docs/http/ngx_http_core_module.html).

<a id="cfg-static-secrets"></a>

<a id="cfg-static-secrets-static-roots-expose-git-backups-databases-and-logs"></a>

## CFG-STATIC-SECRETS. Static root публикует .git, backup, БД и логи

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'static|document_root|root |alias |send_from_directory|FileServer' .
~~~

Сверить содержимое именно public root, symlinks и fallback; поиск файлов: rg --files --hidden -g !.git.

**Уязвимый вариант:**

Из корня проекта раздаются config, backup.sql, SQLite/WAL, архивы или credentials.

**Исправление:** Отдельный public build directory, приватное хранение вне него и authenticated download; не надеяться только на запрет одного расширения.

**Проверка:** Assets работают, скрытые файлы/backup/ссылка наружу не выдаются.

**Основание:** [первичный материал](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).

<a id="cfg-cookie-flags"></a>

<a id="cfg-cookie-flags-explicitly-weakened-django-cookie-flags"></a>

<a id="cfg-cookie-flags-explicitly-weakened-session-cookie-flags"></a>

## CFG-COOKIE-FLAGS. Явно ослабленные флаги session cookies

**Поиск:** правило сканера CFG-COOKIE-FLAGS. Подробности: `--explain CFG-COOKIE-FLAGS`. Regex исключает комментарии/строки: обычные Django SESSION_COOKIE_HTTPONLY/SESSION_COOKIE_SECURE/CSRF_COOKIE_SECURE=false/0. Python AST: известный Flask config[index]/update/from_mapping с отключёнными session HttpOnly/Secure. JS-токены: default import express-session с inline cookie.httpOnly:false. Динамическая конфигурация и defaults проверяются вручную. JS secure:false сам по себе не новый сигнал; учитывайте HTTPS и HTTP-checker.

Дополнительный ручной поиск форм, которые не покрывает автоматическое правило:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Set-Cookie|HttpOnly|SameSite|Secure|cookie.domain|cookie.path' .
~~~

Сопоставьте фактический Set-Cookie с топологией HTTP/TLS/proxy; Domain/Path не заменяют авторизацию.

**Уязвимый вариант:**

Приватные cookies передаются ненужным hosts/путям, без необходимости доступны JavaScript или исчезают из-за неверной настройки Secure.

**Исправление:** Сохраняйте HttpOnly для сессионных cookies и используйте Secure, если согласованный транспорт сервиса поддерживает HTTPS; включение Secure при checker, работающем только по HTTP, требует согласованного изменения транспорта.

**Проверка:** Скрипты не читают сессионные cookies; сессии работают по предусмотренному транспорту, а secure cookies не отправляются по незашифрованному соединению.


**Пример для сканера до исправления:**

~~~config
SESSION_COOKIE_HTTPONLY = False
~~~

**Шаблон исправления:**

~~~config
SESSION_COOKIE_HTTPONLY = True
~~~

<a id="cfg-trusted-headers"></a>

<a id="cfg-trusted-headers-backends-trust-client-supplied-user-role-or-ip"></a>

## CFG-TRUSTED-HEADERS. Backend доверяет клиентскому user/role/IP

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'X-User|X-Role|X-Forwarded|Forwarded|Remote-User|X-Original' .
~~~

Проследить кто устанавливает/очищает заголовок и доступен ли backend в обход доверенного proxy.

**Уязвимый вариант:**

Приложение считает присланный X-User подтверждённой identity.

**Исправление:** Прикладная проверка credential/trusted peer и очистка forwarded identity по реальной архитектуре; один секретный header не универсальный auth.

**Проверка:** Прямой запрос и поддельный header не дают права; штатный proxy проходит.

<a id="cfg-cache-auth"></a>

<a id="cfg-cache-auth-shared-http-caches-retain-personalized-responses"></a>

## CFG-CACHE-AUTH. Общий HTTP cache сохраняет персональный ответ

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'proxy_cache|Cache-Control|Vary|Authorization|Set-Cookie|cache_key' .
~~~

Сверить cache key, условия bypass и ответы с cookie/auth; сравнить два пользователя на одном URL.

**Уязвимый вариант:**

Приватный body кешируется только по URI и выдаётся другой сессии.

**Исправление:** Не кешировать персональные ответы общим ключом; private/no-store по контракту либо полная изоляция контекста и корректная инвалидация.

**Проверка:** A затем B на том же URL, logout/смена роли, штатный публичный cache.

<a id="cfg-debug-endpoint"></a>

<a id="cfg-debug-endpoint-diagnostics-become-public-apis"></a>

## CFG-DEBUG-ENDPOINT. Диагностика доступна как публичный API

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'actuator|swagger|debug|pprof|metrics|heapdump|console|env' .
~~~

Перечислить реально зарегистрированные endpoint и доступ к каждому; имя /health само по себе нормально.

**Уязвимый вариант:**

Env/heapdump/config console раскрывает секреты или позволяет изменить приложение.

**Исправление:** Отключить ненужную диагностику своего сервиса либо прикладная авторизация; оставить требуемый health и monitoring организаторов.

**Проверка:** Health/checker остаются, анонимный env/dump/control недоступен.

<a id="cfg-error-secret"></a>

<a id="cfg-error-secret-logs-expose-credentials-or-private-request-bodies"></a>

## CFG-ERROR-SECRET. Логи содержат credentials/тела приватных запросов

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'logger|logging|console.log|print|Authorization|password|token' .
~~~

Найти логирование whole request/config/exception, debug trace и куда попадает журнал.

**Уязвимый вариант:**

Пароль, подпись или приватный body пишутся без необходимости и доступны через log endpoint/volume.

**Исправление:** Структурные поля без секретов, redaction до сериализации, минимальный доступ/retention; сохранить полезные коды ошибок.

**Проверка:** Ошибочные запросы диагностируются без секретных значений и stacktrace в API.

<a id="cfg-resource-limits"></a>

<a id="cfg-resource-limits-body-decompression-and-multipart-limits"></a>

## CFG-RESOURCE-LIMITS. Лимиты тела, decompression и multipart

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'bodyLimit|maxRequest|client_max_body_size|multipart|decompress|timeout' .
~~~

Сверить limit до чтения, после распаковки и на каждую часть/всё сообщение; приложение и proxy могут отличаться.

**Уязвимый вариант:**

Небольшой compressed input создаёт большое тело; число частей/заголовков не ограничено.

**Исправление:** Бюджеты по контракту для фактических байтов, parts, времени и результата; cleanup при отказе.

**Проверка:** Лимит±1, без Content-Length, compressed body, много частей и легитимный максимум.

<a id="cfg-upload-exec"></a>

<a id="cfg-upload-exec-uploads-become-executable-or-active-content"></a>

## CFG-UPLOAD-EXEC. Upload становится исполняемым или active content

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'upload|media|public|cgi|fastcgi|Content-Type|Content-Disposition' .
~~~

Сопоставить место записи, правила web server и mime браузера; имя/Content-Type клиента не доказательство типа.

**Уязвимый вариант:**

Загруженный документ исполняется сервером или открывается active HTML в origin приложения.

**Исправление:** Приватное неисполняемое хранение, server filename, проверка типа и policy выдачи; для скачивания безопасные headers.

**Проверка:** Upload/download и previews работают; файл не становится серверным кодом/чужим origin-сценарием.

**Основание:** [первичный материал](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).

<a id="cfg-http-parser"></a>

<a id="cfg-http-parser-proxy-and-backend-disagree-on-framing"></a>

## CFG-HTTP-PARSER. Proxy и backend расходятся в framing

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Content-Length|Transfer-Encoding|http_parser|proxy_http_version|keepalive' .
~~~

Проверить версии HTTP parsers и политику противоречивых длины/кодирования; тестировать только изолированный стенд.

**Уязвимый вариант:**

Слои по-разному определяют конец запроса, следующий запрос попадает в иной контекст.

**Исправление:** Совместимые исправленные parsers, единая строгая политика framing и отказ неоднозначным сообщениям; не пытаться чинить regex по payload.

**Проверка:** Обычные keepalive/chunked, противоречивый framing и закрытие соединения без смешения ответов.

<a id="cfg-cors-credentials"></a>

<a id="cfg-cors-credentials-cors-reflects-origin-with-credentials"></a>

## CFG-CORS-CREDENTIALS. CORS отражает Origin вместе с credentials

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Access-Control-Allow-Origin|allow_credentials|origin:|credentials:|CORS' .
~~~

Сверить response к разрешённому и постороннему Origin; wildcard с credentials обычно блокируется браузером, reflection опаснее.

**Уязвимый вариант:**

Любой origin получает своё имя обратно и разрешение credentialed чтения приватного API.

**Исправление:** Точная серверная allowlist origin, корректный Vary и credential policy; CORS не авторизует запросы вне браузера.

**Проверка:** Штатный frontend работает; чужой/null origin не получает credentialed чтение.

<a id="cfg-reset-token"></a>

<a id="cfg-reset-token-recovery-or-share-tokens-lack-purpose-or-one-time-use"></a>

## CFG-RESET-TOKEN. Recovery/share token без purpose и одноразовости

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'reset|recover|invite|share|token|expires|used_at' .
~~~

Проследить выдачу/проверку токена и атомарность consume; сравнить login/share/reset audiences.

**Уязвимый вариант:**

Токен другого действия или уже использованный token повторно меняет доступ.

**Исправление:** CSPRNG/подпись с purpose/resource/subject/expiry, одноразовый consume в транзакции где это требуется; сохранение legit share.

**Проверка:** Повторное/параллельное использование, чужой объект/назначение, срок и штатная операция.

<a id="cfg-object-policy"></a>

<a id="cfg-object-policy-alternative-endpoints-expose-an-object-directly"></a>

## CFG-OBJECT-POLICY. Прямой доступ к объекту через альтернативный endpoint

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'owner|tenant|download|export|delete|share|attachment|job' .
~~~

Для одной сущности пройти все операции и вложенные пути, включая background jobs; ID непредсказуемый не значит разрешённый.

**Уязвимый вариант:**

UI/read защищены, export/download/delete обращаются по ID без проверки owner.

**Исправление:** Единая resource policy на каждой операции, субъект из verified session; sharing сохранить явным правилом.

**Проверка:** Два пользователя/tenant: своё можно, чужое нельзя по каждому endpoint.

**Основание:** [первичный материал](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).

<a id="cfg-deployed-config"></a>

<a id="cfg-deployed-config-reviewing-an-example-instead-of-effective-configuration"></a>

## CFG-DEPLOYED-CONFIG. Проверен пример, запущен другой конфиг

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'env_file|environment:|include|args:|command:|config|settings' .
~~~

Сопоставить entrypoint, includes, override-файлы и эффективную конфигурацию. Вывод конфигов может содержать секреты — читать локально.

**Уязвимый вариант:**

Исправили sample config, runtime получает небезопасный override из env/volume.

**Исправление:** Менять реально используемый источник, проверить precedence и restart; секреты не добавлять в репозиторий.

**Проверка:** После restart эффективное значение исправлено, старая копия не вернулась.

<a id="cfg-media-converter"></a>

<a id="cfg-media-converter-media-documents-load-additional-resources"></a>

## CFG-MEDIA-CONVERTER. Загрузка ресурсов из медиадокумента

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'ffmpeg|magick|convert|thumbnail' .
~~~

Проверить, какие дополнительные файлы/URL читает сам декодер после загрузки документа.

**Уязвимый вариант:**

**Основание:** bookster, авторский разбор RuCTF. Старый FFmpeg при создании
превью мог обрабатывать ссылки из загруженного медиаконтейнера.

**Искать:** FFmpeg, ImageMagick, PDF/SVG/XML-конвертеры, thumbnail/preview,
встроенные playlist/URL; различать входной файл и дополнительные ресурсы,
которые парсер читает сам. Проверки URL только в HTTP-обработчике недостаточно.

**Исправление:** исправленная совместимая сборка, явный разрешённый набор
протоколов/декодеров, ограниченные input/output и ресурсы процесса. Не отключать
предусмотренные форматы или превью целиком. Сетевой firewall не подменяет патч.

**Проверка:** все разрешённые форматы, повреждённый файл, вложенная ссылка на
локальный ресурс, лимиты времени/памяти.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/bookster/README.md).

**Основание:** [первичный материал](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/bookster/README.md).

<a id="cfg-format-transition"></a>

<a id="cfg-format-transition-injection-through-intermediate-yaml"></a>

## CFG-FORMAT-TRANSITION. Инъекция через промежуточный YAML

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'yaml|unmarshal|safe_load|template' .
~~~

Проследить текст → шаблон → YAML → объект update; типизировать данные на каждой границе.

**Уязвимый вариант:**

**Основание:** lost_museum, авторский разбор RuCTF. Шаблон генерировал YAML,
который затем разбирался в map для операции MongoDB.

**Искать:** форматирование структурированных документов строками, затем
unmarshal/parse и передача всех полей в БД. safe_load не исправляет добавление
нежелательных полей: это иной класс ошибки, чем небезопасные YAML-конструкторы.

**Исправление:** типизированная структура → сериализатор; затем явная проекция полей
для update, owner/role только с сервера. Не давать клиенту менять структуру
MongoDB-операции.

**Проверка:** переносы строк, двоеточия, вложенные поля и обычный
текст; изменение только разрешённого поля.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/lost_museum/README.md).

**Основание:** [первичный материал](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/lost_museum/README.md).

<a id="cfg-principal-context"></a>

<a id="cfg-principal-context-clients-modify-authorization-context"></a>

## CFG-PRINCIPAL-CONTEXT. Клиент изменяет контекст авторизации

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'userspace|principal|currentUser|tenant' .
~~~

Проследить каждую запись субъекта: DSL и параметры не должны менять server-auth context.

**Уязвимый вариант:**

**Основание:** scp, авторский разбор RuCTF: DSL позволял менять userspace,
использовавшийся для контроля видимости.
**Искать:** присваивания currentUser, userspace, principal, tenant из выражений,
параметров или промежуточного состояния; переключатели режима auth.

**Исправление:** субъект запроса берётся из проверенной сессии, хранится отдельно от
изменяемого контекста DSL. Все чувствительные операции сверяют его серверную
версию.

**Проверка:** выражение не меняет principal; собственные объекты доступны,
чужие скрыты при любом порядке выражений.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/scp/README.md).

**Основание:** [первичный материал](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/scp/README.md).

<a id="cfg-auth-toctou"></a>

<a id="cfg-auth-toctou-authorization-races-and-identifier-reuse"></a>

## CFG-AUTH-TOCTOU. TOCTOU и повторное использование ID

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'owner|tenant|middleware|await|UPDATE|DELETE' .
~~~

Найти ожидание/смену состояния между проверкой и записью; проверить owner/version в атомарном запросе.

**Уязвимый вариант:**

**Основание:** stalker, авторский разбор RuCTF. ORM-снимок прав создавался до
ожидания тела запроса; удаление и повторное создание записей меняло смысл ID.

**Искать:** объект/список ID в middleware → await/I/O → запись без новой проверки;
кэшированные связи ORM; ID, уникальный лишь в части составного ключа.

**Исправление:** условие владельца проверять атомарно в самом UPDATE/DELETE/SHARE;
транзакция/версия строки при необходимости, стабильная уникальность ID.
Миграцию схемы проводить с сохранением записей.

**Проверка:** детерминированное чередование запросов: проверка → удаление/создание →
мутация; чужая запись не изменяется. Проверить rollback и параллельный штатный
сценарий.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/stalker/README.md).

**Основание:** [первичный материал](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/stalker/README.md).

<a id="cfg-custom-crypto"></a>

<a id="cfg-custom-crypto-algebraic-leakage-in-custom-cryptography"></a>

## CFG-CUSTOM-CRYPTO. Алгебраическая утечка самодельной криптографии

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'encrypt|decrypt|matrix|modulus|nonce' .
~~~

Выписать зависимость вход/выход и где входит секрет; проверить сохраняемые алгебраические отношения с владельцем протокола.

**Уязвимый вариант:**

**Основание:** solaris, авторский разбор RuCTF: матричная схема сохраняла
математические зависимости, связанные с секретом.
**Искать:** авторские комбинации RSA/матриц/арифметики, неизменяемые
соотношения между входом и выходом, недостаточная случайность.

**Исправление:** сначала определить контракт и математический источник утечки.
Для обычного шифрования/аутентификации — стандартная библиотечная конструкция
с правильным nonce и версией формата; у крипто-задачи это может потребовать
специального исправления алгоритма. **Не переносить уменьшение размера ключа
из challenge-specific решения в общий hardening.**

**Проверка:** неизменённая функция для штатного клиента, старые данные и отсутствие
найденного инварианта.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/solaris/README.md).

**Основание:** [первичный материал](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/solaris/README.md).

<a id="cfg-shared-backend-key"></a>

<a id="cfg-shared-backend-key-one-credential-spans-all-child-environments"></a>

## CFG-SHARED-BACKEND-KEY. Один служебный credential для всех дочерних окружений

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'API_KEY|apikey|credential|environment|token' .
~~~

Проследить выдачу общего ключа в дочерние окружения и проверку его resource/audience на backend.

**Уязвимый вариант:**

**ENOWARS / replme, автор.** Компрометация одного дочернего backend раскрывала
общий ключ доверия к другим.

**Исправление:** минимальные полномочия и привязка credential к конкретному ресурсу;
не полагаться только на внутренний адрес.

**Проверка:** credential окружения A
не авторизует действие в B.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/main.tex); [исходник/разбор 2](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/path-traversal.patch); [исходник/разбор 3](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/crc.patch); [исходник/разбор 4](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/backend/util/encoding.go); [исходник/разбор 5](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/backend/controller/repl.go); [исходник/разбор 6](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/image/service/user.go).

**Основание:** [первичный материал](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/main.tex).

<a id="cfg-windows-names"></a>

<a id="cfg-windows-names-filenames-have-different-windows-meanings"></a>

## CFG-WINDOWS-NAMES. Имя файла имеет иной смысл в Windows

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'filename|basename|glob|FindFirstFile|ToLower' .
~~~

Сравнить имя в проверке/БД с фактическим Windows lookup: case, wildcard, trailing dot/space и streams.

**Уязвимый вариант:**

**ICC / MaScroll, автор.** Имена в БД и файловой системе расходились по
регистру и допустимым символам.

**Исправление:** серверные storage ID, единая политика имён для фактической ОС,
проверка владельца.

**Проверка:** регистр, wildcard/служебные символы, разделители;
старые файлы доступны.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/MaScroll/README.md).

**Основание:** [первичный материал](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/MaScroll/README.md).

<a id="cfg-proxy-redirect"></a>

<a id="cfg-proxy-redirect-reverse-proxies-follow-redirects-into-trusted-services"></a>

## CFG-PROXY-REDIRECT. Reverse proxy следует redirect внутрь доверенного сервиса

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'proxy_pass|redirect|Location|logout|internal' .
~~~

Проследить redirect во внутреннем HTTP-клиенте и повторную проверку назначения; internal location сам по себе не auth backend.

**Уязвимый вариант:**

**ICC / NorthernFiles, автор.** Open redirect вместе с конфигурацией proxy
делал внутренний endpoint доступным по цепочке.

**Исправление:** безопасный redirect и явный контракт proxy; внутренний выдающий токены
endpoint сам проверяет полномочия.

**Проверка:** внешние/внутренние redirect и
штатный logout.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/NorthernFiles/README.md).

**Основание:** [первичный материал](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/NorthernFiles/README.md).

<a id="cfg-protocol-key"></a>

<a id="cfg-protocol-key-degenerate-values-in-cryptographic-protocols"></a>

## CFG-PROTOCOL-KEY. Вырожденное значение в криптопротоколе

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'public_key|pubkey|group|identity|point' .
~~~

Проверить декодирование и принадлежность ключа допустимой группе, запрет вырожденных элементов по конкретному протоколу.

**Уязвимый вариант:**

**ICC / NorthernFiles, автор.** Допустимый по типу вход приводил согласование
ключа к тривиальному значению.

**Исправление:** протокольная проверка элементов группы и вырожденных состояний;
использовать проверенную реализацию, где совместимо.

**Проверка:** neutral/invalid elements, отрицательные сценарии и interop с клиентом.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/NorthernFiles/README.md).

**Основание:** [первичный материал](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/NorthernFiles/README.md).

<a id="cfg-aggregate-key"></a>

<a id="cfg-aggregate-key-incorrect-public-key-aggregation"></a>

## CFG-AGGREGATE-KEY. Некорректная агрегация публичных ключей

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'aggregate|coefficient|pubkey|subset' .
~~~

Сверить вычисление коэффициентов и proof-of-possession с выбранной схемой; оценить стоимость проверки наборов.

**Уязвимый вариант:**

**ICC / UberPendragon, автор.** Линейная функция коэффициентов не давала
ожидаемой защиты от rogue keys.

**Исправление:** проверенная схема агрегации; при неизменяемом клиенте — обоснованная
проверка вырожденных наборов по конкретному протоколу с ограниченной стоимостью.

**Проверка:** обычные группы, повторяющиеся ключи, вырожденный aggregate и нагрузка.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/UberPendragon/README.md).

**Основание:** [первичный материал](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/UberPendragon/README.md).

<a id="cfg-k8s-host"></a>

<a id="cfg-k8s-host-container-shares-host-namespaces"></a>

## CFG-K8S-HOST. Контейнер разделяет host namespace

**Поиск:** скрипт, правило CFG-K8S-HOST. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-K8S-HOST. Regex: hostPID/hostIPC/hostNetwork:true, Compose pid/ipc/network_mode:host. Не анализирует admission policy или фактический pod.

**Уязвимый вариант:** Доступ к namespaces хоста расширяет последствия компрометации workload.

~~~config
hostPID: true
hostIPC: true
hostNetwork: true
~~~

**Исправление:** Отключить ненужные host namespaces; требуемую связь реализовать в разрешённой topology игры и проверить probes/порты.

~~~config
hostPID: false
hostIPC: false
hostNetwork: false
~~~

**Проверка:** Сервис и checker доступны; workload не видит процессы/IPC хоста и не получает неожиданные host-сокеты.

Первичная документация: [документация 1](https://kubernetes.io/docs/concepts/security/pod-security-standards/).

<a id="cfg-unconfined"></a>

<a id="cfg-unconfined-seccompapparmor-profile-disabled"></a>

## CFG-UNCONFINED. Отключён профиль seccomp/AppArmor

**Поиск:** скрипт, правило CFG-UNCONFINED. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-UNCONFINED. Regex: seccomp/apparmor=unconfined или :unconfined; Kubernetes type:Unconfined. Чужой YAML ключ type может дать ложный сигнал.

**Уязвимый вариант:** Unconfined снимает слой ограничения системных вызовов/доступов контейнера.

~~~config
security_opt:
  - seccomp:unconfined
  - apparmor:unconfined
~~~

**Исправление:** Вернуть стандартный или минимальный совместимый профиль; нужные исключения задавать узко.

~~~config
security_opt:
  - no-new-privileges:true
# Keep the runtime default seccomp/AppArmor profiles.
~~~

**Проверка:** Основные операции и checker работают; фактический контейнер применяет выбранный профиль.

Первичная документация: [документация 1](https://docs.docker.com/engine/security/seccomp/).

<a id="cfg-priv-escalation"></a>

<a id="cfg-priv-escalation-process-privilege-escalation-allowed"></a>

## CFG-PRIV-ESCALATION. Разрешено повышение привилегий процесса

**Поиск:** скрипт, правило CFG-PRIV-ESCALATION. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-PRIV-ESCALATION. Regex: явное allowPrivilegeEscalation:true. Отсутствие поля, defaults и взаимодействие с privileged/CAP_SYS_ADMIN вручную.

**Уязвимый вариант:** Разрешение privilege escalation оставляет пути через setuid/file capabilities.

~~~config
allowPrivilegeEscalation: true
~~~

**Исправление:** Выключить allowPrivilegeEscalation, убрать privileged/CAP_SYS_ADMIN и лишние capabilities; проверить реально необходимые операции.

~~~config
allowPrivilegeEscalation: false
~~~

**Проверка:** Нужные операции работают с ограничениями; runtime securityContext соответствует manifest.

Первичная документация: [документация 1](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).

<a id="cfg-actuator"></a>

<a id="cfg-actuator-spring-actuator-exposes-every-endpoint"></a>

## CFG-ACTUATOR. Spring Actuator публикует все endpoints

**Поиск:** скрипт, правило CFG-ACTUATOR. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-ACTUATOR. Regex: плоское свойство или environment MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE с *. Вложенный YAML и активные profiles искать вручную по endpoints/exposure/include.

**Уязвимый вариант:** Широкая публикация management endpoints может раскрыть runtime/config или предоставить управление.

~~~config
management.endpoints.web.exposure.include=*
~~~

**Исправление:** Оставить необходимые endpoints и ограничить доступ management plane; health details и пользовательский SecurityFilterChain проверить отдельно.

~~~config
management.endpoints.web.exposure.include=health
~~~

**Проверка:** Checker/health работает; env, heapdump, loggers, shutdown и другие ненужные endpoints недоступны без разрешённого admin-доступа.

Первичная документация: [документация 1](https://docs.spring.io/spring-boot/reference/actuator/endpoints.html).

<a id="cfg-h2-console"></a>

<a id="cfg-h2-console-h2-web-console-enabled"></a>

## CFG-H2-CONSOLE. Веб-консоль H2 включена

**Поиск:** скрипт, правило CFG-H2-CONSOLE. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-H2-CONSOLE. Regex: spring.h2.console.enabled/SPRING_H2_CONSOLE_ENABLED=true. Вложенный YAML, aliases и разные profiles вручную.

**Уязвимый вариант:** Консоль базы является отдельной административной поверхностью с собственным auth и JDBC-вводом.

~~~config
spring.h2.console.enabled=true
~~~

**Исправление:** Отключить в runtime profile или выделить защищённый локальный admin-доступ; не отключать auth/CSRF всей программы ради консоли.

~~~config
spring.h2.console.enabled=false
~~~

**Проверка:** Приложение работает с БД, endpoint консоли не доступен из игровой сети.

Первичная документация: [документация 1](https://docs.spring.io/spring-boot/reference/data/sql.html#data.sql.h2-web-console).

<a id="cfg-tls-upstream"></a>

<a id="cfg-tls-upstream-proxy-does-not-verify-upstream-tls"></a>

## CFG-TLS-UPSTREAM. Proxy не проверяет TLS upstream

**Поиск:** скрипт, правило CFG-TLS-UPSTREAM. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-TLS-UPSTREAM. Regex: proxy_ssl_verify/grpc_ssl_verify off. Отсутствие директивы, inheritance и эффективные значения требуют просмотра полного nginx config.

**Уязвимый вариант:** HTTPS до upstream без проверки сертификата не подтверждает, что это нужный backend.

~~~config
proxy_ssl_verify off;
~~~

**Исправление:** Включить verify, доверенный CA и корректное имя/SNI; проверить цепочку и число промежуточных CA для своего upstream.

~~~config
proxy_ssl_verify on;
proxy_ssl_trusted_certificate /etc/nginx/trusted-ca.pem;
proxy_ssl_server_name on;
proxy_ssl_name notes.internal;
~~~

**Проверка:** Правильный backend доступен, чужой сертификат/hostname отвергается без HTTP fallback.

Первичная документация: [документация 1](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ssl_verify).

<a id="cfg-ssh-empty-password"></a>

<a id="cfg-ssh-empty-password-sshd-permits-empty-passwords"></a>

## CFG-SSH-EMPTY-PASSWORD. SSHD допускает пустой пароль

**Поиск:** скрипт, правило CFG-SSH-EMPTY-PASSWORD. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-SSH-EMPTY-PASSWORD. Regex: PermitEmptyPasswords yes. Стандартное имя sshd_config поддержано; включаемые файлы произвольного имени перед сканом нужно явно учитывать вручную.

**Уязвимый вариант:** При доступной password authentication аккаунт с пустым паролем может стать входом на хост.

~~~config
PermitEmptyPasswords yes
~~~

**Исправление:** Запретить пустые пароли, проверить Match-блоки/PAM и аккаунты; до применения сохранить действующий канал доступа.

~~~config
PermitEmptyPasswords no
~~~

**Проверка:** Разрешённый способ входа работает; пустой пароль не принимается в каждом применимом Match-контексте.

Первичная документация: [документация 1](https://man.openbsd.org/sshd_config#PermitEmptyPasswords).

<a id="cfg-sudo-all"></a>

<a id="cfg-sudo-all-unrestricted-passwordless-sudo"></a>

## CFG-SUDO-ALL. Неограниченный sudo без пароля

**Поиск:** скрипт, правило CFG-SUDO-ALL. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CFG-SUDO-ALL. Regex: NOPASSWD:ALL. Aliases, include-файлы, wildcard argv и опасные разрешённые бинарники требуют ручного просмотра; файл sudoers распознаётся.

**Уязвимый вариант:** NOPASSWD:ALL превращает выполнение кода runtime пользователя в доступ ко всем разрешённым Runas целям.

~~~config
app ALL=(ALL:ALL) NOPASSWD: ALL
~~~

**Исправление:** Убрать sudo у сервисного пользователя; редкие операции вынести в минимальный helper без произвольных argv, shell и редактируемых зависимостей.

~~~config
# Runtime user has no sudo grant.
# Provision required resources before service startup.
~~~

**Проверка:** Сервис работает без sudo; эффективный список прав runtime не содержит ALL или команды с выходом в shell.

Первичная документация: [документация 1](https://www.sudo.ws/docs/man/sudoers.man/).

<a id="cfg-jwt-key-selection"></a>

<a id="cfg-jwt-key-selection-untrusted-kidjku-selects-verification-keys"></a>

## CFG-JWT-KEY-SELECTION. Недоверенный kid/jku выбирает ключ проверки

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'kid|jku|x5u|jwks|JWK|keyfunc|getKey|IssuerSigningKeyResolver' .
~~~

Проследить, откуда берутся issuer, URL набора ключей, локальный путь и ключ по kid. Сравнить доверенный registry с полями ещё не проверенного токена; проверить cache key по issuer и kid.

**Уязвимый вариант:** Токен сам задаёт адрес JWKS/файл ключа или kid другого issuer, а валидатор принимает найденный материал как доверенный.

**Исправление:** Закрепить допустимый issuer и его JWKS/ключи серверной конфигурацией; kid использовать только как точный индекс внутри этого issuer. Ограничить допустимые алгоритмы, типы ключей, кеш и ротацию. Не доверять встроенному jku/x5u.

**Проверка:** Штатная ротация ключа работает; неизвестный kid, kid другого issuer и пользовательский URL не меняют доверенную область. Ошибка загрузки ключей не разрешает вход.

Основание: [первичная документация/материал](https://www.rfc-editor.org/rfc/rfc8725.html). Описание и рецепт адаптации составлены для этой базы.

<a id="cfg-signed-request"></a>

<a id="cfg-signed-request-signatures-are-not-bound-to-operations-or-preventable-replays"></a>

## CFG-SIGNED-REQUEST. Подпись не связана с действием или допускает повтор

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'signature|signed_url|signedUrl|nonce|expires|timestamp|hmac|Content-Digest' .
~~~

Выписать точный набор подписываемых байтов: метод, путь, query, body, получатель, назначение, срок. Проверить нормализацию на signer/verifier и атомарность одноразового nonce.

**Уязвимый вариант:** Верная подпись для чтения принимается при изменении данных, body можно заменить, либо одноразовый webhook/платёж применяют повторно.

**Исправление:** Подписывать канонический контракт с action/purpose, получателем и необходимыми компонентами запроса; ограничить срок и clock skew. Для одноразовых операций атомарно фиксировать использованный nonce/idempotency key вместе с изменением.

**Проверка:** Изменение метода/пути/body/получателя ломает проверку. Два одновременных повтора дают один эффект; штатные разрешённые retries возвращают согласованный результат.

Основание: [первичная документация/материал](https://www.rfc-editor.org/rfc/rfc9421.html). Описание и рецепт адаптации составлены для этой базы.

<a id="cfg-rate-limit-identity"></a>

<a id="cfg-rate-limit-identity-senders-choose-their-rate-limit-identity"></a>

## CFG-RATE-LIMIT-IDENTITY. Ключ rate limit выбирает отправитель

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'rate.?limit|throttle|X-Forwarded-For|X-Real-IP|req\.ip|remote_addr|client_ip' .
~~~

Сопоставить ключ лимита с реальной границей доверия proxy. Проверить регистр/Unicode имени, маршрут-алиасы, отдельные воркеры, истечение счётчика и отказ backend.

**Уязвимый вариант:** Лимит привязан к произвольному заголовку, одному из вариантов имени аккаунта или локальной памяти каждого worker; смена представления сбрасывает бюджет.

**Исправление:** Нормализовать идентификатор одинаково с auth; принимать proxy headers только от доверенных hop. Применять атомарный общий бюджет по нужным субъектам/операциям, сохранив доступность легитимных общих IP.

**Проверка:** Смена заголовка и формы идентификатора не создаёт новый бюджет; параллельные workers соблюдают лимит; допустимый checker traffic проходит.

Основание: [первичная документация/материал](https://expressjs.com/en/guide/behind-proxies.html). Описание и рецепт адаптации составлены для этой базы.

<a id="cfg-token-revocation"></a>

<a id="cfg-token-revocation-password-or-role-changes-fail-to-revoke-access"></a>

## CFG-TOKEN-REVOCATION. Смена пароля или роли не отзывает полномочия

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'logout|revoke|revocation|token_version|session_version|password_changed|security_stamp|refresh_token' .
~~~

Проследить login, refresh, logout, смену пароля, удаление аккаунта и изменение роли. Проверить, когда API перечитывает полномочия, как проверяется session/token version и какие кеши остаются.

**Уязвимый вариант:** Удалённый администратор продолжает пользоваться старым JWT/session; отозванный refresh восстанавливает доступ.

**Исправление:** Определить срок действия и отзыв по контракту: session version/denylist/короткие access tokens с проверяемым refresh. Ротацию refresh выполнять атомарно, инвалидировать связанные кеши.

**Проверка:** После выбранного события отзыва старые access/refresh перестают давать доступ в обещанный срок на всех workers; штатный повтор входа работает.

Основание: [первичная документация/материал](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html). Описание и рецепт адаптации составлены для этой базы.

<a id="cfg-fail-open"></a>

<a id="cfg-fail-open-verification-errors-become-permission"></a>

## CFG-FAIL-OPEN. Ошибка проверки превращается в разрешение

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'catch|except|finally|recover|fallback|default.*allow|on_error|unwrap_or|Result' .
~~~

Для auth/signature/ACL-проверки проследить все исключения, timeout, nil/None/null и ветви cleanup. Проверить catch/finally, вызываемый следующий middleware и значение по умолчанию.

**Уязвимый вариант:** Ошибка БД или валидатора возвращает allow/default principal; handler продолжает работу после записи 401; finally перезаписывает отказ.

**Исправление:** По умолчанию отказывать до выполнения побочного эффекта. Различать отказ авторизации и временную недоступность, завершать цепочку обработки; ошибки логировать без секретов.

**Проверка:** Искусственная ошибка/timeout auth backend, неверный тип и nil результат не дают данных и не изменяют состояние; штатная проверка проходит.

Основание: [первичная документация/материал](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html). Описание и рецепт адаптации составлены для этой базы.

<a id="cfg-ldap-filter"></a>

<a id="cfg-ldap-filter-ldap-filters-or-dns-built-as-strings"></a>

## CFG-LDAP-FILTER. Строковая сборка LDAP filter или DN

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'ldap_search|ldap\.search|search_s|SearchFilter|DirContext|LdapName|Filter\.create|escape_filter' .
~~~

Проследить сборку search filter отдельно от DN: это разные грамматики. Проверить bind/search, wildcard, пустой пароль и выбор записи при нескольких совпадениях.

**Уязвимый вариант:** Имя пользователя подставляют в LDAP expression как синтаксис; расширенный фильтр выбирает другую запись или несколько записей, первая из которых считается пользователем.

**Исправление:** Использовать builder/parameter API либо escape именно для filter value; DN строить штатным DN builder. Требовать ровно ожидаемое совпадение и корректный bind, не считать поиск аутентификацией.

**Проверка:** Специальные символы остаются частью значения; ноль/много совпадений и пустые credentials не дают вход; штатный пользователь проходит.

Основание: [первичная документация/материал](https://www.rfc-editor.org/rfc/rfc4515.html). Описание и рецепт адаптации составлены для этой базы.

<a id="cfg-ci-trust"></a>

<a id="cfg-ci-trust-untrusted-data-and-code-cross-ci-trust-boundaries"></a>

## CFG-CI-TRUST. Недоверенные данные и код пересекают границу CI

**Поиск:** вручную; отдельного правила сканера нет. CFG-CI-TRUST — идентификатор
раздела, а не автоматического сигнала. Найти workflows и composite actions:

~~~bash
rg -n --hidden -g '*.yml' -g '*.yaml' -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'pull_request_target|workflow_run|permissions:|secrets\.|allow-unsafe-pr-checkout|checkout@|download-artifact@|head\.sha|git fetch|gh pr checkout|run:|script:|uses: \./' .
rg -n --hidden -g '*.yml' -g '*.yaml' -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e '\$\{\{[^}]*github\.(event|head_ref)' .
~~~

Открыть весь найденный job и вызываемые actions/reusable workflows. Проследить
последовательно: кто задаёт event field/ref/artifact → где значение становится
shell/JS-кодом, зависимостью или исполняемым файлом → какие permissions, secrets,
окружение и runner получает этот шаг. Само имя события не доказывает дефект.
Многострочные выражения, косвенные outputs и входы composite actions требуют
просмотра даже без совпадения команды поиска.

**Уязвимый вариант:** первая граница — подстановка данных события прямо в
исходник `run`/`script`. Кавычки вокруг expression не защищают: выражение
подставляется до разбора shell.

~~~yaml
- name: Show title
  shell: bash
  run: printf '%s\n' "${{ github.event.pull_request.title }}"
~~~

Реальный случай с `workflow_run.head_branch` разобран в
[GHSL-2025-099](https://securitylab.github.com/advisories/GHSL-2025-099_cross-platform-actions_action/).
Он относился к workflow репозитория action; это не утверждение об уязвимости
каждого проекта, использующего этот action.

Вторая граница — исполнение PR-кода в привилегированном job:

~~~yaml
on: pull_request_target
permissions:
  contents: write
jobs:
  checks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          allow-unsafe-pr-checkout: true
      - run: make test
        env:
          SERVICE_TOKEN: ${{ secrets.SERVICE_TOKEN }}
~~~

PR может менять не только тест, но и Makefile, install hook или локальный action.
У `workflow_run` аналогичная ошибка — скачать artifact предыдущего PR-run и
выполнить содержащийся в нём скрипт. Верный run ID и статус success подтверждают
происхождение результата, но не доверенность его содержимого.
[GitHub: доверие к pull_request_target и workflow_run](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target).
Реальная цепочка PR → привилегированный workflow → выполнение PR-кода описана
в [исследовании Gradio GHSL-2024-150 — GHSL-2024-157](https://securitylab.github.com/advisories/GHSL-2024-150_GHSL-2024-157_Gradio/).

В `checkout` v7 опасный checkout fork PR при `pull_request_target` и при
`workflow_run`, чей `workflow_run.event` относится к `pull_request*`, по умолчанию
блокируется; пример выше явно отключает защиту. Это не защита любого
`workflow_run`. Защита перенесена в поддерживаемые major-ветки,
но старый закреплённый SHA сам не обновляется. Проверить фактический commit и
backport; получение кода через `git fetch`, сторонний action или artifact эта
проверка не заменяет.
[Изменение checkout](https://github.blog/changelog/2026-06-18-safer-pull_request_target-defaults-for-github-actions-checkout/).
Дополнительно проверить фактически применимую event policy репозитория:
её наличие и режим нельзя вывести только из workflow YAML.
[GitHub: event policy](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target#default-policy-for-pull_request_target).

**Исправление:** для значения события сохранить разделение данных и кода:

~~~yaml
- name: Show title
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  shell: bash
  run: printf '%s\n' "$PR_TITLE"
~~~

Формат `printf` фиксирован, значение передаётся одним аргументом. Последующий
`eval`, `bash -c` или конструирование JS снова нарушат границу. Передача через
`with` безопасна лишь при соответствующем поведении принимающего action.
[GitHub: защита от script injection](https://docs.github.com/en/actions/reference/security/secure-use#good-practices-for-mitigating-script-injection-attacks).

Для обычных проверок PR использовать непривилегированный workflow без secrets:

~~~yaml
on: pull_request
permissions:
  contents: read
jobs:
  checks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          persist-credentials: false
      - run: make test
~~~

`persist-credentials: false` отдельно не исправляет выполнение PR-кода с
привилегиями. Если нужны комментарии, метки или публикация отчёта, отделить
доверенный job: он принимает ограниченный JSON/text, проверяет размер, схему,
repo/run/head SHA и назначение PR, не исполняет и не импортирует artifact.
Скачивать данные отдельно от доверенного workspace. Тесты с private registry/API
потребуют отдельного дизайна; передавать их секреты произвольному PR нельзя.
`pull_request_target` только для меток/комментариев может быть обоснован.
[GitHub Security Lab: разделение стадий](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/).

**Проверка:** статически подтвердить путь данных и минимальные эффективные права
с учётом настроек репозитория. В разрешённом тестовом CI проверить fork PR,
новый SHA после approval, название с кавычками/переводами строк как данные,
чужой run ID, неверную схему и oversized artifact. Штатные проверки и публикация
отчёта должны сохраниться; PR-код не получает secrets или постоянный self-hosted
runner с доступом к внутренним ресурсам. Эти workflows в рамках проверки базы
не запускались; офлайн-сканер не определяет effective permissions и связи Actions.

<a id="cfg-docker-tcp"></a>

<a id="cfg-docker-tcp-docker-daemon-listens-on-every-tcp-interface"></a>

## CFG-DOCKER-TCP. Docker daemon слушает на всех TCP-интерфейсах

**Поиск:** правило сканера CFG-DOCKER-TCP. Точный контракт детектора: `--explain CFG-DOCKER-TCP`. Regex с лексическими исключениями: dockerd, после которого на той же строке стоят -H/--host tcp://0.0.0.0 или [::]. Не оценивает TLS-флаги, JSON-конфигурацию daemon, именованные интерфейсы и shell-подстановки; listener с TLS тоже требует проверки.

**Уязвимый вариант:**

~~~shell
dockerd -H tcp://0.0.0.0:2375
~~~

**Исправление:** Предпочитайте локальный доступ к Docker. Если удалённое управление необходимо, используйте аутентифицированный зашифрованный транспорт и явно ограниченный интерфейс управления; не публикуйте его как командный UI.

~~~shell
dockerd -H unix:///var/run/docker.sock
~~~

**Проверка:** Несогласованные LAN-клиенты не могут управлять Docker; согласованное администрирование остаётся доступным без раскрытия credentials.

[Первичный источник 1](https://docs.docker.com/reference/cli/dockerd/#daemon-socket-option)

<a id="cfg-floating-image"></a>

<a id="cfg-floating-image-explicit-latest-image-tag"></a>

## CFG-FLOATING-IMAGE. Явный тег образа latest

**Поиск:** правило сканера CFG-FLOATING-IMAGE. Точный контракт детектора: `--explain CFG-FLOATING-IMAGE`. Regex с лексическими исключениями: Docker FROM или обычный YAML-ключ image с незаключённым в кавычки image:latest без digest. YAML в кавычках, образы без тега, другие изменяемые теги, подстановки ARG и фактическая архитектура требуют аудита модели deployment.

**Уязвимый вариант:**

~~~docker
FROM example.invalid/app:latest
~~~

**Исправление:** Зафиксируйте согласованную версию исходников и digest образа для нужной архитектуры; заполните offline-инвентарь образов и проверьте импортированные образы.

~~~docker
FROM example.invalid/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
~~~

**Проверка:** Повторные offline-запуски используют согласованные байты и архитектуру; не происходит неявного pull или отката к latest.

[Первичный источник 1](https://docs.docker.com/reference/dockerfile/#from)

<a id="tpl-autoescape-off"></a>

<a id="tpl-autoescape-off-template-block-disables-autoescaping"></a>

## TPL-AUTOESCAPE-OFF. Блок шаблона отключает автоматическое экранирование

**Поиск:** правило сканера TPL-AUTOESCAPE-OFF. Точный контракт детектора: `--explain TPL-AUTOESCAPE-OFF`. Regex с исключением HTML/Jinja-комментариев: блоки Jinja/Twig autoescape false и Django autoescape off. Не оценивает defaults шаблонизатора, внешние блоки и доверенность значений.

**Уязвимый вариант:**

~~~template
{% autoescape false %}{{ message }}{% endautoescape %}
~~~

**Исправление:** Сохраняйте автоматическое экранирование недоверенного текста; явно очищайте разрешённый HTML и проверяйте контекст вывода.

~~~template
{{ message }}
~~~

**Проверка:** Пользовательские теги и атрибуты остаются данными; разрешённое форматирование продолжает работать.

[Первичный источник 1](https://jinja.palletsprojects.com/en/stable/templates/#autoescape-overrides)
