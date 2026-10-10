<a id="sql--databases-find-fix-and-verify"></a>

# SQL / базы данных: поиск и исправление

[English](sql.md) | Русский

[Вся база](README-RU.md) · [Сканер](../offline-scanner-RU.md) · [Проверка патча](../patch-validation-RU.md)

18 разделов. Формат: **Поиск → Уязвимый вариант → Исправление → Проверка**.
Команды `rg` выполняются в корне локальной копии сервиса и только читают файлы. Субъект/владелец определяется по проверенной сессии, а не данным запроса. Примеры нужно адаптировать к реальным API и контракту.

Автоматические находки — ограниченные синтаксические сигналы для проверки. AST-анализ не разрешает типы и не отслеживает данные между функциями; regex не заменяет парсер языка. Комментарии, строки и одноимённые пользовательские API могут давать совпадения. Проверьте фактическое исполнение, входные данные, авторизацию и границы доверия.

<a id="contents"></a>

## Содержание

- [SQL-UPSERT — Upsert/replace требует проверки владельца](#sql-upsert)
- [SQL-DEFINER — SECURITY DEFINER и доверие search_path](#sql-definer)
- [SQL-BYPASSRLS — Роль приложения обходит RLS](#sql-bypassrls)
- [SQL-PUBLIC-GRANT — Широкая выдача прав PUBLIC](#sql-public-grant)
- [SQL-RLS-POLICY — RLS: USING, WITH CHECK и объединение политик](#sql-rls-policy)
- [SQL-IDENTIFIERS — Параметры не подставляют имена таблиц и ORDER BY](#sql-identifiers)
- [SQL-COLLATION — Разная канонизация в auth и unique constraint](#sql-collation)
- [SQL-TRANSACTION — Проверка и изменение вне одной атомарной операции](#sql-transaction)
- [SQL-POOL-CONTEXT — Пул соединений сохраняет tenant/search_path](#sql-pool-context)
- [SQL-SQLITE-FK — SQLite foreign_keys явно отключён](#sql-sqlite-fk)
- [SQL-MYSQL-PRIVILEGES — MySQL FILE и административные права app](#sql-mysql-privileges)
- [SQL-SECOND-ORDER — Сохранённое значение снова становится SQL](#sql-second-order)
- [SQL-NESTED-DSL — Несколько уровней языка запроса](#sql-nested-dsl)
- [SQL-RLS-DISABLE — PostgreSQL RLS отключают для таблицы](#sql-rls-disable)
- [SQL-TOKEN-PREFIX — Секретный токен проверяется по префиксу или диапазону](#sql-token-prefix)
- [SQL-NULL-AUTH — NULL меняет смысл проверки доступа](#sql-null-auth)
- [SQL-RLS-ALLOW-ALL — Безусловное выражение в политике RLS](#sql-rls-allow-all)

- [SQL-SERVER-ROLE — Выданы роли PostgreSQL для файлов и программ сервера](#sql-server-role)

<a id="sql-upsert"></a>

<a id="sql-upsert-upsertreplace-requires-ownership-review"></a>

## SQL-UPSERT. Upsert/replace требует проверки владельца

**Поиск:** скрипт, правило SQL-UPSERT. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain SQL-UPSERT. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~sql
INSERT INTO notes(id, owner, body) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE body=VALUES(body);
~~~

**Исправление:** Разделить создание и обновление; нормализация/колляция до проверки, ownership в атомарном UPDATE. Проверить число изменённых строк, уникальность и транзакцию.

~~~sql
UPDATE notes SET body=? WHERE id=? AND owner=?;
~~~

**Проверка:** Конфликт после case-fold/Unicode/триггера не обновляет чужую запись; штатное создание/редактирование сохранены.

**Вариант A/D:** Нормализация ключа после проверки + upsert. **RuCTF / rusi-trainer, автор.** Поиск прав использовал исходное имя, а триггер
БД нормализовал ключ перед вставкой; конфликт превращал её в обновление.

**Патч:** единая канонизация и колляция, разделить insert/update, ownership
в самой мутации. Замена СУБД не универсальное исправление.
**Тест:** Unicode/case-варианты, конфликт уникальности, параллельная вставка.
**Поиск:** SQL-UPSERT; триггер и сопоставление ключей вручную.

[исходник/разбор 1](https://github.com/HackerDom/ructf-2023/blob/0cc333e44f2ba6908ff6c5d613146e3b00173315/writeups/rusi-trainer/README.md).

<a id="sql-definer"></a>

<a id="sql-definer-security-definer-and-search_path-trust"></a>

## SQL-DEFINER. SECURITY DEFINER и доверие search_path

**Поиск:** скрипт, правило SQL-DEFINER. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain SQL-DEFINER. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~sql
CREATE FUNCTION f() RETURNS int LANGUAGE sql SECURITY DEFINER AS $$ SELECT value FROM settings $$;
~~~

**Исправление:** Если повышенные права не нужны — INVOKER. Иначе минимальный владелец, безопасный фиксированный search_path с pg_temp в конце, schema-qualified объекты и ограниченный EXECUTE.

~~~sql
CREATE FUNCTION f() RETURNS int LANGUAGE sql SECURITY INVOKER AS $$ SELECT value FROM app.settings $$;
~~~

**Проверка:** Пользователь не может подменить объект временной/доступной схемой; обычный вызов сохраняет права.

**Основание:** [первичный материал](https://www.postgresql.org/docs/current/sql-createfunction.html).

<a id="sql-bypassrls"></a>

<a id="sql-bypassrls-application-role-bypasses-rls"></a>

## SQL-BYPASSRLS. Роль приложения обходит RLS

**Поиск:** правило сканера SQL-BYPASSRLS. Подробности: `--explain SQL-BYPASSRLS`. Ограниченный SQL-поиск: CREATE/ALTER ROLE или USER с явным SUPERUSER/BYPASSRLS. Комментарии и строки исключены; keywords без кавычек, до 300 символов. Поздние overrides, владелец таблиц, наследуемые роли и фактическая runtime-политика требуют ручной проверки.

**Уязвимый вариант:**

~~~sql
ALTER ROLE app BYPASSRLS;
~~~

**Исправление:** Отдельная роль приложения без повышенных атрибутов; владельца таблицы проверять отдельно. FORCE RLS не ограничивает superuser/BYPASSRLS.

~~~sql
ALTER ROLE app NOBYPASSRLS NOSUPERUSER;
~~~

**Проверка:** SELECT/INSERT/UPDATE от реальной роли двух tenant; миграционная роль отдельно.

**Основание:** [первичный материал](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).

<a id="sql-public-grant"></a>

<a id="sql-public-grant-broad-privileges-granted-to-public"></a>

## SQL-PUBLIC-GRANT. Широкая выдача прав PUBLIC

**Поиск:** правило сканера SQL-PUBLIC-GRANT. Подробности: `--explain SQL-PUBLIC-GRANT`. Ограниченный SQL-поиск: GRANT ALL или списки SELECT/INSERT/UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER/CREATE/USAGE/EXECUTE/CONNECT/TEMPORARY/TEMP ON object TO PUBLIC. Комментарии/строки исключены; совпадение не пересекает statements. Quoted identifiers, defaults, сложные grants, реальные права и намеренно общие объекты проверяются вручную.

**Уязвимый вариант:**

~~~sql
GRANT ALL ON notes TO PUBLIC;
~~~

**Исправление:** Выдать конкретной роли необходимые действия; проверить старые и default privileges, sequences и функции. Не отзывать права чужой инфраструктуры.

~~~sql
GRANT SELECT, INSERT, UPDATE ON notes TO app;
~~~

**Проверка:** Нет доступа соседней роли; app создаёт ID/читает старые данные.

**Основание:** [первичный материал](https://www.postgresql.org/docs/current/sql-grant.html).

<a id="sql-rls-policy"></a>

<a id="sql-rls-policy-rls-using-with-check-and-policy-composition"></a>

## SQL-RLS-POLICY. RLS: USING, WITH CHECK и объединение политик

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'CREATE POLICY|ROW LEVEL SECURITY|USING|WITH CHECK' .
~~~

Сверить роль приложения, SELECT/UPDATE/INSERT, owner bypass и OR между permissive policies.

**Уязвимый вариант:**

Новая широкая policy делает прежнее ограничение бесполезным либо изменение tenant не контролируется.

**Исправление:** Политика чтения и нового состояния по контракту, тестировать effective role; ограничения RLS не заменяют object-level app policy.

**Проверка:** Чужая строка скрыта и tenant нельзя изменить; migrations/checker работают.

**Основание:** [первичный материал](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).

<a id="sql-identifiers"></a>

<a id="sql-identifiers-parameters-do-not-substitute-table-names-or-order-by"></a>

## SQL-IDENTIFIERS. Параметры не подставляют имена таблиц и ORDER BY

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'ORDER BY|table_name|column_name|quote_ident|identifier' .
~~~

Найти все динамические identifiers и направление сортировки, отдельно от значений.

**Уязвимый вариант:**

Конкатенация order/column из запроса меняет синтаксис; placeholder для имени не работает как ожидается.

**Исправление:** Фиксированная карта допустимых identifiers/направлений, quoting API драйвера при необходимости; значения параметризовать.

**Проверка:** Разрешённая сортировка сохраняется, неизвестное поле/направление отвергаются.

<a id="sql-collation"></a>

<a id="sql-collation-authorization-and-uniqueness-use-different-canonicalization"></a>

## SQL-COLLATION. Разная канонизация в auth и unique constraint

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'COLLATE|LOWER\(|UPPER\(|UNIQUE|TRIGGER|citext' .
~~~

Сопоставить сравнение приложения, collation БД, trigger и уникальный индекс.

**Уязвимый вариант:**

Два имени различаются при проверке прав, но считаются одним при записи.

**Исправление:** Единая канонизация до проверки/записи и стабильный owner ID; миграция конфликтов, не просто смена всей БД.

**Проверка:** Case/Unicode/trailing spaces по реальной БД, старые ссылки и уникальность.

<a id="sql-transaction"></a>

<a id="sql-transaction-check-and-mutation-are-not-one-atomic-operation"></a>

## SQL-TRANSACTION. Проверка и изменение вне одной атомарной операции

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'SELECT|UPDATE|DELETE|BEGIN|FOR UPDATE|version' .
~~~

Сверить isolation level и where условия записи, число изменённых строк.

**Уязвимый вариант:**

Два запроса проходят SELECT-проверку и оба тратят ресурс/меняют чужое после смены owner.

**Исправление:** Условный UPDATE/DELETE с owner/version/остатком, транзакция и bounded retry; выбрать нужный уровень изоляции.

**Проверка:** Детерминированная гонка, conflict/rollback и штатная конкурентность.

<a id="sql-pool-context"></a>

<a id="sql-pool-context-connection-pools-retain-tenant-or-search_path"></a>

## SQL-POOL-CONTEXT. Пул соединений сохраняет tenant/search_path

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'SET ROLE|SET search_path|set_config|tenant|pool|RESET' .
~~~

Сравнить session-level SET и transaction-local SET; проверить возврат соединения после ошибки.

**Уязвимый вариант:**

Следующий запрос получает прежнюю роль/schema/tenant.

**Исправление:** SET LOCAL в корректной транзакции либо надёжный reset; owner не из client-controlled session variable.

**Проверка:** Два tenant на одном соединении, rollback/exception и обычный повторный запрос.

**Основание:** [первичный материал](https://www.postgresql.org/docs/current/ddl-schemas.html).

<a id="sql-sqlite-fk"></a>

<a id="sql-sqlite-fk-sqlite-foreign_keys-explicitly-disabled"></a>

## SQL-SQLITE-FK. SQLite foreign_keys явно отключён

**Поиск:** скрипт, правило SQL-SQLITE-FK. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain SQL-SQLITE-FK. Regex: PRAGMA foreign_keys=OFF/0/false или foreign_keys(OFF/0/false). Отсутствие ON, pool hooks и compile options требуют ручной проверки.

Дополнительный ручной поиск для непокрытых форм:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'PRAGMA foreign_keys|sqlite3.connect|Data Source|FOREIGN KEY' .
~~~

Проверить фактический PRAGMA после открытия каждого connection и до начала транзакции.

**Уязвимый вариант:**

DDL содержит FK, приложение считает ownership связи гарантированными, enforcement отключён.

**Исправление:** Включить foreign_keys для каждого соединения вне транзакции, проверить результат и существующие нарушения; отдельно мигрировать некорректные записи и обработать constraint errors.

**Проверка:** Каждое соединение сообщает foreign_keys=1; foreign_key_check не возвращает нарушений; недопустимый владелец отклоняется, каскады и старые данные совместимы.

**Основание:** [первичный материал](https://www.sqlite.org/pragma.html#pragma_foreign_keys).


**Сигнал сканера — пример до:**

~~~sql
PRAGMA foreign_keys = OFF;
~~~

**Шаблон исправления:**

~~~sql
PRAGMA foreign_keys = ON;
~~~

Первичная документация: [документация 1](https://www.sqlite.org/foreignkeys.html).

<a id="sql-mysql-privileges"></a>

<a id="sql-mysql-privileges-mysql-runtime-user-has-admin-privileges"></a>

## SQL-MYSQL-PRIVILEGES. MySQL FILE и административные права app

**Поиск:** скрипт, правило SQL-MYSQL-PRIVILEGES. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain SQL-MYSQL-PRIVILEGES. Regex: GRANT с FILE/SUPER или ALL [PRIVILEGES] ON *.*. Другие опасные dynamic privileges, роли и уже выданные права вручную.

Дополнительный ручной поиск для непокрытых форм:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'GRANT|FILE|SUPER|ALL PRIVILEGES|secure_file_priv|local_infile' .
~~~

Прочитать SHOW GRANTS своей app-роли; проверить FILE, чтение/запись и настройки LOCAL INFILE обеих сторон.

**Уязвимый вариант:**

Обычное приложение имеет права файлового/административного доступа, которые усиливают ошибку запроса.

**Исправление:** Разделить runtime-аккаунт и аккаунт миграций; убрать ненужные глобальные привилегии и GRANT OPTION; ограничить hosts аккаунтов реальной топологией. Согласовать secure_file_priv и отключение ненужного LOCAL INFILE.

**Проверка:** SHOW GRANTS содержит только необходимые права; CRUD, миграции и checker работают, операция вне полномочий отвергается; аккаунты организаторов не менять.

**Основание:** [первичный материал](https://dev.mysql.com/doc/refman/8.4/en/privileges-provided.html).


**Сигнал сканера — пример до:**

~~~sql
GRANT FILE, SUPER ON *.* TO 'app'@'%';
~~~

**Шаблон исправления:**

~~~sql
GRANT SELECT, INSERT, UPDATE, DELETE ON appdb.* TO 'app'@'localhost';
~~~

Первичная документация: [документация 1](https://dev.mysql.com/doc/refman/8.4/en/privileges-provided.html).

<a id="sql-second-order"></a>

<a id="sql-second-order-stored-data-becomes-sql-again"></a>

## SQL-SECOND-ORDER. Сохранённое значение снова становится SQL

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'execute|query|EXECUTE|format\(|quote|SELECT' .
~~~

Проследить значение из БД до второго запроса/export/job; хранение не делает данные доверенными.

**Уязвимый вариант:**

При insert значение параметризовано, позже строка из записи вставляется в динамический SQL.

**Исправление:** Параметризация на каждом sink, включая stored procedures и jobs; отдельная карта identifiers.

**Проверка:** Сохранённое значение с разделителем остаётся данными при последующей операции.

<a id="sql-nested-dsl"></a>

<a id="sql-nested-dsl-multiple-query-language-layers"></a>

## SQL-NESTED-DSL. Несколько уровней языка запроса

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'LIKE|database|tenant|parse|execute' .
~~~

Разделить внешний DSL, внутренний SQL и выбор базы; проверить интерпретацию разделителей на обоих уровнях.

**Уязвимый вариант:**

**Основание:** museumorphosis, авторский разбор RuCTF: собственный SQL DSL и
плохая граница между запросом и выбором базы.
**Искать:** SQL внутри строк другого языка, regex вместо полноценного парсера,
пользовательский текст в LIKE, имя базы/tenant.

**Исправление:** параметры для значений на каждом уровне; выбор базы из проверенного
серверного tenant; однозначный парсер DSL. Экранирование внутреннего SQL
не доказывает безопасность внешнего языка.

**Проверка:** разделители обоих языков, обычные wildcard согласно контракту,
попытка сменить базу, доступ только к своему tenant.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/museumorphosis/README.md).

**Основание:** [первичный материал](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/museumorphosis/README.md).

<a id="sql-rls-disable"></a>

<a id="sql-rls-disable-postgresql-table-rls-disabled"></a>

## SQL-RLS-DISABLE. PostgreSQL RLS отключают для таблицы

**Поиск:** скрипт, правило SQL-RLS-DISABLE. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain SQL-RLS-DISABLE. Regex: ALTER TABLE ... DISABLE ROW LEVEL SECURITY. Отсутствие ENABLE, широкие политики и роль соединения не выводятся из текста.

**Уязвимый вариант:** Отключение RLS снимает серверную границу строк, если доступ полагается на политики.

~~~sql
ALTER TABLE notes DISABLE ROW LEVEL SECURITY;
~~~

**Исправление:** Установить нужные policies и включить RLS; runtime не должен быть superuser/BYPASSRLS. FORCE влияет на владельца, но не устраняет эти bypass-привилегии.

~~~sql
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE notes FORCE ROW LEVEL SECURITY;
-- Install reviewed owner/tenant policies before serving traffic.
~~~

**Проверка:** Проверить SELECT/INSERT/UPDATE/DELETE двумя runtime субъектами и чужим tenant; migration user отдельно.

Первичная документация: [документация 1](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).

<a id="sql-token-prefix"></a>

<a id="sql-token-prefix-secret-token-checked-by-prefix-or-range"></a>

## SQL-TOKEN-PREFIX. Секретный токен проверяется по префиксу или диапазону

**Поиск:** скрипт, правило SQL-TOKEN-PREFIX. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain SQL-TOKEN-PREFIX. Regex: nonce/token/reset_token/api_key перед LIKE, >= или <= в SQL-тексте. Числовые счётчики и поиск служебных журналов могут быть допустимы; переименованные поля, substr, startsWith и сравнение части в приложении искать вручную.

**Уязвимый вариант:** Если nonce/token является bearer-секретом, частичное совпадение резко уменьшает пространство проверки.

~~~sql
SELECT content FROM exports WHERE username = $1 AND nonce >= $2 AND nonce < $3;
~~~

**Исправление:** Требовать полный канонический токен допустимой длины, точное совпадение и связь с пользователем/действием/сроком; не заменять проверку rate limit.

~~~sql
SELECT content FROM exports WHERE username = $1 AND nonce = $2;
-- Before querying: require the full canonical token, correct length/type and purpose.
~~~

**Проверка:** Пустой, короткий, префиксный, лишний суффикс и токен другого пользователя отвергнуты; полный действующий токен работает.

Первичная документация: [документация 1](https://github.com/enowars/enowars10-service-flagdrive/blob/d1575098fe2c516460136bb5fba11d9a1c4af3f7/documentation/FLAGSTORE_0.md).


**Вариант A/D:** авторы FlagDrive (ENOWARS10) описали выбор экспорта по короткому префиксу nonce. Исправление требует полной длины и точного равенства; правило отмечает SQL-диапазон, а смысл bearer-секрета проверяется вручную.

<a id="sql-null-auth"></a>

<a id="sql-null-auth-null-changes-authorization-logic"></a>

## SQL-NULL-AUTH. NULL меняет смысл проверки доступа

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'NOT IN|!=|<>|IS NULL|IS NOT NULL|COALESCE|LEFT JOIN|owner|tenant' .
~~~

Составить таблицу TRUE/FALSE/UNKNOWN для auth-условия и результата LEFT JOIN. Проследить, как приложение превращает nullable bool в разрешение/отказ, есть ли NULL в NOT IN subquery.

**Уязвимый вариант:** Условие отказа owner <> actor даёт UNKNOWN при NULL, и приложение проваливается в разрешённую ветку; отсутствующая ACL трактуется как default allow.

**Исправление:** Разрешать доступ только при явно истинной положительной проверке. Где NULL недопустим — NOT NULL и целостная связь; где допустим — задать его точный смысл, не подменять владельца общим значением через COALESCE.

**Проверка:** NULL owner, отсутствующая ACL, пустой join и NULL внутри подзапроса не дают доступа; обычные own/shared сценарии сохраняются.

Основание: [первичная документация/материал](https://www.postgresql.org/docs/current/functions-comparison.html). Описание и рецепт адаптации составлены для этой базы.

<a id="sql-rls-allow-all"></a>

<a id="sql-rls-allow-all-rls-policy-has-an-unconditional-expression"></a>

## SQL-RLS-ALLOW-ALL. Безусловное выражение в политике RLS

**Поиск:** правило сканера SQL-RLS-ALLOW-ALL. Точный контракт детектора: `--explain SQL-RLS-ALLOW-ALL`. Regex с лексическими исключениями: USING(true) или WITH CHECK(true). Может быть намеренным; правило не связывает выражения с CREATE POLICY, ролями и командами. Фактические политики и авторизация приложения требуют проверки.

**Уязвимый вариант:**

~~~sql
CREATE POLICY open_notes ON notes USING (true);
~~~

**Исправление:** Определите выражения USING и WITH CHECK с учётом ролей и арендаторов для реальной модели идентификации; проверьте сочетания разрешающих политик и роли, обходящие RLS.

~~~sql
CREATE POLICY owned_notes ON notes USING (owner_id = current_user);
~~~

**Проверка:** Два пользователя времени исполнения не могут читать или менять строки друг друга; INSERT и UPDATE проверяют нужного владельца, а допустимые операции работают.

[Первичный источник 1](https://www.postgresql.org/docs/current/sql-createpolicy.html)

<a id="sql-server-role"></a>
<a id="sql-server-role-postgresql-server-fileprogram-role-granted"></a>

## SQL-SERVER-ROLE. Выданы роли PostgreSQL для файлов и программ сервера

**Поиск:** правило сканера SQL-SERVER-ROLE. Подробности: `--explain SQL-SERVER-ROLE`. Ограниченный SQL-поиск: GRANT списка ролей без кавычек, содержащего pg_read_server_files, pg_write_server_files или pg_execute_server_program перед TO. Комментарии/строки исключены; REVOKE и отдельный pg_monitor не дают сигнал. Quoted roles, наследование, поздние отзывы прав, версии и эффективные права проверяются вручную.

**Уязвимый вариант:**

~~~sql
GRANT pg_read_server_files TO app;
~~~

**Исправление:** Разделите роли приложения и администратора. Выдавайте необходимые права на объекты, а не файлы/программы сервера; проверяйте членство. Отзывайте только согласованные права своего сервиса с процедурой rollback.

~~~sql
GRANT SELECT ON notes TO app;
~~~

**Проверка:** Фактическая runtime-роль не читает/пишет файлы сервера и не запускает программы; обычные запросы, миграции и восстановление работают.

[Первичный источник](https://www.postgresql.org/docs/14/predefined-roles.html)
