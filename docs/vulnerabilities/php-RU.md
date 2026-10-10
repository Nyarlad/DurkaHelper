<a id="php-find-fix-and-verify"></a>

# PHP: поиск и исправление

[English](php.md) | Русский

[Вся база](README-RU.md) · [Сканер](../offline-scanner-RU.md) · [Проверка патча](../patch-validation-RU.md)

23 разделов. Формат: **Поиск → Уязвимый вариант → Исправление → Проверка**.
Команды `rg` выполняются в корне локальной копии сервиса и только читают файлы. Субъект/владелец определяется по проверенной сессии, а не данным запроса. Примеры нужно адаптировать к реальным API и контракту.

Автоматические находки — ограниченные синтаксические сигналы для проверки. AST-анализ не разрешает типы и не отслеживает данные между функциями; regex не заменяет парсер языка. Комментарии, строки и одноимённые пользовательские API могут давать совпадения. Проверьте фактическое исполнение, входные данные, авторизацию и границы доверия.

<a id="contents"></a>

## Содержание

- [PHP-SQL — Динамический SQL PHP](#php-sql)
- [PHP-OBJECT — unserialize внешних данных](#php-object)
- [PHP-SHELL — Исполнение текста PHP/команды](#php-shell)
- [PHP-INCLUDE — Клиентский путь include](#php-include)
- [PHP-PREFIX-MAC — Хеш конкатенации вместо MAC](#php-prefix-mac)
- [PHP-PARSE-STR — Нормализация ключей parse_str](#php-parse-str)
- [PHP-LOOSE-COMPARE — Нестрогое сравнение токена или подписи](#php-loose-compare)
- [PHP-UPLOAD — Перенос загруженного файла](#php-upload)
- [PHP-DISPLAY-ERRORS — PHP показывает ошибки клиенту](#php-display-errors)
- [PHP-XSS — HTML/атрибут/JS получают сырой текст](#php-xss)
- [PHP-SESSION — PHP session: fixation, strict mode, старое состояние](#php-session)
- [PHP-WRAPPERS — Файловый API принимает URL/wrapper](#php-wrappers)
- [PHP-EXTRACT — extract и variable variables подменяют контекст](#php-extract)
- [PHP-SERIALIZE-MAGIC — Magic methods и доверие данным из БД](#php-serialize-magic)
- [PHP-CSRF — Cookie авторизует изменяющий запрос без CSRF](#php-csrf)
- [PHP-REGEX-ERROR — Ошибка preg_match трактуется как разрешение](#php-regex-error)
- [PHP-XML-FLAGS — XML разрешает подстановку сущностей и DTD](#php-xml-flags)
- [PHP-TEMPLATE — Шаблон создаётся из динамического текста](#php-template)
- [PHP-CURL-TLS — cURL не проверяет сертификат или имя](#php-curl-tls)
- [PHP-URL-INCLUDE — Разрешён include удалённого ресурса](#php-url-include)
- [PHP-SESSION-CONFIG — Ослабленные настройки PHP-сессии](#php-session-config)
- [PHP-MASS-ASSIGN — Ключи массива выбирают колонки и права](#php-mass-assign)
- [PHP-LDAP-FILTER — LDAP-фильтр склеивается с PHP-переменной](#php-ldap-filter)

<a id="php-sql"></a>

<a id="php-sql-dynamic-php-sql"></a>

## PHP-SQL. Динамический SQL PHP

**Поиск:** скрипт, правило PHP-SQL. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PHP-SQL. Regex: query/exec/prepare со сборкой строки, double-quoted интерполяция, mysqli_query/pg_query с обычным аргументом соединения. Escaping, другие формы интерполяции и SQL из переменной полноценно не разбираются.

**Уязвимый вариант:**

~~~php
$db->query("SELECT id FROM notes WHERE name=" . $name);
~~~

**Исправление:** Prepared statements и связанные значения в API выбранного драйвера, например PDO prepare/execute; идентификаторы — из разрешённого набора, значения не подставлять вручную.

~~~php
$stmt = $db->prepare("SELECT id FROM notes WHERE name = ?");
$stmt->execute([$name]);
~~~

**Проверка:** Кавычки остаются данными; ограничения владельца сохраняются.

<details>
<summary>Развёрнутый пример и ограничения</summary>

```php
// Vulnerable: client input is interpolated into SQL.
$row = $pdo->query("SELECT body FROM notes WHERE id = '" . $_GET['id'] . "'")->fetch();
```

**Патч PDO для приватной заметки:**

```php
function readPrivateNote(PDO $pdo, ?int $userId, int $noteId): ?string {
    if ($userId === null) {
        throw new RuntimeException('authentication required');
    }
    $stmt = $pdo->prepare('SELECT body FROM notes WHERE id = :id AND owner_id = :owner');
    $stmt->bindValue(':id', $noteId, PDO::PARAM_INT);
    $stmt->bindValue(':owner', $userId, PDO::PARAM_INT);
    $stmt->execute();
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row === false ? null : $row['body'];
}
```

До функции валидировать числовой ID: `(int) $_GET['id']` молча преобразует часть
некорректных строк. Настроить обработку ошибок PDO; не возвращать клиенту текст
SQL-исключения. Маркеры предназначены для значений, не имён таблиц/столбцов.
Для поддерживающего драйвера можно использовать native prepares; не менять
режим всего приложения вслепую, поскольку поведение драйверов различается.

**Проверить:** своё/чужое/нет сессии; отсутствующая запись; неверный ID; поиск
другого строкового поля с апострофом не ломается. Сохранить общий доступ, если он есть.

</details>

<a id="php-object"></a>

<a id="php-object-untrusted-php-unserialize"></a>

## PHP-OBJECT. unserialize внешних данных

**Поиск:** скрипт, правило PHP-OBJECT. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PHP-OBJECT. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~php
$value = unserialize($data);
~~~

**Исправление:** JSON со схемой; совместимость старого формата отдельно. allowed_classes=false не заменяет схему.

~~~php
$value = json_decode($data, true, 32, JSON_THROW_ON_ERROR); // validate schema
~~~

**Проверка:** Объекты PHP не создаются; старые данные учтены.

<details>
<summary>Развёрнутый пример и ограничения</summary>

```php
// Vulnerable with untrusted input: object restoration has side effects.
$profile = unserialize($_COOKIE['profile']);
```

**Патч для простого профиля при совместимом JSON-контракте:**

```php
function decodeProfile(string $raw): array {
    $value = json_decode($raw, false, 32, JSON_THROW_ON_ERROR);
    if (!($value instanceof stdClass)) {
        throw new InvalidArgumentException('object required');
    }
    $fields = get_object_vars($value);
    if (array_keys($fields) !== ['display_name'] || !is_string($fields['display_name'])) {
        throw new InvalidArgumentException('unexpected profile fields');
    }
    return ['display_name' => $fields['display_name']];
}
```

Глубина 32 — пример ограничения, не требование игры; размер тела ограничивать
до парсинга по контракту. `role` и владелец задаются сервером. PHP прямо
предостерегает от `unserialize` недоверенных данных даже с `allowed_classes`:
один этот флаг не считать полным исправлением.

**Проверить:** корректный профиль, неизвестное поле, массив вместо объекта,
неверный тип и ошибка JSON. Переход формата требует совместимости старых клиентов
и данных; не оставлять fallback на `unserialize` для строки клиента.

</details>

<a id="php-shell"></a>

<a id="php-shell-php-code-or-shell-execution"></a>

## PHP-SHELL. Исполнение текста PHP/команды

**Поиск:** скрипт, правило PHP-SHELL. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PHP-SHELL. Regex: eval/shell_exec/system/passthru/popen/exec и строковый/переменный proc_open. Literal argv-массив proc_open в первом аргументе, также с command: в PHP 8+, не помечается, кроме явного shell; массив поддержан PHP 7.4+. Исполняемый файл и опасные опции проверить вручную. Переставленные named arguments, backticks, variable functions, wrappers и действующая версия PHP требуют ручного анализа; одноимённые пользовательские функции и комментарии могут совпадать.

**Уязвимый вариант:**

~~~php
shell_exec($command);
~~~

**Исправление:** Библиотечная операция вместо shell; иначе фиксированные argv через API без оболочки.

~~~php
$size = filesize($checkedPath);
~~~

**Проверка:** Штатная функция сохранена; текст не исполняется.

`proc_open` принимает argv-массив начиная с PHP 7.4; именованный `command:` —
с PHP 8.0. Массив передаётся процессу без неявной оболочки. Для действительно
нужной утилиты можно сохранить вызов без shell, например на PHP 8+:

~~~php
$process = proc_open(
    command: ['/usr/bin/file', '--', $checkedName],
    descriptor_spec: $descriptors,
    pipes: $pipes
);
~~~

Здесь путь к executable фиксирован, а `$checkedName` должен пройти проверку
доступа и допустимого пути. `--` подходит только утилите, поддерживающей такой
разделитель. `command: array('/usr/bin/file', '--', $checkedName)` также не
получает PHP-SHELL. Исключение ограничено первым аргументом с литеральной
формой массива; перестановка именованных аргументов и массив из переменной
остаются сигналами для просмотра.
[proc_open: массив и ограничения Windows](https://github.com/php/doc-en/blob/master/reference/exec/functions/proc-open.xml#L68),
[PHP 8: именованные аргументы](https://www.php.net/manual/en/migration80.new-features.php#migration80.new-features.core.named-arguments),
[сигнатура proc_open в PHP 8.0](https://github.com/php/php-src/blob/php-8.0.0/ext/standard/basic_functions.stub.php#L1156).

Явный запуск shell сохраняет риск и сигнал даже при массиве:

~~~php
$process = proc_open(command: ['sh', '-c', $command], descriptor_spec: $descriptors, pipes: $pipes);
~~~

Не превращать pipeline в argv простым разделением строки: перенести нужные
операции в библиотеку либо явно связать процессы. Проверить executable,
опции, `PATH`, рабочий каталог и окружение. На Windows экранирование массива
рассчитано на совместимый с VC runtime разбор командной строки; произвольный
parser программы может иметь другой контракт. Закрывать pipes и процесс,
проверять ошибки, лимиты времени/вывода и прежний формат результата.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'proc_open|proc_close|proc_terminate|shell_exec|descriptor_spec|bypass_shell' .
~~~

После совпадения проследить реальный argv и источник каждого аргумента.
В разрешённом тестовом окружении проверить пробелы, кавычки, имя с ведущим
дефисом, штатный файл и ошибку процесса. Отсутствие PHP-SHELL не доказывает
безопасность аргументов. Здесь проверены исходники и поведение сканера;
PHP runtime и найденные команды не запускались.

<a id="php-include"></a>

<a id="php-include-client-selected-include-path"></a>

## PHP-INCLUDE. Клиентский путь include

**Поиск:** скрипт, правило PHP-INCLUDE. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PHP-INCLUDE. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~php
include $_GET['page'];
~~~

**Исправление:** Фиксированная таблица разрешённых модулей; пользовательский текст хранить как данные.

~~~php
$pages = ['home' => __DIR__ . '/pages/home.php'];
if (!isset($pages[$page])) { throw new Exception('bad page'); }
include $pages[$page];
~~~

**Проверка:** Неизвестные имена/пути отвергаются; штатные страницы работают.

<details>
<summary>Развёрнутый пример и ограничения</summary>

```php
// Vulnerable: the client controls the executable PHP file path.
include $_GET['page'];
```

**Патч, если контракт — выбор одной из известных страниц:**

```php
$pages = [
    'help' => __DIR__ . '/pages/help.php',
    'profile' => __DIR__ . '/pages/profile.php',
];
$page = $_GET['page'] ?? 'help';
if (!is_string($page) || !array_key_exists($page, $pages)) {
    http_response_code(404);
    exit;
}
require $pages[$page];
```

Пути заданы сервером. Требования авторизации `profile` остаются обязательными
до выдачи приватных данных. `basename()` не ограничивает пользователя нужным
набором страниц и не решает права. Если функция обещает загрузку пользовательского
файла, `include` вообще не должен использоваться для его отображения.

**Проверить:** обе штатные страницы, неизвестное имя, массив вместо page;
закрытая страница не открывается анониму; меняется только допустимый выбор страницы.

</details>

<a id="php-prefix-mac"></a>

<a id="php-prefix-mac-hash-concatenation-instead-of-mac"></a>

## PHP-PREFIX-MAC. Хеш конкатенации вместо MAC

**Поиск:** скрипт, правило PHP-PREFIX-MAC. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PHP-PREFIX-MAC. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~php
$tag = sha1($key . $payload);
~~~

**Исправление:** HMAC с секретом вместо sha1(secret || data). Проверять тег через hash_equals; версионировать формат и спланировать переход старых токенов.

~~~php
$tag = hash_hmac('sha256', $payload, $key);
~~~

**Проверка:** Изменение/добавление данных не проходит; подпись охватывает назначение и все auth-поля.

**Вариант A/D:** Secret-prefix hash ошибочно назван HMAC. **ECSC / Diese, автор + код.** Подпись построена как SHA1 от secret || data.
**Патч:** настоящий HMAC и версия токена; безопасный переход старых подписей.
**Тест:** изменение/добавление полей не принимается.
**Поиск:** PHP-PREFIX-MAC; имя функции hmac само по себе ничего не гарантирует.

[исходник/разбор 1](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/README.md); [исходник/разбор 2](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/webapp/src/classes/Utils.class.php); [исходник/разбор 3](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/hsm/src/msg.c).

<a id="php-parse-str"></a>

<a id="php-parse-str-parse_str-key-normalization"></a>

## PHP-PARSE-STR. Нормализация ключей parse_str

**Поиск:** скрипт, правило PHP-PARSE-STR. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PHP-PARSE-STR. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~php
parse_str($token_data, $params);
~~~

**Исправление:** Явная схема и allowlist полей до подписи и после разбора; учесть преобразование точек/пробелов в underscore, массивы и дубли ключей.

~~~php
$params = parse_and_validate_canonical_share_dto($token_data); // one schema, duplicate policy, server-owned fields
~~~

**Проверка:** Разные написания поля не меняют owner/doc_id; signer и verifier разбирают одинаково.

**Вариант A/D:** Нормализация ключей параметров после подписи. **ECSC / Diese, автор + код.** parse_str превращает некоторые разные имена
в одинаковые, меняя смысл полей.
**Патч:** allowlist и одна каноническая DTO-схема у signer/verifier; запрет
неоднозначных дублей. **Тест:** точки, пробелы, underscore и массивы.
**Поиск:** PHP-PARSE-STR; сам вызов не обязательно уязвим.

[исходник/разбор 1](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/README.md); [исходник/разбор 2](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/webapp/src/classes/Utils.class.php); [исходник/разбор 3](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/hsm/src/msg.c).

<a id="php-loose-compare"></a>

<a id="php-loose-compare-loose-comparison-of-token-or-signature"></a>

## PHP-LOOSE-COMPARE. Нестрогое сравнение токена или подписи

**Поиск:** скрипт, правило PHP-LOOSE-COMPARE. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PHP-LOOSE-COMPARE. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~php
$ok = $token == $provided;
~~~

**Исправление:** Проверить тип; для тега hash_equals, для обычного значения ===, для пароля password_verify. Семантика числовых строк зависит от версии и операндов.

~~~php
$ok = is_string($provided) && hash_equals($token, $provided);
~~~

**Проверка:** Число/массив/числовая строка не превращаются в авторизацию; правильное значение принимается.

**Основание:** [первичный материал](https://www.php.net/manual/en/language.operators.comparison.php).

<a id="php-upload"></a>

<a id="php-upload-moving-an-uploaded-file"></a>

## PHP-UPLOAD. Перенос загруженного файла

**Поиск:** скрипт, правило PHP-UPLOAD. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PHP-UPLOAD. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~php
move_uploaded_file($tmp, $webroot . $name);
~~~

**Исправление:** Проверять upload error/размер/тип, серверное имя и отсутствие перезаписи, хранить вне исполняемого webroot; выдавать после auth.

~~~php
move_uploaded_file($validatedTmp, $serverChosenPrivatePath);
~~~

**Проверка:** Обычный upload/download, коллизия имени, чужой owner, неверный тип и полный диск. Вызов остаётся сигналом.

**Основание:** [первичный материал](https://www.php.net/manual/en/features.file-upload.php).

<a id="php-display-errors"></a>

<a id="php-display-errors-php-displays-errors-to-clients"></a>

## PHP-DISPLAY-ERRORS. PHP показывает ошибки клиенту

**Поиск:** скрипт, правило PHP-DISPLAY-ERRORS. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PHP-DISPLAY-ERRORS. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~php
display_errors = On
~~~

**Исправление:** Отключить клиентский вывод, включить локальный журнал без секретов; проверить эффективный php.ini/FPM pool и runtime ini_set.

~~~php
display_errors = Off
~~~

**Проверка:** Parse/DB/type error дают штатный ответ, диагностика сохраняется.

**Основание:** [первичный материал](https://www.php.net/manual/en/errorfunc.configuration.php).

<a id="php-xss"></a>

<a id="php-xss-raw-data-reaches-html-attributes-or-javascript"></a>

## PHP-XSS. HTML/атрибут/JS получают сырой текст

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'echo|print|htmlspecialchars|json_encode|<script' .
~~~

Определить контекст вывода; htmlspecialchars для текста не делает строку безопасным JavaScript.

**Уязвимый вариант:**

echo $title внутри HTML без encoding; вставка JSON в script без подходящего сериализатора.

**Исправление:** Autoescape шаблона или htmlspecialchars с ENT_QUOTES/ENT_SUBSTITUTE и UTF-8 для HTML; отдельное безопасное кодирование JS/URL.

**Проверка:** Кавычки/теги/Unicode показываются как данные; легитимное форматирование не ломается.

<details>
<summary>Развёрнутый пример и ограничения</summary>

```php
// Vulnerable with untrusted title: the browser interprets it as markup.
echo '<p>' . $title . '</p>';
```

**Патч для текстового содержимого HTML:**

```php
echo '<p>' . htmlspecialchars($title, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</p>';
```

`$title` перед этим проверен как строка. Сохранить исходный текст в БД и кодировать
при выводе. Иначе повторное редактирование может накопить двойное экранирование.
Этот пример не является кодированием JavaScript, CSS или проверкой URL; для этих
контекстов другой механизм. Разрешённый по контракту HTML требует очистки
допустимого подмножества, а не превращения всей разметки в текст.

**Проверить:** `<`, `>`, `&`, кавычки и Unicode показываются текстом; старая запись
и цикл «сохранить → открыть → изменить» сохраняют исходное содержание.

</details>

<a id="php-session"></a>

<a id="php-session-session-fixation-strict-mode-and-stale-state"></a>

## PHP-SESSION. PHP session: fixation, strict mode, старое состояние

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'session_start|session_regenerate_id|session.use_strict_mode|session_id' .
~~~

Проследить принятие внешнего ID, регенерацию при login и запись роли в session.

**Уязвимый вариант:**

Внешний неизвестный ID принимается, после входа остаётся тем же.

**Исправление:** session.use_strict_mode, штатная регенерация с учётом concurrent requests, серверная роль; согласованные Secure/HttpOnly/SameSite.

**Проверка:** Прежний ID не авторизует, обычные параллельные запросы не теряют состояние.

**Основание:** [первичный материал](https://www.php.net/manual/en/session.security.ini.php).

<a id="php-wrappers"></a>

<a id="php-wrappers-filesystem-apis-accept-urls-or-wrappers"></a>

## PHP-WRAPPERS. Файловый API принимает URL/wrapper

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'file_get_contents|fopen|copy\(|file_exists|is_file|phar|stream_context' .
~~~

Проверить, что API принимает путь или stream URL; сопоставить версию PHP и нужные wrappers.

**Уязвимый вариант:**

Пользователь выбирает схему/локальный путь вместо разрешённого объекта; open_basedir не является полным sandbox.

**Исправление:** Серверный путь из авторизованного ID; для HTTP отдельный клиент с URL policy; запрет клиентского выбора wrapper.

**Проверка:** Штатный файл читается, внешний URL/чужой файл/нестандартная схема не достигают операции.

<a id="php-extract"></a>

<a id="php-extract-extract-overwrites-local-variables"></a>

## PHP-EXTRACT. extract и variable variables подменяют контекст

**Поиск:** скрипт, правило PHP-EXTRACT. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PHP-EXTRACT. Regex: любой extract(...); доверенные шаблонные контексты требуют ручной классификации.

Дополнительный ручной поиск для непокрытых форм:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'extract\(|parse_str|\$\$|GLOBALS|register_globals' .
~~~

Сравнить импортируемые ключи с именами auth/config переменных; двухаргументный parse_str имеет иной риск, чем старое поведение.

**Уязвимый вариант:**

extract($_REQUEST) перезаписывает локальные переменные либо $$key выбирает чувствительное имя.

**Исправление:** Явно читать разрешённые поля в отдельный DTO; не импортировать клиентские ключи в symbol table. EXTR_SKIP уменьшает перезаписи, но не заменяет проверку схемы, типов и новых имён.

**Проверка:** role, authorized, путь и конфигурация не меняются при лишних ключах.

**Основание:** [первичный материал](https://www.php.net/manual/en/function.extract.php).


**Сигнал сканера — пример до:**

~~~php
extract($_POST);
if ($is_admin) { show_private_data(); }
~~~

**Шаблон исправления:**

~~~php
$display_name = validate_display_name($_POST['display_name'] ?? '');
~~~

Первичная документация: [документация 1](https://www.php.net/manual/en/function.extract.php).

<a id="php-serialize-magic"></a>

<a id="php-serialize-magic-magic-methods-and-trust-in-stored-data"></a>

## PHP-SERIALIZE-MAGIC. Magic methods и доверие данным из БД

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e '__wakeup|__unserialize|__destruct|__toString|unserialize' .
~~~

От места PHP-OBJECT пройти reachable classes и побочные эффекты; БД не становится доверенной после клиентской записи.

**Уязвимый вариант:**

Десериализованный объект вызывает файловую/сетевую операцию до проверки результата.

**Исправление:** DTO без выбора класса и побочных эффектов; совместимая миграция отдельно, не fallback на небезопасный parser.

**Проверка:** Неизвестный тип не вызывает эффектов; старый допустимый формат читается по плану.

<a id="php-csrf"></a>

<a id="php-csrf-cookies-authorize-mutations-without-csrf-protection"></a>

## PHP-CSRF. Cookie авторизует изменяющий запрос без CSRF

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'csrf|POST|PUT|DELETE|REQUEST_METHOD|SameSite' .
~~~

Проверить формы и JSON endpoint с cookie auth, исключения middleware и Origin/Referer policy.

**Уязвимый вариант:**

Браузер автоматически прикладывает cookie к изменению состояния из чужого контекста.

**Исправление:** Штатный CSRF token и проверка origin по архитектуре; SameSite дополняет, не заменяет серверную проверку. Bearer API имеет другой контекст.

**Проверка:** Неверный/отсутствующий token отклоняется; нормальная форма и предусмотренные API-клиенты работают.

<a id="php-regex-error"></a>

<a id="php-regex-error-preg_match-errors-become-permission"></a>

## PHP-REGEX-ERROR. Ошибка preg_match трактуется как разрешение

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'preg_match|preg_last_error|preg_replace' .
~~~

Различить false, 0 и 1; найти отрицание результата и лимиты regex.

**Уязвимый вариант:**

Ошибка движка при длинном вводе попадает в ветвь «запрещённое не найдено».

**Исправление:** Проверять результат === 1/0/false по смыслу, fail closed при ошибке; ограничить длину и сложность.

**Проверка:** Match/no-match/ошибка движка дают разные ожидаемые ответы, штатный Unicode поддержан.

**Основание:** [первичный материал](https://www.php.net/manual/en/function.preg-match.php).

<a id="php-xml-flags"></a>

<a id="php-xml-flags-xml-entity-substitution-or-dtd-enabled"></a>

## PHP-XML-FLAGS. XML разрешает подстановку сущностей и DTD

**Поиск:** скрипт, правило PHP-XML-FLAGS. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PHP-XML-FLAGS. Regex: LIBXML_NOENT/DTDLOAD/DTDATTR/DTDVALID и substituteEntities/resolveExternals=true. Числовые маски из ini/БД не распознаются: вручную сопоставить каждый бит с константами runtime.

**Уязвимый вариант:** NOENT означает подстановку сущностей, а NONET сам по себе не запрещает доступ к локальному файлу.

~~~php
$doc->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_NONET);
~~~

**Исправление:** Убрать подстановку/загрузку внешних DTD, установить лимиты и проверить версию libxml. На поддерживаемом runtime добавить LIBXML_NO_XXE; не полагаться на один NONET.

~~~php
$doc->resolveExternals = false;
$doc->substituteEntities = false;
$doc->loadXML($boundedXml, LIBXML_NONET);
~~~

**Проверка:** Обычный XML разбирается; внешний DTD/сущность не читает файл и не делает сетевой запрос, объём/вложенность ограничены.

Первичная документация: [документация 1](https://www.php.net/manual/en/libxml.constants.php), [документация 2](https://github.com/enowars/enowars7-service-oldschool#vulnerabilities).

<a id="php-template"></a>

<a id="php-template-template-built-from-dynamic-text"></a>

## PHP-TEMPLATE. Шаблон создаётся из динамического текста

**Поиск:** скрипт, правило PHP-TEMPLATE. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PHP-TEMPLATE. Regex: createTemplate($...) и Smarty display/fetch с eval: или string:. Переменные loaders, custom filters и шаблоны из БД просматривать вручную.

**Уязвимый вариант:** Если пользовательские данные становятся исходником шаблона, возможности template engine становятся доступными пользователю.

~~~php
$template = $twig->createTemplate($profileText);
echo $template->render($vars);
~~~

**Исправление:** Разделить доверенный шаблон и параметры; если продукт допускает шаблоны, отдельно ограничить sandbox, loader, доступные функции и ресурсы.

~~~php
echo $twig->render('profile.html.twig', ['about' => $profileText]);
~~~

**Проверка:** Текст шаблонных выражений в профиле отображается как данные; приватные шаблоны/файлы недоступны.

Первичная документация: [документация 1](https://twig.symfony.com/doc/3.x/api.html#loading-templates-from-a-string).

<a id="php-curl-tls"></a>

<a id="php-curl-tls-curl-certificate-or-hostname-checks-disabled"></a>

## PHP-CURL-TLS. cURL не проверяет сертификат или имя

**Поиск:** скрипт, правило PHP-CURL-TLS. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PHP-CURL-TLS. Regex: CURLOPT_SSL_VERIFYPEER=false/0 и CURLOPT_SSL_VERIFYHOST=false/0/1, аргумент или setopt_array. Значения из переменных не вычисляются.

**Уязвимый вариант:** Отключение проверки сервера позволяет подменить результат исходящего HTTPS-запроса.

~~~php
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
~~~

**Исправление:** Проверять peer и hostname, настроить доверенный CA. На VERIFYHOST использовать 2, не исторически неоднозначное 1.

~~~php
curl_setopt_array($ch, [CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_CAINFO => $trustedCA]);
~~~

**Проверка:** Верный CA/hostname работает, чужой hostname/CA и истёкший сертификат дают ошибку без fallback.

Первичная документация: [документация 1](https://www.php.net/manual/en/function.curl-setopt.php).

<a id="php-url-include"></a>

<a id="php-url-include-remote-resource-inclusion-enabled"></a>

## PHP-URL-INCLUDE. Разрешён include удалённого ресурса

**Поиск:** скрипт, правило PHP-URL-INCLUDE. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PHP-URL-INCLUDE. Regex: allow_url_include=On/1/true в ini/config или присваивании. Runtime overrides и фактический include path проверять отдельно.

**Уязвимый вариант:** URL include расширяет последствия управления путём PHP include/require.

~~~config
allow_url_include = On
~~~

**Исправление:** Отключить allow_url_include в действующей конфигурации SAPI; пути подключений выбирать из закрытой серверной таблицы.

~~~config
allow_url_include = Off
~~~

**Проверка:** Приложение загружает штатные модули; пользовательский URL не становится исполняемым кодом.

Первичная документация: [документация 1](https://www.php.net/manual/en/filesystem.configuration.php#ini.allow-url-include).

<a id="php-session-config"></a>

<a id="php-session-config-weakened-php-session-configuration"></a>

## PHP-SESSION-CONFIG. Ослабленные настройки PHP-сессии

**Поиск:** скрипт, правило PHP-SESSION-CONFIG. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PHP-SESSION-CONFIG. Regex: явные опасные значения use_strict_mode/use_only_cookies/use_trans_sid. Пропущенные настройки и ini_set с аргументами остаются ручными.

**Уязвимый вариант:** Принятие навязанного session id и перенос id в URL создают фиксацию/утечку сессии.

~~~config
session.use_strict_mode = 0
session.use_only_cookies = 0
session.use_trans_sid = 1
~~~

**Исправление:** Включить strict mode и cookie-only transport, отключить URL rewriting; при auth сменить id, проверить custom session handler и флаги cookie.

~~~config
session.use_strict_mode = 1
session.use_only_cookies = 1
session.use_trans_sid = 0
~~~

**Проверка:** Навязанный неизвестный id не принимается, после login id меняется; URL/логи не содержат id, штатная сессия сохраняется.

Первичная документация: [документация 1](https://www.php.net/manual/en/session.configuration.php).

<a id="php-mass-assign"></a>

<a id="php-mass-assign-array-keys-choose-columns-and-privileges"></a>

## PHP-MASS-ASSIGN. Ключи массива выбирают колонки и права

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e '\$_(POST|GET|REQUEST)|array_keys|array_merge|profileData|UPDATE|SET|fill\(|update\(' .
~~~

Проследить не только значения, но и ключи массива от запроса до UPDATE/ORM и назначения owner/admin/association. Проверить вложенные поля и числовые индексы.

**Уязвимый вариант:** Параметризованы значения SQL, но имена колонок берутся из пользовательского массива; поле роли или связи с чужим объектом массово обновляется.

**Исправление:** Явно сопоставить разрешённые входные поля фиксированным колонкам и типам. Права, owner и связи проверять отдельно; placeholders не экранируют SQL identifiers.

**Проверка:** Неизвестная колонка, служебное поле и чужая связь отклонены без изменения состояния; разрешённые поля сохраняются.

Основание: [OWASP Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html). Описание и рецепт адаптации составлены для этой базы.

**Вариант A/D:** в Oldschool массовое обновление позволяло менять служебную связь; имена колонок также попадали в SQL без ограничения. [Авторское описание](https://github.com/enowars/enowars7-service-oldschool#vulnerabilities).

<a id="php-ldap-filter"></a>

<a id="php-ldap-filter-ldap-filter-concatenates-a-php-variable"></a>

## PHP-LDAP-FILTER. LDAP-фильтр склеивается с PHP-переменной

**Поиск:** правило сканера PHP-LDAP-FILTER. Точный контракт детектора: `--explain PHP-LDAP-FILTER`. Regex с лексическими исключениями: ldap_search/list/read с простыми первыми двумя аргументами и строкой, напрямую объединённой с переменной в третьем аргументе. Переменная может уже быть экранирована; заранее собранные фильтры и интерполяция требуют ручной проверки.

**Уязвимый вариант:**

~~~php
ldap_search($conn, $base, '(uid=' . $name . ')');
~~~

**Исправление:** Экранируйте значения для контекста LDAP-фильтра, а не DN; имена атрибутов и область поиска должны быть доверенными.

~~~php
$filter = '(uid=' . ldap_escape($name, '', LDAP_ESCAPE_FILTER) . ')';
ldap_search($conn, $base, $filter);
~~~

**Проверка:** Метасимволы LDAP в значении не расширяют результат; разрешённые поисковые запросы работают.

[Первичный источник 1](https://www.php.net/manual/en/function.ldap-escape.php)
