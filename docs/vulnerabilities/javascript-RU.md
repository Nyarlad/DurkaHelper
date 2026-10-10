<a id="javascript--typescript-find-fix-and-verify"></a>

# JavaScript / TypeScript: поиск и исправление

[English](javascript.md) | Русский

[Вся база](README-RU.md) · [Сканер](../offline-scanner-RU.md) · [Проверка патча](../patch-validation-RU.md)

28 разделов. Формат: **Поиск → Уязвимый вариант → Исправление → Проверка**.
Команды `rg` выполняются в корне локальной копии сервиса и только читают файлы. Субъект/владелец определяется по проверенной сессии, а не данным запроса. Примеры нужно адаптировать к реальным API и контракту.

Автоматические находки — ограниченные синтаксические сигналы для проверки. AST-анализ не разрешает типы и не отслеживает данные между функциями; regex не заменяет парсер языка. Комментарии, строки и одноимённые пользовательские API могут давать совпадения. Проверьте фактическое исполнение, входные данные, авторизацию и границы доверия.

<a id="contents"></a>

## Содержание

- [JS-SHELL — Shell API Node.js](#js-shell)
- [JS-EVAL — Динамический JavaScript](#js-eval)
- [JS-SQL — Динамический SQL Node.js](#js-sql)
- [JS-NOSQL — Тело запроса как фильтр MongoDB](#js-nosql)
- [JS-MASS-ASSIGN — Массовое присваивание](#js-mass-assign)
- [JS-PROTOTYPE — Глубокое слияние недоверенного объекта](#js-prototype)
- [JS-TLS — TLS отключён в Node.js](#js-tls)
- [JS-HTML — HTML sink](#js-html)
- [JS-TRUST-PROXY — Полное доверие proxy-заголовкам](#js-trust-proxy)
- [JS-CURL-ARGV — curl из Node.js: проверить опции и URL](#js-curl-argv)
- [JS-SESSION-STATE — Изменение чувствительного состояния сессии](#js-session-state)
- [JS-VM — node:vm используется как security sandbox](#js-vm)
- [JS-REGEX-DYNAMIC — Regex создаётся из клиентского текста](#js-regex-dynamic)
- [JS-TYPE-ASSERTION — TypeScript as не валидирует JSON](#js-type-assertion)
- [JS-AWAIT-AUTH — Забытый await у проверки прав](#js-await-auth)
- [JS-WEBSOCKET — WebSocket: права только на handshake](#js-websocket)
- [JS-GRAPHQL — GraphQL: resolver и batching обходят общий guard](#js-graphql)
- [JS-SESSION-FIXATION — Сессия не меняется после входа](#js-session-fixation)
- [JS-SSRF — fetch/axios: redirect и повторное DNS-разрешение](#js-ssrf)
- [JS-BUFFER-EXPOSURE — Неинициализированная память в Buffer](#js-buffer-exposure)
- [JS-JWT-DECODE — JWT декодируется без проверки подписи](#js-jwt-decode)
- [JS-JWT-OPTIONS — Ослабленные параметры JWT](#js-jwt-options)
- [JS-HTTP-PARSER — Ослабленный HTTP parser Node.js](#js-http-parser)
- [JS-STATIC-DOTFILES — Статика разрешает скрытые файлы](#js-static-dotfiles)
- [JS-QUERY-SHAPE — Параметр меняет тип между middleware](#js-query-shape)
- [JS-MIDDLEWARE-TRUST — Обработчик доверяет выполнению middleware](#js-middleware-trust)
- [JS-REDIRECT-INPUT — Поле запроса напрямую передаётся в Express-подобный redirect](#js-redirect-input)

- [JS-LOG-CREDENTIALS — Credentials напрямую передаются в console](#js-log-credentials)

<a id="js-shell"></a>

<a id="js-shell-shell-api-nodejs"></a>

## JS-SHELL. Shell API Node.js

**Поиск:** скрипт, правило JS-SHELL. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JS-SHELL. Regex: exec/execSync без receiver, распространённые child_process/cp receiver, shell:true или непустая строка shell, буквальный shell у spawn/execFile. Дополнительно статические ESM/CommonJS imports child_process с aliases и строковым bracket-access. Произвольный object.exec не считается процессом. Imports — подсказка без scope/type/data-flow анализа: комментарии, shadowing и reassignment могут дать ложный сигнал; wrappers и dynamic import требуют ручного просмотра.

**Уязвимый вариант:**

~~~javascript
child_process.exec(command);
~~~

**Исправление:** execFile/spawn с shell:false, фиксированным executable, проверенными argv и ограничением времени исполнения.

~~~javascript
child_process.execFile('/usr/bin/file', ['--', filename], {timeout: 3000}, callback);
~~~

**Проверка:** Спецсимволы остаются данными; опасные опции отклоняются; штатные команды работают.

<details>
<summary>Развёрнутый пример и ограничения</summary>

```javascript
// Vulnerable: a shell interprets the command string.
exec("printf '%s' '" + req.body.text + "' | sha256sum", callback);
```

**Патч для хеша содержимого:**

<!-- example: js-sha256 -->
```javascript
const { createHash } = require("node:crypto");

function digestText(text) {
  if (typeof text !== "string") throw new TypeError("string required");
  return createHash("sha256").update(text, "utf8").digest("hex");
}
```

Для ESM использовать `import { createHash } from "node:crypto"`.
Сохранить кодировку и внешний формат результата. Если внешняя программа
действительно нужна, фиксировать executable и аргументы отдельно; даже
`execFile` не запрещает вредную опцию самой программы автоматически.

**Проверить:** известный digest, пустая строка, Unicode, кавычки и переводы строк;
нет дочернего процесса. SHA-256 сам по себе не подходит для хранения паролей.

</details>

<a id="js-eval"></a>

<a id="js-eval-dynamic-javascript-execution"></a>

## JS-EVAL. Динамический JavaScript

**Поиск:** скрипт, правило JS-EVAL. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JS-EVAL. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~javascript
const value = eval(input);
~~~

**Исправление:** JSON.parse + схема для данных; ограниченный парсер для выражений.

~~~javascript
const value = JSON.parse(input); // validate schema
~~~

**Проверка:** Выражения не исполняются; размер/структура ограничены.

<a id="js-sql"></a>

<a id="js-sql-dynamic-nodejs-sql"></a>

## JS-SQL. Динамический SQL Node.js

**Поиск:** правило сканера JS-SQL. Подробности: `--explain JS-SQL`. Старый regex с исключением комментариев/строк: строковая сборка query/execute или text/sql objects (receiver без определения типа). Ограниченный анализ токенов также распознаёт прямое свойство req/request.body/query/params как SQL у pg Pool/Client или mysql/mysql2 createPool/createConnection через default/namespace import. Именованные импорты, полученные соединения, SQL-переменные, tagged templates, wrappers и потоки между файлами требуют ручной проверки.

**Уязвимый вариант:**

~~~javascript
db.query("SELECT id FROM notes WHERE name=" + name);
~~~

**Исправление:** Параметризовать значения синтаксисом драйвера; identifiers по allowlist.

~~~javascript
db.query("SELECT id FROM notes WHERE name=?", [name]);
~~~

**Проверка:** Кавычки — данные; owner_id сохраняется.

<details>
<summary>Развёрнутый пример и ограничения</summary>

```javascript
// Vulnerable: client input controls the query and ownership is unchecked.
const result = await pool.query(`SELECT body FROM notes WHERE id = '${req.params.id}'`);
```

**Патч для node-postgres (`pg`) и приватных заметок:**

<!-- example: js-read-note -->
```javascript
async function readPrivateNote(pool, currentUserId, noteId) {
  if (currentUserId == null) throw new Error("authentication required");
  const result = await pool.query(
    "SELECT body FROM notes WHERE id = $1 AND owner_id = $2",
    [noteId, currentUserId]
  );
  if (result.rows.length === 0) return null;
  return result.rows[0].body;
}
```

`null` здесь означает отсутствие доступного объекта; маршрут преобразует его
в принятый API ответ. Имена колонок/направление сортировки выбирать из фиксированной
карты, не принимать как текст запроса. Маркеры `$1` относятся к PostgreSQL,
не ко всем JS-драйверам.

**Проверить:** своё читается, чужое не возвращается; апостроф в строковом поле
остаётся данными; ошибочный тип не превращается в запрос другого смысла;
отказ не содержит тела чужой заметки.

</details>

<a id="js-nosql"></a>

<a id="js-nosql-request-body-used-as-a-mongodb-filter"></a>

## JS-NOSQL. Тело запроса как фильтр MongoDB

**Поиск:** скрипт, правило JS-NOSQL. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JS-NOSQL. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~javascript
collection.findOne(req.body);
~~~

**Исправление:** Собрать фиксированный фильтр из проверенных скаляров и server-side owner_id.

~~~javascript
if (typeof req.body.name !== 'string') throw new Error('invalid');
collection.findOne({name: req.body.name, ownerId: currentUser.id});
~~~

**Проверка:** Объект/массив вместо строки отвергается; клиент не выбирает владельца.

<details>
<summary>Развёрнутый пример и ограничения</summary>

```javascript
// Vulnerable: title may be an operator object rather than a string.
const note = await notes.findOne({ ownerId: currentUserId, title: req.body.title });
```

**Патч:** проверить тип и собрать фильтр самостоятельно. Пример для документа,
где `ownerId` уже имеет ожидаемый тип идентификатора из доверенного контекста.

<!-- example: js-title-filter -->
```javascript
function privateTitleFilter(currentUserId, body) {
  if (currentUserId == null) throw new Error("authentication required");
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    throw new TypeError("object required");
  }
  if (!Object.prototype.hasOwnProperty.call(body, "title") || typeof body.title !== "string") {
    throw new TypeError("title must be a string");
  }
  return { ownerId: currentUserId, title: body.title };
}
// In the handler: await notes.findOne(privateTitleFilter(currentUserId, req.body));
```

Не исправлять через `String(req.body.title)`: объект станет бессмысленной
строкой и изменит контракт. Не переносить остальной `req.body` в фильтр и
не смешивать с ним серверное условие владельца.

**Проверить:** строка, Unicode, разрешённый пустой заголовок; объект, массив,
`null` вместо title отвергаются **до обращения к БД**; присланный `ownerId`
не меняет фильтр.

</details>

<a id="js-mass-assign"></a>

<a id="js-mass-assign-mass-assignment"></a>

## JS-MASS-ASSIGN. Массовое присваивание

**Поиск:** скрипт, правило JS-MASS-ASSIGN. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JS-MASS-ASSIGN. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~javascript
Object.assign(user, req.body);
~~~

**Исправление:** Явно перечислить разрешённые поля; роль и владелец задаются сервером.

~~~javascript
user.displayName = validateName(req.body.displayName);
~~~

**Проверка:** Лишние и вложенные поля role/owner не меняют привилегии: они отклоняются или игнорируются; разрешённые поля редактируются.

<details>
<summary>Развёрнутый пример и ограничения</summary>

```javascript
// Vulnerable: clients can write ownerId/role and other administrative fields.
Object.assign(note, req.body);
```

**Патч для редактирования заголовка и текста:**

<!-- example: js-editable-note -->
```javascript
function editableNoteFields(body) {
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    throw new TypeError("object required");
  }
  const result = {};
  for (const key of Object.keys(body)) {
    if (key !== "title" && key !== "body") throw new TypeError("unknown field");
    if (typeof body[key] !== "string") throw new TypeError("string required");
    result[key] = body[key];
  }
  return result;
}
// After authorization: update only editableNoteFields(req.body).
```

Список разрешённых полей не заменяет авторизацию записи. Не «очищать» объект
удалением одного ключа с последующим глубоким merge: вложенные пути остаются.
Клиентский JSON с `__proto__` не должен попадать в произвольный merge.

**Проверить:** частичное обновление title, допустимый пустой body; `ownerId`,
`role`, неизвестное поле и вложенный объект отвергаются; исходный объект не мутирует.

</details>

<a id="js-prototype"></a>

<a id="js-prototype-deep-merge-of-an-untrusted-object"></a>

## JS-PROTOTYPE. Глубокое слияние недоверенного объекта

**Поиск:** скрипт, правило JS-PROTOTYPE. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JS-PROTOTYPE. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~javascript
merge(settings, req.body);
~~~

**Исправление:** Проверить библиотеку/версию; собирать объект из allowlist. Если merge необходим, учитывать опасные ключи на любой глубине.

~~~javascript
settings.theme = validateTheme(req.body.theme);
~~~

**Проверка:** Вложенные ключи не меняют прототип/служебные поля.

<a id="js-tls"></a>

<a id="js-tls-nodejs-tls-verification-disabled"></a>

## JS-TLS. TLS отключён в Node.js

**Поиск:** скрипт, правило JS-TLS. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JS-TLS. Regex: rejectUnauthorized:false/присваивание только в JavaScript/config; NODE_TLS_REJECT_UNAUTHORIZED с точным литералом 0 или парными кавычками вокруг 0. Отдельные шаблоны языков: shell KEY=0 до whitespace/;&|/конца; Docker — первый ключ ENV KEY=0 до whitespace/конца или ENV KEY 0 с целым значением, включая парные кавычки. 0.1/0-disabled/0 с пробелом внутри кавычек не сигналят; #//suffix — часть shell/Docker значения, ; также часть Docker ENV. Комментарии/строки могут совпадать; Docker RUN/последующие ENV ключи, конкатенация, shell expansions, продолжения строк, custom Agent и действующее окружение/переопределения требуют ручного анализа.

**Уязвимый вариант:**

~~~javascript
const options = {rejectUnauthorized: false};
~~~

**Исправление:** Вернуть проверку сертификата, при необходимости задать доверенный CA.

~~~javascript
const options = {rejectUnauthorized: true};
~~~

**Проверка:** Корректный сертификат работает; неверный CA, чужое имя сервера и истёкший срок дают отказ.

Тот же риск задаётся вне JavaScript через окружение процесса:

~~~dockerfile
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
~~~

~~~bash
NODE_TLS_REJECT_UNAUTHORIZED=0 node server.js
~~~

Node.js отключает штатную проверку, когда значение переменной равно строке
`'0'`. Значения `'0.1'`, `'0-disabled'` и `'0 '` не равны этому флагу;
не использовать их как исправление — устранить настройку или явно восстановить
проверку. Сравнение `process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0'`
само по себе ничего не отключает.
[Node.js: переменная окружения](https://nodejs.org/api/cli.html#node_tls_reject_unauthorizedvalue),
[точное сравнение в Node.js 22.14.0](https://github.com/nodejs/node/blob/v22.14.0/lib/internal/options.js).

Для внутреннего CA сохранить нужное доверие через настройку CA приложения
или поддерживаемую Node.js конфигурацию. Например, при заранее установленном
PEM-файле в образе:

~~~dockerfile
ENV NODE_TLS_REJECT_UNAUTHORIZED=1
ENV NODE_EXTRA_CA_CERTS=/etc/service-ca.pem
~~~

Проверить путь, доступность и нужный состав CA; CA задаёт доверие, а не заменяет
проверку имени. Настройка `ca` у отдельного TLS-клиента и пользовательский Agent
требуют отдельного просмотра. Проверить штатный внутренний сервер и отказ
для чужого CA/имени/просроченного сертификата на фактической версии Node.js.

У Docker поддержаны формы `ENV KEY=value` и устаревшая `ENV KEY value`.
У второй формы весь остаток — значение: `ENV NODE_TLS_REJECT_UNAUTHORIZED 0 extra`
не означает точное `'0'`. ENV образа может быть переопределён при запуске.
[Dockerfile ENV](https://docs.docker.com/reference/dockerfile/#env).

В Dockerfile сканер проверяет только первый ключ инструкции `ENV`;
`RUN NODE_TLS_REJECT_UNAUTHORIZED=0 node server.js` и значение после другого
первого ключа `ENV` искать вручную. У shell и Dockerfile разные границы токена:
`0#suffix` и `0//suffix` входят в значение, а `0;` отделяет команду в shell,
но является значением в `ENV KEY=0;`. Кавычки вокруг точного `0` поддержаны
и в устаревшей форме `ENV KEY "0"`.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'NODE_TLS_REJECT_UNAUTHORIZED|NODE_EXTRA_CA_CERTS|rejectUnauthorized|https[.]Agent|tls[.]connect|env_file|environment:' .
~~~

Связать Dockerfile/build stage, Compose/манифест, startup shell и код с
окружением именно работающего процесса; проверить поздние присваивания и
параметры конкретного запроса. Regex не вычисляет подстановки, порядок запуска
и эффективное окружение, не является полным парсером shell/Dockerfile/JS.
Комментарии и строки-примеры могут давать сигнал; это требует просмотра контекста.

<a id="js-html"></a>

<a id="js-html-html-sink"></a>

## JS-HTML. HTML sink

**Поиск:** скрипт, правило JS-HTML. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JS-HTML. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~javascript
element.innerHTML = message;
~~~

**Исправление:** Для текста textContent; для необходимой разметки проверенный sanitizer с явной политикой.

~~~javascript
element.textContent = message;
~~~

**Проверка:** Текст отображается; события/скрипты не исполняются.

<a id="js-trust-proxy"></a>

<a id="js-trust-proxy-unrestricted-trust-in-proxy-headers"></a>

## JS-TRUST-PROXY. Полное доверие proxy-заголовкам

**Поиск:** правило сканера JS-TRUST-PROXY. Подробности: `--explain JS-TRUST-PROXY`. Regex исключает комментарии/строки: .set('trust proxy', true). Тип receiver не определяется; true бывает допустим за proxy, который перезаписывает forwarded headers. Топология и число proxy-hops не проверяются; исследуйте прямые входы и фактический ближайший peer.

**Уязвимый вариант:**

~~~javascript
app.set('trust proxy', true);
~~~

**Исправление:** Проверить реальную цепочку proxy и доверять конкретным непосредственным узлам; не использовать клиентский X-Forwarded-* как auth. Сеть организаторов не менять.

~~~javascript
app.set('trust proxy', isKnownProxy); // implement topology-specific peer validation
~~~

**Проверка:** Прямой запрос с поддельным заголовком не получает доверенную роль/IP/scheme; штатный reverse proxy работает.

<a id="js-curl-argv"></a>

<a id="js-curl-argv-nodejs-curl-review-url-and-options"></a>

## JS-CURL-ARGV. curl из Node.js: проверить опции и URL

**Поиск:** скрипт, правило JS-CURL-ARGV. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JS-CURL-ARGV. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~javascript
spawn('/usr/bin/curl', [url, '-o', filename]);
~~~

**Исправление:** Отдельные argv не мешают option injection. Предпочесть HTTP-библиотеку с политикой URL/redirect и лимитами; если curl нужен, жёсткие опции/протоколы, -- перед проверенным URL, серверный output.

~~~javascript
downloadValidatedHttpResource(url, destination); // bounded HTTP client, checked redirects/DNS and server-chosen output
~~~

**Проверка:** URL с ведущим дефисом, другие схемы, redirects и чужой output не принимаются; штатная загрузка работает.

**Вариант A/D:** Отдельные argv не защищают от опций самой программы. **ECSC / duogesto, автор.** curl интерпретировал клиентское значение как опцию.
**Патч:** ограниченный HTTP-клиент либо фиксированные опции, --, допустимые
схемы/redirect и серверный output. **Тест:** ведущий дефис, иной протокол,
чужой путь и штатный URL. **Поиск:** JS-CURL-ARGV; shell:false недостаточно.

[исходник/разбор 1](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/duogesto/README.md); [исходник/разбор 2](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/duogesto/backend/app.mjs).

<a id="js-session-state"></a>

<a id="js-session-state-sensitive-session-state-assignment"></a>

## JS-SESSION-STATE. Изменение чувствительного состояния сессии

**Поиск:** скрипт, правило JS-SESSION-STATE. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JS-SESSION-STATE. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~javascript
const user = req.body;
req.session.user = user;
~~~

**Исправление:** Формировать session DTO из сохранённого проверенного объекта; author/question/commitment связать одной серверной записью. Не хранить клиентские поля привилегий.

~~~javascript
req.session.user = {id: savedUser.id, friends: savedUser.friends}; // server-validated fields only
~~~

**Проверка:** Лишние friends/role во входе и другой порядок endpoint не меняют права; корректное присваивание тоже даёт сигнал.

**Вариант A/D:** Несвязанные endpoint перезаписывают контекст операции. **ECSC / duogesto, автор.** Автор текущего задания менялся другим запросом,
а завершение использовало старый ответ с новым автором.
**Патч:** хранить challenge ID, автора и состояние вместе; проверять связь
при завершении. **Тест:** перестановки запросов и несколько вкладок.
**Поиск:** JS-SESSION-STATE, семантика вручную.

[исходник/разбор 1](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/duogesto/README.md); [исходник/разбор 2](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/duogesto/backend/app.mjs).

**Вариант A/D:** В БД безопасный объект, в сессии — исходный request body. **ECSC / duogesto, автор.** Инициализация session сохраняла клиентские friends.
**Патч:** явный session DTO из проверенного сохранённого пользователя;
не копировать пароль/лишние поля.
**Тест:** регистрация с role/friends не даёт привилегий, обычный login работает.
**Поиск:** JS-SESSION-STATE; отсутствие taint-анализа учитывать.

[исходник/разбор 1](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/duogesto/README.md); [исходник/разбор 2](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/duogesto/backend/app.mjs).

<a id="js-vm"></a>

<a id="js-vm-nodevm-used-as-a-security-sandbox"></a>

## JS-VM. node:vm используется как security sandbox

**Поиск:** скрипт, правило JS-VM. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JS-VM. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~javascript
vm.runInNewContext(userCode, context);
~~~

**Исправление:** node:vm не граница безопасности для чужого кода. Если нужен калькулятор — ограниченная грамматика; выполнение программ требует отдельно спроектированной изоляции.

~~~javascript
evaluateAllowedExpression(parsedInput); // implement a restricted grammar
~~~

**Проверка:** Недопустимые конструкции отвергаются, штатные выражения работают; лимиты времени и памяти проверены.

**Основание:** [первичный материал](https://nodejs.org/api/vm.html).

<a id="js-regex-dynamic"></a>

<a id="js-regex-dynamic-regex-built-from-client-text"></a>

## JS-REGEX-DYNAMIC. Regex создаётся из клиентского текста

**Поиск:** скрипт, правило JS-REGEX-DYNAMIC. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JS-REGEX-DYNAMIC. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~javascript
const re = new RegExp(input);
~~~

**Исправление:** Для поиска подстроки includes; если regex — функция сервиса, ограниченный движок/сложность и размер. Простое timeout Promise не прерывает синхронный regex.

~~~javascript
const found = text.includes(input);
~~~

**Проверка:** Длинный почти совпадающий ввод не блокирует event loop; Unicode/регистрозависимость сохранены.

**Основание:** [первичный материал](https://nodejs.org/en/learn/asynchronous-work/dont-block-the-event-loop).

<a id="js-type-assertion"></a>

<a id="js-type-assertion-typescript-as-does-not-validate-json"></a>

## JS-TYPE-ASSERTION. TypeScript as не валидирует JSON

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'as [A-Z]|JSON.parse|req.body|parseInt|Number\(' .
~~~

Найти переход unknown → тип; проверить реальную runtime-схему перед доступом к полям.

**Уязвимый вариант:**

req.body as User скрывает отсутствие проверки; parseInt принимает числовой префикс.

**Исправление:** Schema validator или явные проверки типов/диапазона/полей; strict full-string numeric parsing, серверные ID отдельно.

**Проверка:** Массив/null/объект вместо строки, хвост числа, NaN/Infinity и unsafe integer отклоняются.

<a id="js-await-auth"></a>

<a id="js-await-auth-missing-await-on-authorization-checks"></a>

## JS-AWAIT-AUTH. Забытый await у проверки прав

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'authorize|isAllowed|verifyToken|Promise|async' .
~~~

Для каждого if с auth-helper сверить возвращаемый тип; Promise truthy вне зависимости от результата.

**Уязвимый вариант:**

if (isAllowed(user, note)) при async isAllowed пропускает запрос до решения.

**Исправление:** await перед проверкой, явный отказ при исключении; не продолжать response после rejected Promise.

**Проверка:** Асинхронные true/false/error и задержка: закрытый объект не читается до завершения проверки.

<a id="js-websocket"></a>

<a id="js-websocket-authorization-only-at-the-websocket-handshake"></a>

## JS-WEBSOCKET. WebSocket: права только на handshake

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'WebSocket|upgrade|on\(.message|subscribe|room|channel' .
~~~

Сопоставить handshake, каждое message/action, room join и broadcast; проверить Origin отдельно от cookie.

**Уязвимый вариант:**

После входа клиент выбирает чужой room или сохраняет доступ после смены прав.

**Исправление:** Проверять субъект и ресурс каждой операции/подписки, срок сессии и допустимый Origin браузера; лимиты сообщений.

**Проверка:** Два пользователя, отзыв роли, reconnect, чужой room и обычный broadcast.

**Основание:** [первичный материал](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html).

<a id="js-graphql"></a>

<a id="js-graphql-resolvers-and-batching-bypass-a-common-guard"></a>

## JS-GRAPHQL. GraphQL: resolver и batching обходят общий guard

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'resolver|resolve|GraphQL|DataLoader|context|mutation' .
~~~

Проверить nested resolver, node(id), loaders и mutations; scope кеша DataLoader к запросу/пользователю.

**Уязвимый вариант:**

Корневой query защищён, вложенный resolver читает объект по ID без owner; общий loader отдаёт чужой результат.

**Исправление:** Resource auth в resolver/service, request-scoped loader, лимит глубины/стоимости/пакета по контракту.

**Проверка:** Чужой node, вложенный путь, aliases/batch и обычная пагинация.

**Основание:** [первичный материал](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html).

<a id="js-session-fixation"></a>

<a id="js-session-fixation-session-id-does-not-change-at-login"></a>

## JS-SESSION-FIXATION. Сессия не меняется после входа

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'session|regenerate|login|logout|sessionID' .
~~~

Сравнить идентификатор до/после login и связь прежнего ID с новым principal.

**Уязвимый вариант:**

Предварительно известная анонимная сессия после входа становится авторизованной.

**Исправление:** Штатная регенерация session ID на переходе привилегий с переносом только разрешённых данных; logout инвалидирует серверное состояние.

**Проверка:** Старый ID не авторизует, корзина/допустимое состояние сохраняется, concurrent login не теряет сессию.

<a id="js-ssrf"></a>

<a id="js-ssrf-fetchaxios-redirects-and-repeated-dns-resolution"></a>

## JS-SSRF. fetch/axios: redirect и повторное DNS-разрешение

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'fetch\(|axios|undici|http.request|https.request' .
~~~

Проследить URL до фактического соединения и каждый redirect; JS-CURL-ARGV покрывает только curl-вызов.

**Уязвимый вариант:**

Проверен исходный hostname, но соединение или redirect выбирает иной адрес/схему.

**Исправление:** Серверная карта назначений или policy нормализованного URL, разрешённых IP/портов и фактического соединения; лимиты ответа/времени.

**Проверка:** Mock DNS/redirect, разрешённый внутренний адрес по контракту, timeout и oversized body.

**Основание:** [первичный материал](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

<a id="js-buffer-exposure"></a>

<a id="js-buffer-exposure-uninitialized-buffer-exposure"></a>

## JS-BUFFER-EXPOSURE. Неинициализированная память в Buffer

**Поиск:** скрипт, правило JS-BUFFER-EXPOSURE. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JS-BUFFER-EXPOSURE. Regex: Buffer.allocUnsafe и allocUnsafeSlow. Полная инициализация до выдачи снимает риск вручную; старый new Buffer и ошибочные длины искать отдельно.

Дополнительный ручной поиск для непокрытых форм:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'allocUnsafe|allocUnsafeSlow|write\(|subarray|res.end|socket.write' .
~~~

Сравнить allocated capacity, реально записанные байты и длину отправки.

**Уязвимый вариант:**

Buffer.allocUnsafe(n) отправляется целиком после частичного заполнения.

**Исправление:** Buffer.alloc либо заполнение каждого байта; отправлять только записанную длину, обрабатывать short read.

**Проверка:** Короткое чтение, EOF и ошибки не раскрывают байты незаписанного хвоста; штатные бинарные ответы, NUL и максимальная длина сохранены.

**Основание:** [первичный материал](https://nodejs.org/api/buffer.html).

**Сигнал сканера — пример до:**

~~~javascript
const out = Buffer.allocUnsafe(size);
const n = await readInto(out);
res.end(out);
~~~

**Шаблон исправления:**

~~~javascript
const out = Buffer.alloc(size);
const n = await readInto(out);
res.end(out.subarray(0, n));
~~~

Первичная документация: [документация 1](https://nodejs.org/api/buffer.html#what-makes-bufferallocunsafe-and-bufferallocunsafeslow-unsafe).

<a id="js-jwt-decode"></a>

<a id="js-jwt-decode-jwt-decoded-without-signature-verification"></a>

## JS-JWT-DECODE. JWT декодируется без проверки подписи

**Поиск:** скрипт, правило JS-JWT-DECODE. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JS-JWT-DECODE. Regex: привычные jwt.decode/decodeJwt/jwtDecode; дополнительно статические ESM/CommonJS aliases jsonwebtoken.decode и jose.decodeJwt. Нет анализа scope/reassignment, re-export, dynamic import или использования claims; декодирование для диагностики может быть допустимо.

**Уязвимый вариант:** decode/decodeJwt только извлекает данные; использовать их как подтверждённую личность нельзя.

~~~javascript
const user = jwt.decode(token);
loadNotes(user.sub);
~~~

**Исправление:** Проверять подпись и claims до выдачи данных. В async варианте дождаться проверки и обрабатывать ошибку до продолжения.

~~~javascript
const claims = jwt.verify(token, key, { algorithms: ['RS256'], issuer: 'auth', audience: 'notes' });
loadNotes(claims.sub);
~~~

**Проверка:** Изменённый payload, неверная подпись, чужой issuer/audience не дают доступа; штатный токен работает.

Первичная документация: [документация 1](https://github.com/auth0/node-jsonwebtoken#jwtdecodetoken--options).

<a id="js-jwt-options"></a>

<a id="js-jwt-options-weakened-jwt-options"></a>

## JS-JWT-OPTIONS. Ослабленные параметры JWT

**Поиск:** скрипт, правило JS-JWT-OPTIONS. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JS-JWT-OPTIONS. Regex: ignoreExpiration/ignoreNotBefore/allowInvalidAsymmetricKeyTypes=true; options может находиться отдельно от verify, поэтому контекст проверять вручную.

**Уязвимый вариант:** Игнорирование времени или разрешение несовместимого ключа ослабляет проверку токена.

~~~javascript
jwt.verify(token, key, { ignoreExpiration: true, ignoreNotBefore: true });
~~~

**Исправление:** Убрать обходы проверки, закрепить алгоритм/тип ключа и контракт claims. Отсутствие exp при необходимости отклонять отдельно.

~~~javascript
jwt.verify(token, key, { algorithms: ['RS256'], issuer: 'auth', audience: 'notes' });
~~~

**Проверка:** Просроченный и ещё не действующий токен отклонены; неверные alg и key type не проходят.

Первичная документация: [документация 1](https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback).

<a id="js-http-parser"></a>

<a id="js-http-parser-lenient-nodejs-http-parser"></a>

## JS-HTTP-PARSER. Ослабленный HTTP parser Node.js

**Поиск:** скрипт, правило JS-HTTP-PARSER. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JS-HTTP-PARSER. Regex: insecureHTTPParser:true или --insecure-http-parser. Сам по себе сигнал не подтверждает request smuggling.

**Уязвимый вариант:** Разные правила разбора proxy/backend создают неоднозначные границы запроса.

~~~javascript
http.createServer({ insecureHTTPParser: true }, handler);
~~~

**Исправление:** Использовать строгий parser на всех hop; согласовать нормализацию и framing. Проверить также NODE_OPTIONS и CLI.

~~~javascript
http.createServer({ insecureHTTPParser: false }, handler);
~~~

**Проверка:** Противоречивые длины/заголовки отклоняются на первом hop; штатные keep-alive запросы не смешиваются.

Первичная документация: [документация 1](https://nodejs.org/api/http.html#httpcreateserveroptions-requestlistener).

<a id="js-static-dotfiles"></a>

<a id="js-static-dotfiles-static-server-allows-dotfiles"></a>

## JS-STATIC-DOTFILES. Статика разрешает скрытые файлы

**Поиск:** скрипт, правило JS-STATIC-DOTFILES. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JS-STATIC-DOTFILES. Regex: dotfiles:allow. Не проверяет фактический root, middleware order, backup-файлы без точки и символические ссылки.

**Уязвимый вариант:** Статический root со скрытыми файлами может раскрыть конфиги, историю и ключи.

~~~javascript
app.use(express.static(root, { dotfiles: 'allow' }));
~~~

**Исправление:** Выделить публичный каталог, запретить dotfiles; служебные .well-known маршруты разрешать точечно без секретов.

~~~javascript
app.use(express.static(publicDir, { dotfiles: 'deny' }));
~~~

**Проверка:** Публичные ассеты доступны; dotfile, резервная копия и файл за пределами root недоступны.

Первичная документация: [документация 1](https://expressjs.com/en/4x/api.html#express.static).

<a id="js-query-shape"></a>

<a id="js-query-shape-parameters-change-type-between-middleware"></a>

## JS-QUERY-SHAPE. Параметр меняет тип между middleware

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'req\.(query|body|params)|URLSearchParams|querystring|qs\.|Object\.assign|\.\.\.' .
~~~

Проверить повторные query keys, scalar/array/object, настройку query parser и порядок merge params/query/body. Сравнить поле, которое проверяли, с полем, которое реально передали в DB/auth.

**Уязвимый вариант:** Валидатор проверяет одну строку, следующий слой берёт последнее значение/объект или body перезаписывает уже проверенный owner из params.

**Исправление:** Один раз разобрать запрос в DTO с точными типами; отвергать дубликаты/неожиданные структуры по контракту. Не смешивать клиентские поля с установленным сервером principal.

**Проверка:** Дубликаты, bracket notation, вложенный объект и конфликт body/query не меняют owner/фильтр; обычный запрос сохраняет прежний результат.

Основание: [первичная документация/материал](https://expressjs.com/en/4x/api.html#req.query). Описание и рецепт адаптации составлены для этой базы.

<a id="js-middleware-trust"></a>

<a id="js-middleware-trust-handlers-assume-middleware-has-run"></a>

## JS-MIDDLEWARE-TRUST. Обработчик доверяет выполнению middleware

**Поиск:** вручную; отдельного правила сканера нет. Этот ID обозначает раздел
каталога. Сканер не устанавливает версию Next.js, топологию маршрутизации или
наличие проверки доступа на каждом пути исполнения.

~~~bash
rg -n --hidden -g '!node_modules/**' -g '!.git/**' -g 'middleware.*' -g 'proxy.*' -g 'next.config.*' -g '*.conf' -e 'matcher|NextResponse\.(next|rewrite|redirect)|x-middleware-subrequest|proxy_pass|proxy_set_header|standalone' .
rg -n --hidden -g '!node_modules/**' -g '!.git/**' -e 'next/server|export.*(GET|POST|PUT|PATCH|DELETE)|use server|verifySession|authorize|"next"|next@' .
~~~

По первому поиску составить цепочку внешний вход → proxy/adapter → Next.js →
matcher/rewrite → обработчик. По второму проследить реальную проверку сессии
и прав до чтения/изменения данных; открыть helper и lock-файл, не ограничиваться
именем функции или диапазоном package.json. Проверить также прямой доступ к
backend в обход proxy. Middleware только для локали/публичной страницы и
обработчик с собственной проверкой доступа — похожие безопасные случаи.

**Уязвимый вариант:** В CVE-2025-29927 внешний `x-middleware-subrequest`
попадал в механизм предотвращения рекурсии Next.js и позволял пропустить
middleware. Если обработчик полагался только на него, проверка доступа
пропускалась. Postmortem подтверждает влияние на self-hosted `next start`
и `output: 'standalone'`; static export не выполняет middleware. Vercel и
рассмотренные авторами adapters Netlify/Cloudflare Workers не были затронуты
из-за другой маршрутизации. Это границы конкретного инцидента, не гарантия
безопасности любой конфигурации этих платформ.
[Разбор разработчиков](https://vercel.com/blog/postmortem-on-next-js-middleware-bypass).

Минимальная опасная связка; `verifySession` и функции данных — helpers проекта:

~~~javascript
// middleware.js
import { NextResponse } from 'next/server';
import { verifySession } from './lib/auth.js';
export async function middleware(req) {
  if (!(await verifySession(req))) {
    return NextResponse.redirect(new URL('/login', req.url));
  }
  return NextResponse.next();
}
export const config = { matcher: ['/api/notes/:path*'] };
~~~

~~~javascript
// app/api/notes/route.js
import { listNotes } from '../../../lib/data.js';
export async function GET(req) {
  return Response.json(await listNotes());
}
~~~

Исторические диапазоны advisory: `>=11.1.4 <12.3.5`,
`>=13.0.0 <13.5.9`, `>=14.0.0 <14.2.25`, `>=15.0.0 <15.2.3`.
Релизы 12.3.5, 13.5.9, 14.2.25, 15.2.3 исправляют именно этот CVE;
отдельного исправленного релиза 11.x advisory не указывает.
[GHSA-f82v-jwr5-mffw](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw).

**Исправление:** Перейти на поддерживаемую ветку с актуальными исправлениями
безопасности. Исторический минимальный релиз выше не является рекомендацией
для установки сегодня: последующее исправление утечки внутреннего заголовка
потребовало новых релизов.
[GHSA-223j-4rm8-mrmf](https://github.com/vercel/next.js/security/advisories/GHSA-223j-4rm8-mrmf),
[advisories проекта](https://github.com/vercel/next.js/security/advisories).
Upstream-патч проверяет происхождение внутреннего заголовка; regression test
сохраняет ожидаемый redirect при внешнем заголовке.
[Исправление 52a078d и тест](https://github.com/vercel/next.js/commit/52a078da3884efe6501613c7834a3d02a91676d2).

Проверять сессию и разрешение операции в обработчике/слое доступа к данным,
включая Server Actions; middleware может сохранить ранний redirect для UX.
`verifySession` ниже должен валидировать сессию, а `listNotesForUser` —
ограничивать выборку проверенным субъектом, не значением из запроса.
[Next.js: авторизация и DAL](https://nextjs.org/docs/app/guides/authentication).

~~~javascript
// app/api/notes/route.js
import { verifySession } from '../../../lib/auth.js';
import { listNotesForUser } from '../../../lib/data.js';
export async function GET(req) {
  const session = await verifySession(req);
  if (!session) return new Response(null, { status: 401 });
  return Response.json(await listNotesForUser(session.userId));
}
~~~

Единая политика owner/tenant и альтернативные endpoints описаны в
[CFG-OBJECT-POLICY](configuration-RU.md#cfg-object-policy).

Временная мера на **внешней** границе nginx — удалить присланный клиентом
заголовок перед передачей Next.js. Добавить в каждый применимый proxy location,
сохраняя прочие необходимые заголовки и параметры:

~~~nginx
proxy_set_header x-middleware-subrequest "";
~~~

Пустое значение исключает заголовок из upstream-запроса. Директивы
`proxy_set_header` наследуются только при отсутствии таких директив на текущем
уровне: проверить все locations и отдельные ingress, ограничить backend
доверенными входами. Это не готовая полная конфигурация proxy.
[nginx: proxy_set_header](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header).
Не удалять внутренний заголовок без разбора на каждом межсервисном переходе:
штатный fetch из middleware использует его для предотвращения рекурсии.

**Проверка:** В разрешённом тестовом окружении повторить проверки с внешним
заголовком и без него. Матрица должна включать:

| Путь | Проверяемый результат |
|---|---|
| Страница, API чтения и записи, rewrite и альтернативный URL | Аноним не получает защищённые данные; разрешённая операция владельца работает; чужие данные недоступны. |
| Server Action и прямой вызов обработчика | Проверка прав выполняется независимо от страницы и middleware. |
| Каждый внешний ingress и прямой backend | Внешний внутренний заголовок не отключает защиту; backend недоступен через неразрешённый вход. |
| Внутренний fetch из middleware | Сохраняются штатные ответы/redirect; нет рекурсивного цикла. |

Сверить cookies, сессию, response contract и нагрузку после переноса проверок:
дополнительный доступ к хранилищу и несовместимый auth helper могут нарушить
штатные операции. Здесь проверены исходники и инертные примеры для офлайн-сканера;
Next.js runtime и HTTP-проверки приложения не запускались. Нулевой отчёт сканера
не подтверждает устранение этой ручной проблемы.

<a id="js-redirect-input"></a>

<a id="js-redirect-input-request-field-passed-directly-to-an-express-style-redirect"></a>

## JS-REDIRECT-INPUT. Поле запроса напрямую передаётся в Express-подобный redirect

**Поиск:** правило сканера JS-REDIRECT-INPUT. Точный контракт детектора: `--explain JS-REDIRECT-INPUT`. Regex с лексическими исключениями комментариев и строк: res/response.redirect с прямым свойством req/request.query/body/params, возможно после литерального кода статуса. Тип получателя и поток данных не анализируются; вычисляемые ключи, aliases и предшествующая валидация требуют проверки.

**Уязвимый вариант:**

~~~javascript
res.redirect(req.query.next);
~~~

**Исправление:** Определяйте redirect по серверной таблице маршрутов или явной политике нормализованных URL.

~~~javascript
res.redirect('/account');
~~~

**Проверка:** Внешние адреса и адреса вида //host отклоняются; согласованная навигация работает.

[Первичный источник 1](https://expressjs.com/en/4x/api.html#res.redirect)

<a id="js-log-credentials"></a>
<a id="js-log-credentials-credential-like-value-passed-directly-to-console"></a>

## JS-LOG-CREDENTIALS. Credentials напрямую передаются в console

**Поиск:** правило сканера JS-LOG-CREDENTIALS. Подробности: `--explain JS-LOG-CREDENTIALS`. Ограниченные JS-токены: console log/info/warn/error/debug/trace с прямыми чувствительными именами/свойствами, inline object/array или конкатенацией. Наблюдаемые shadows/reassignments console подавляют подсказки во всём файле. Templates, helper calls, другие loggers, динамические ключи и потоки между файлами проверяются вручную; отсутствие сигнала не доказывает очистку.

**Уязвимый вариант:**

~~~javascript
console.warn(req.headers.authorization);
~~~

**Исправление:** Логируйте категории событий и согласованные идентификаторы, а не credentials. Проверьте ошибки входа и исключения; helper очистки нужно реализовать и протестировать отдельно.

~~~javascript
console.warn('authentication failed');
~~~

**Проверка:** Синтетические canary credentials не появляются в stdout, логах, evidence и трансляции экрана; полезные категории ошибок остаются.

[Первичный источник](https://nodejs.org/api/console.html)
