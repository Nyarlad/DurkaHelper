<a id="go-find-fix-and-verify"></a>

# Go: поиск и исправление

[English](go.md) | Русский

[Вся база](README-RU.md) · [Сканер](../offline-scanner-RU.md) · [Проверка патча](../patch-validation-RU.md)

19 разделов. Формат: **Поиск → Уязвимый вариант → Исправление → Проверка**.
Команды `rg` выполняются в корне локальной копии сервиса и только читают файлы. Субъект/владелец определяется по проверенной сессии, а не данным запроса. Примеры нужно адаптировать к реальным API и контракту.

Автоматические находки — ограниченные синтаксические сигналы для проверки. AST-анализ не разрешает типы и не отслеживает данные между функциями; regex не заменяет парсер языка. Комментарии, строки и одноимённые пользовательские API могут давать совпадения. Проверьте фактическое исполнение, входные данные, авторизацию и границы доверия.

<a id="contents"></a>

## Содержание

- [GO-SQL — Динамический SQL Go](#go-sql)
- [GO-HASH-SUM — Непустой аргумент hash.Sum](#go-hash-sum)
- [GO-HTML — Обход autoescape Go](#go-html)
- [GO-TLS — InsecureSkipVerify](#go-tls)
- [GO-SHELL — Go exec.Command запускает shell](#go-shell)
- [GO-CRC — CRC используется как идентификатор/контроль доверия](#go-crc)
- [GO-MATH-RAND — math/rand рядом с возможным секретом](#go-math-rand)
- [GO-READALL-BODY — ReadAll тела запроса](#go-readall-body)
- [GO-PPROF — pprof регистрируется на HTTP mux](#go-pprof)
- [GO-FILESERVER — FileServer публикует дерево файлов](#go-fileserver)
- [GO-AUTH-RETURN — После http.Error выполнение продолжается](#go-auth-return)
- [GO-JSON-FIELDS — JSON в entity и неоднозначные ключи](#go-json-fields)
- [GO-RACE — Общие map/slice и check-then-use](#go-race)
- [GO-ERROR-DEFAULT — Игнорирование ошибки даёт нулевого субъекта](#go-error-default)
- [GO-SSRF — Go HTTP client и redirects](#go-ssrf)
- [GO-ZIP-PATH — filepath.Join не обеспечивает containment](#go-zip-path)
- [GO-TLS-MIN — Явно разрешён устаревший TLS](#go-tls-min)
- [GO-JWT-UNVERIFIED — JWT без подписи или проверки claims](#go-jwt-unverified)
- [GO-UPLOAD-PATH — Имя multipart-файла напрямую включается в путь](#go-upload-path)

<a id="go-sql"></a>

<a id="go-sql-dynamic-go-sql"></a>

## GO-SQL. Динамический SQL Go

**Поиск:** скрипт, правило GO-SQL. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain GO-SQL. Regex: Query/QueryRow/Exec/Prepare и Context-варианты с конкатенацией или fmt.Sprintf. Простой context expression поддержан; сложный синтаксис/aliases fmt и заранее собранный SQL вручную.

**Уязвимый вариант:**

~~~go
db.Query("SELECT id FROM notes WHERE name=" + name)
~~~

**Исправление:** Передавать значения аргументами; placeholder зависит от драйвера. Идентификаторы выбирать из разрешённого набора.

~~~go
db.Query("SELECT id FROM notes WHERE name=$1", name)
~~~

**Проверка:** Кавычки — данные; права сохранены.

<details>
<summary>Развёрнутый пример и ограничения</summary>

```go
// Vulnerable: client input becomes SQL syntax.
q := fmt.Sprintf("SELECT body FROM notes WHERE id = '%s'", inputID)
err := db.QueryRowContext(ctx, q).Scan(&body)
```

**Патч для приватной заметки:**

```go
import (
    "context"
    "database/sql"
)

func ReadPrivateNote(ctx context.Context, db *sql.DB, userID, noteID int64) (string, error) {
    var body string
    err := db.QueryRowContext(ctx,
        "SELECT body FROM notes WHERE id = $1 AND owner_id = $2",
        noteID, userID,
    ).Scan(&body)
    return body, err
}
```

До вызова разобрать ID через проверяемое преобразование, не игнорировать ошибку
парсинга. `sql.ErrNoRows` перевести в штатное отсутствие доступного объекта;
при любой иной ошибке не выдавать `body` как успешный результат. Для MySQL/другого
драйвера проверить синтаксис маркеров — он может отличаться.

**Проверить:** своё, чужое, отсутствующий объект; неверный ID; отмена/таймаут
контекста; старые записи. В списках проверять ошибку `rows.Err()` после обхода.

</details>

<a id="go-hash-sum"></a>

<a id="go-hash-sum-non-empty-argument-to-hashsum"></a>

## GO-HASH-SUM. Непустой аргумент hash.Sum

**Поиск:** скрипт, правило GO-HASH-SUM. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain GO-HASH-SUM. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~go
digest := h.Sum(record.Hash[:])
~~~

**Исправление:** Hash.Sum(b) добавляет digest к b, не хеширует b: сначала Write(data), потом Sum(nil). Проверить длину/все подписанные поля.

~~~go
h.Write(record.Hash[:])
digest := h.Sum(nil)
~~~

**Проверка:** Результаты совпадают с известными тестовыми векторами; старые форматы digest мигрируют явно. Изменение каждого подписанного поля нарушает подпись.

**Вариант A/D:** Sum не хеширует свой аргумент. **Основание:** certified-transparency, анализ трёх файлов saarCTF.
Checksum передавал Hash в Sum; ToHash копировал первые 32 байта результата.
Из семантики Go следует: эти байты могли быть исходным Hash, а не digest
ранее записанных Size/Timestamp. Полный сервис мы не воспроизводили.
Сканер: GO-HASH-SUM.

~~~go
// Before: return ToHash(h.Sum(record.Hash[:]))
// After: include data in hash state, then extract only the digest.
h.Write(record.Hash[:])
return ToHash(h.Sum(nil))
~~~

**Тест:** изменить по одному Size, Timestamp, Hash: каждая старая подпись должна
перестать приниматься. Согласовать переход формата подписей и старые данные.
Непустой Sum не всегда ошибка: buf[:0] может использоваться для выделенной
заранее памяти. Поэтому сигнал требует чтения потребителя результата.

[исходник/разбор 1](https://github.com/saarsec/saarctf-2024/blob/3a06d18974ca177c6dd251a11bdf9b4b334f382a/certified-transparency/service/pkg/models/serialization.go); [исходник/разбор 2](https://github.com/saarsec/saarctf-2024/blob/3a06d18974ca177c6dd251a11bdf9b4b334f382a/certified-transparency/service/pkg/models/models.go); [исходник/разбор 3](https://github.com/saarsec/saarctf-2024/blob/3a06d18974ca177c6dd251a11bdf9b4b334f382a/certified-transparency/service/pkg/signatures.go).

<a id="go-html"></a>

<a id="go-html-go-autoescape-bypass"></a>

## GO-HTML. Обход autoescape Go

**Поиск:** скрипт, правило GO-HTML. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain GO-HTML. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~go
value := template.HTML(input)
~~~

**Исправление:** Обычная строка в html/template; sanitizer только для предусмотренного богатого HTML.

~~~go
value := input // string passed to html/template
~~~

**Проверка:** Теги и кавычки пользователя отображаются текстом; предусмотренное форматирование работает.

<details>
<summary>Развёрнутый пример и ограничения</summary>

```go
// Vulnerable when message is client-controlled.
err := page.Execute(w, template.HTML(message))
```

**Патч для вывода обычного текста:**

```go
import (
    "html/template"
    "io"
)

func RenderMessage(w io.Writer, message string) error {
    page, err := template.New("message").Parse("<p>{{.}}</p>")
    if err != nil {
        return err
    }
    return page.Execute(w, message)
}
```

Шаблон фиксирован; данные — обычная строка. Использовать `html/template`, а не
`text/template`, для HTML. Не заменять ошибку типом `template.JS`/`template.URL`:
эти типы тоже выражают доверие к данным. В реальном приложении фиксированный
шаблон можно разобрать один раз при старте. Если возможна ошибка рендеринга,
учесть частично записанный HTTP-ответ: при необходимости сначала рендерить в буфер.

**Проверить:** разметка и кавычки отображаются текстом, Unicode сохранён;
сервис не стал компилировать сам message; допустимое форматирование по контракту работает.

</details>

<a id="go-tls"></a>

<a id="go-tls-insecureskipverify"></a>

## GO-TLS. InsecureSkipVerify

**Поиск:** скрипт, правило GO-TLS. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain GO-TLS. Regex: InsecureSkipVerify: true и присваивание .InsecureSkipVerify = true, включая переносы строк; ==/!= и false не сигналят. Наличие VerifyConnection не снимает review: тип объекта, достижимость, callback и итоговую конфигурацию проверить вручную. Комментарии и строки могут совпадать.

**Уязвимый вариант:**

~~~go
cfg := tls.Config{InsecureSkipVerify: true}
~~~

**Исправление:** Вернуть штатную проверку сертификата и имени сервера; при необходимости настроить RootCAs/ServerName. Проверить пользовательские callbacks проверки.

~~~go
cfg := tls.Config{InsecureSkipVerify: false}
~~~

**Проверка:** Корректный сервер доступен; неверный сертификат отвергается.

Опасная настройка может появиться после создания конфига:

~~~go
cfg := &tls.Config{}
cfg.InsecureSkipVerify = true
~~~

Для обычного TLS-клиента вернуть `false` и настроить `RootCAs`/`ServerName`
для нужного сервера. Проверить доверенный сертификат, неизвестный CA,
несовпадающее имя и истёкший срок, сохранив доступ к штатному внутреннему CA.

При `InsecureSkipVerify: true` приложение может реализовать собственную
проверку в `VerifyConnection`. Если она полноценно проверяет требуемую цепочку
и имя, флаг может быть обоснован; наличие callback само по себе этого не
доказывает. Сканер не анализирует его тело и сохраняет сигнал после такого
исправления. Сравнение `cfg.InsecureSkipVerify == true` не изменяет настройку
и отдельно не получает GO-TLS. [Go: tls.Config](https://pkg.go.dev/crypto/tls#Config).

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'InsecureSkipVerify|VerifyConnection|VerifyPeerCertificate|RootCAs|ServerName|TLSClientConfig' .
~~~

Связать конфигурацию с используемым transport, проследить все присваивания
и возвраты ошибки в callback, включая возобновлённые TLS-сессии. Значение из
переменной и эффективная конфигурация остаются ручной проверкой. Regex может
совпасть с комментарием или текстовым примером; это не подтверждение выполнения.

<a id="go-shell"></a>

<a id="go-shell-go-execcommand-launches-a-shell"></a>

## GO-SHELL. Go exec.Command запускает shell

**Поиск:** скрипт, правило GO-SHELL. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain GO-SHELL. Regex: любой receiver.Command/CommandContext с буквальным shell и -c/-lc/-ec. Простой context expression, включая r.Context(), поддержан; вложенная запятая внутри context expression может скрыть вызов. Тип receiver и доверенность команды вручную.

**Уязвимый вариант:**

~~~go
cmd := exec.Command("sh", "-c", command)
~~~

**Исправление:** Фиксированный executable + argv. Для утилиты, читающей запись со stdin, передать её без shell и проверить разделители формата.

~~~go
cmd := exec.Command("/usr/bin/file", "--", filename)
~~~

**Проверка:** Спецсимволы остаются данными, опасные опции/разделители отвергаются; штатные допустимые аргументы работают.

<details>
<summary>Развёрнутый пример и ограничения</summary>

```go
// Vulnerable: exec.Command starts a shell that parses input text.
out, err := exec.Command("sh", "-c", "printf '%s' '"+message+"' | sha256sum").Output()
```

**Патч для SHA-256 содержимого:**

```go
import (
    "crypto/sha256"
    "encoding/hex"
)

func DigestText(message string) string {
    sum := sha256.Sum256([]byte(message))
    return hex.EncodeToString(sum[:])
}
```

Go-строка — байты; пример сохраняет их как есть. Если протокол требует именно
UTF-8, его корректность проверить отдельно. Сохранить внешний формат ответа,
который мог отличаться от сырого вывода `sha256sum`. Это не хеширование паролей.

**Проверить:** известный digest, пустая строка, Unicode, кавычки и переводы строк;
нет запуска процесса. Для действительно нужной внешней команды задавать executable
и аргументы отдельно, ограничивать время через контекст; аргументы всё ещё может
интерпретировать сама программа.

</details>

**Вариант A/D:** Shell спрятан во внутреннем backend. **ENOWARS / replme, автор.** Внутренний обработчик помещал пароль в shell-команду.
**Патч:** вызывать фиксированную утилиту без shell; данные передавать stdin
с проверкой разделителей её формата. Ограничивать пароль только буквами
без проверки контракта нельзя. **Тест:** пробелы и допустимые символы работают,
разделители записи отвергаются. **Поиск:** GO-SHELL; проследить весь вызов.

[исходник/разбор 1](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/main.tex); [исходник/разбор 2](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/path-traversal.patch); [исходник/разбор 3](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/crc.patch); [исходник/разбор 4](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/backend/util/encoding.go); [исходник/разбор 5](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/backend/controller/repl.go); [исходник/разбор 6](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/image/service/user.go).

<a id="go-crc"></a>

<a id="go-crc-crc-near-an-identifier-or-trust-boundary"></a>

## GO-CRC. CRC используется как идентификатор/контроль доверия

**Поиск:** скрипт, правило GO-CRC. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain GO-CRC. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~go
resource := service.CRC.Calculate(username)
~~~

**Исправление:** CRC не граница между пользователями. Для отображения ресурса — серверный уникальный ID/криптохеш + отдельная проверка владельца; для MAC — HMAC, не простой хеш.

~~~go
resource := sha256.Sum256([]byte(username))
~~~

**Проверка:** Разные пользователи не делят ресурс; коллизия не меняет владельца; есть миграция прежних ключей.

**Вариант A/D:** CRC как граница между ресурсами пользователей. **ENOWARS / replme, автор + патч.** CRC имени выбирал контейнер;
коллизия объединяла чужие ресурсы.

**Патч:** серверный уникальный ID либо криптографическое отображение, отдельная
проверка владельца и миграция существующих ресурсов. Криптохеш не заменяет auth.
**Тест:** одинаковый checksum двух имён не даёт общий ресурс.
**Поиск:** GO-CRC; PY-CRC покрывает аналогичный риск в Python.

[исходник/разбор 1](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/main.tex); [исходник/разбор 2](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/path-traversal.patch); [исходник/разбор 3](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/crc.patch); [исходник/разбор 4](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/backend/util/encoding.go); [исходник/разбор 5](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/backend/controller/repl.go); [исходник/разбор 6](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/image/service/user.go).

<a id="go-math-rand"></a>

<a id="go-math-rand-mathrand-near-a-possible-secret"></a>

## GO-MATH-RAND. math/rand рядом с возможным секретом

**Поиск:** скрипт, правило GO-MATH-RAND. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain GO-MATH-RAND. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~go
import "math/rand"
rand.Seed(time.Now().UnixMilli())
~~~

**Исправление:** Токены/секреты генерировать crypto/rand с обработкой ошибок. Перестановка алфавита/скрытый seed не заменяет CSPRNG.

~~~go
import "crypto/rand"
_, err := rand.Read(token)
if err != nil { return err }
~~~

**Проверка:** Источник энтропии и длина достаточны; ошибка генератора не создаёт предсказуемый fallback.

**Вариант A/D:** Go-токен с seed от времени. **RuCTF / werk, автор.** Обычный math/rand и время создания ограничивали
непредсказуемость токена.
**Патч:** crypto/rand, достаточная длина и проверка ошибок; перестановка алфавита
не устраняет слабость генератора. **Тест:** контракт токена и отказ генератора
без предсказуемой замены. **Поиск:** GO-MATH-RAND, включая alias импорта;
кастомный PRNG анализировать отдельно.

[исходник/разбор 1](https://github.com/HackerDom/ructf-2023/blob/0cc333e44f2ba6908ff6c5d613146e3b00173315/writeups/werk/README.md).

<a id="go-readall-body"></a>

<a id="go-readall-body-readall-on-a-request-body"></a>

## GO-READALL-BODY. ReadAll тела запроса

**Поиск:** скрипт, правило GO-READALL-BODY. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain GO-READALL-BODY. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~go
body, err := io.ReadAll(r.Body)
~~~

**Исправление:** Ограничить тело до чтения, корректно обработать превышение лимита. Правило не отслеживает ранее установленный MaxBytesReader.

~~~go
r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
body, err := io.ReadAll(r.Body)
if err != nil { return } // map to an appropriate client error
~~~

**Проверка:** Лимит-1/лимит/лимит+1, stream без Content-Length; штатный максимальный документ работает.

<a id="go-pprof"></a>

<a id="go-pprof-pprof-registered-on-an-http-mux"></a>

## GO-PPROF. pprof регистрируется на HTTP mux

**Поиск:** скрипт, правило GO-PPROF. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain GO-PPROF. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~go
import _ "net/http/pprof"
~~~

**Исправление:** Не публиковать DefaultServeMux с debug handlers как бизнес-API. Разделить mux и прикладную авторизацию диагностического endpoint.

~~~go
// use a separate authenticated diagnostics mux when diagnostics is required
~~~

**Проверка:** Обычный API работает; аноним не получает профиль/heap. Импорт сам по себе не доказывает доступность.

**Основание:** [первичный материал](https://pkg.go.dev/net/http/pprof).

<a id="go-fileserver"></a>

<a id="go-fileserver-fileserver-publishes-a-file-tree"></a>

## GO-FILESERVER. FileServer публикует дерево файлов

**Поиск:** скрипт, правило GO-FILESERVER. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain GO-FILESERVER. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~go
http.Handle("/", http.FileServer(http.Dir(".")))
~~~

**Исправление:** Отдельный public root без секретов/БД, права на приватные файлы вне static handler; проверить symlink и directory listing.

~~~go
http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("./public"))))
~~~

**Проверка:** Assets доступны; .env/исходники/чужие файлы и ссылка наружу недоступны.

**Основание:** [первичный материал](https://pkg.go.dev/net/http#FileServer).

<a id="go-auth-return"></a>

<a id="go-auth-return-execution-continues-after-httperror"></a>

## GO-AUTH-RETURN. После http.Error выполнение продолжается

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'http.Error|WriteHeader|StatusForbidden|StatusUnauthorized' .
~~~

Пройти код после каждой ветви отказа, deferred effects и goroutines.

**Уязвимый вариант:**

http.Error(w, ..., 403) записывает ответ, но не прекращает handler; затем данные читаются/меняются.

**Исправление:** Явный return до побочного эффекта; auth-result обязателен на всех путях, включая helper.

**Проверка:** Отказ не меняет БД и не дописывает приватный body; свой запрос работает.

<a id="go-json-fields"></a>

<a id="go-json-fields-json-entities-and-ambiguous-keys"></a>

## GO-JSON-FIELDS. JSON в entity и неоднозначные ключи

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'json.NewDecoder|json.Unmarshal|Decode\(|DisallowUnknownFields' .
~~~

Сверить exported поля entity, теги и повторные/разнорегистровые ключи; DisallowUnknownFields не решает дубли.

**Уязвимый вариант:**

Decode в модель принимает Owner/Role либо парсеры по-разному выбирают повторный ключ.

**Исправление:** Отдельный DTO, разрешённые поля, проверка EOF и типов; при подписи строгая политика дублей/канонизации.

**Проверка:** Лишнее auth-поле, второй JSON-документ, null и повторные ключи; штатный payload.

<a id="go-race"></a>

<a id="go-race-shared-mapslice-state-and-check-then-use"></a>

## GO-RACE. Общие map/slice и check-then-use

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'map\[|sync.Mutex|RWMutex|go func|LoadOrStore|owner' .
~~~

Определить владельца shared state; блокировка должна охватывать проверку и изменение, не отдельные обращения.

**Уязвимый вариант:**

Две goroutine проходят проверку баланса/прав и затем обе изменяют состояние.

**Исправление:** Атомарная операция/критическая секция либо транзакция БД; не удерживать глобальный lock на медленном I/O.

**Проверка:** Barrier-тест инварианта и race detector на подготовленном стенде; отсутствие race-отчёта не доказывает отсутствие логической гонки.

<a id="go-error-default"></a>

<a id="go-error-default-ignored-errors-produce-a-zero-principal"></a>

## GO-ERROR-DEFAULT. Игнорирование ошибки даёт нулевого субъекта

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'ParseInt|Atoi|Unmarshal|Verify|Find|_, _|err' .
~~~

Найти игнорируемые ошибки parse/auth/DB; проверить, не означает ли zero ID глобальный/default объект.

**Уязвимый вариант:**

id, _ := strconv.Atoi(input) превращает неправильный ввод в 0, который имеет особые права.

**Исправление:** Проверять ошибку и допустимый диапазон до операции; различать not found и backend failure.

**Проверка:** Неправильный ID/таймаут БД не авторизуют и не возвращают чужое; допустимый ноль по контракту обработан явно.

<a id="go-ssrf"></a>

<a id="go-ssrf-http-clients-and-redirects"></a>

## GO-SSRF. Go HTTP client и redirects

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'http.Get|Client.Do|NewRequest|CheckRedirect|DialContext' .
~~~

Проследить custom transport, redirect policy, DNS и повторное использование соединения.

**Уязвимый вариант:**

URL проверен до Client.Do, но redirect/transport уводит запрос к другому назначению.

**Исправление:** Фиксированные назначения либо единая policy URL/redirect/соединения, timeouts и лимит body; не блокировать легитимную private сеть без контракта.

**Проверка:** Mock redirect/DNS/timeout, обычный upstream, oversized response.

**Основание:** [первичный материал](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

<a id="go-zip-path"></a>

<a id="go-zip-path-filepathjoin-does-not-enforce-containment"></a>

## GO-ZIP-PATH. filepath.Join не обеспечивает containment

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'archive/zip|archive/tar|filepath.Join|EvalSymlinks|MkdirAll' .
~~~

Найти имена entries и ссылок; сравнить очищенный путь с root и фактическую операцию открытия.

**Уязвимый вариант:**

Join(root, entry) используется для записи без проверки выхода/ссылок.

**Исправление:** Проверить relative path и тип entry, безопасное открытие внутри каталога с политикой symlink, лимиты и уборка.

**Проверка:** Вложенный допустимый путь, выход наружу, link entry и изменение родителя между проверкой и записью.

**Основание:** [первичный материал](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).

<a id="go-tls-min"></a>

<a id="go-tls-min-obsolete-minimum-tls-version"></a>

## GO-TLS-MIN. Явно разрешён устаревший TLS

**Поиск:** скрипт, правило GO-TLS-MIN. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain GO-TLS-MIN. Regex: MinVersion:tls.VersionSSL30/TLS10/TLS11 и присваивание .MinVersion = этим константам, включая переносы строк; ==/!=, TLS12/TLS13 и 0 не сигналят. VersionSSL30 — устаревшая настройка, современный Go не поддерживает SSLv3. Тип объекта, итоговую конфигурацию и версию Go проверять вручную; числовые версии, import aliases, переменные и настройки listener вне Go не вычисляются.

**Уязвимый вариант:** Настройка понижает минимум для используемого TLS-клиента
или сервера, если версия и режим runtime допускают эти старые протоколы.

~~~go
cfg := &tls.Config{}
cfg.MinVersion = tls.VersionTLS10
~~~

**Исправление:** Выбрать минимум TLS 1.2/1.3 по совместимости checker и peer;
сохранить проверку сертификата. Настроить Config до передачи TLS-функции:
после начала использования его менять нельзя.

~~~go
cfg := &tls.Config{}
cfg.MinVersion = tls.VersionTLS12
~~~

**Проверка:** Штатные peers соединяются; TLS ниже выбранного минимума отвергнут.
Проверить итоговый Config, обработку ошибки соединения и старых клиентов до
выкладки: поднятие минимума может нарушить совместимость.

Поле литерала `MinVersion: tls.VersionTLS10` и отдельное присваивание
`cfg.MinVersion = tls.VersionTLS10` требуют одинакового просмотра.
Сравнения `==`/`!=` не меняют настройку и не получают этот сигнал.
`TLS12`/`TLS13` и `0` также не сигналят; `0` означает default конкретного runtime,
а не подтверждённую политику безопасности.

`VersionSSL30` остаётся сигналом устаревшей настройки: наличие константы
не означает, что современный Go поддерживает SSLv3.
Версия, режим runtime и последующие переопределения влияют на реальное поведение.
[Go: tls.Config](https://pkg.go.dev/crypto/tls#Config),
[контракт MinVersion в Go 1.24](https://github.com/golang/go/blob/go1.24.0/src/crypto/tls/common.go#L756).

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'MinVersion|MaxVersion|TLSClientConfig|GetConfigForClient|crypto/tls|GODEBUG|GOFIPS140' .
~~~

Связать объект с реальным TLS-клиентом/listener и проверить все изменения,
возвращаемые callbacks конфигурации, aliases импорта, числовые константы и
значения из окружения. Regex не устанавливает тип объекта или достижимость
настройки и может совпасть с комментарием. Семантика сверена по первичным
исходникам; Go runtime и TLS-соединения в этой проверке не запускались.

<a id="go-jwt-unverified"></a>

<a id="go-jwt-unverified-jwt-without-signature-or-claims-verification"></a>

## GO-JWT-UNVERIFIED. JWT без подписи или проверки claims

**Поиск:** скрипт, правило GO-JWT-UNVERIFIED. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain GO-JWT-UNVERIFIED. Regex: ParseUnverified и WithoutClaimsValidation; не доказывает использование результата для auth. Пример относится к golang-jwt/jwt/v5.

**Уязвимый вариант:** Разобранный токен не равен проверенному; ошибка или отключённая валидация не должны вести к авторизации.

~~~go
token, _, err := parser.ParseUnverified(raw, &claims)
~~~

**Исправление:** Использовать валидирующий API с доверенным keyfunc, алгоритмами и claims; проверять err до использования token/claims.

~~~go
token, err := jwt.ParseWithClaims(raw, &claims, trustedKeyFunc, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("auth"), jwt.WithAudience("notes"), jwt.WithExpirationRequired())
if err != nil || !token.Valid { return ErrUnauthorized }
~~~

**Проверка:** Подпись/срок/адресат проверяются; nil token при ошибке не вызывает panic; штатный токен принимается.

Первичная документация: [документация 1](https://pkg.go.dev/github.com/golang-jwt/jwt/v5).

<a id="go-upload-path"></a>

<a id="go-upload-path-multipart-filename-used-directly-in-a-joined-path"></a>

## GO-UPLOAD-PATH. Имя multipart-файла напрямую включается в путь

**Поиск:** правило сканера GO-UPLOAD-PATH. Точный контракт детектора: `--explain GO-UPLOAD-PATH`. Regex с лексическими исключениями: filepath.Join с простым первым аргументом и прямым header/fileHeader/file.Filename во втором. MIME-парсер может нормализовать имя файла; правило не доказывает traversal, тип импортированного объекта или отсутствие предшествующей валидации.

**Уязвимый вариант:**

~~~go
path := filepath.Join(root, header.Filename)
~~~

**Исправление:** Выбирайте серверное имя хранения без перезаписи существующих файлов, вне исполняемых и публичных корней; проверяйте права на скачивание, размер и тип загрузки.

~~~go
path := filepath.Join(root, serverGeneratedID)
~~~

**Проверка:** Другие разделители, traversal, коллизии и запросы от другого владельца не меняют выбранный путь хранения; обычные загрузки работают.

[Первичный источник 1](https://pkg.go.dev/mime/multipart#FileHeader)
