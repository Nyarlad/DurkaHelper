<a id="java-find-fix-and-verify"></a>

# Java: поиск и исправление

[English](java.md) | Русский

[Вся база](README-RU.md) · [Сканер](../offline-scanner-RU.md) · [Проверка патча](../patch-validation-RU.md)

18 разделов. Формат: **Поиск → Уязвимый вариант → Исправление → Проверка**.
Команды `rg` выполняются в корне локальной копии сервиса и только читают файлы. Субъект/владелец определяется по проверенной сессии, а не данным запроса. Примеры нужно адаптировать к реальным API и контракту.

Автоматические находки — ограниченные синтаксические сигналы для проверки. AST-анализ не разрешает типы и не отслеживает данные между функциями; regex не заменяет парсер языка. Комментарии, строки и одноимённые пользовательские API могут давать совпадения. Проверьте фактическое исполнение, входные данные, авторизацию и границы доверия.

<a id="contents"></a>

## Содержание

- [JAVA-OBJECT — Java ObjectInputStream](#java-object)
- [JAVA-RNG — java.util.Random в возможном секрете](#java-rng)
- [JAVA-SQL — Динамический JDBC SQL](#java-sql)
- [JAVA-PROCESS — Запуск процесса Java](#java-process)
- [JAVA-JACKSON-TYPES — Jackson default typing](#java-jackson-types)
- [JAVA-XML — XML parser требует явной политики внешних ресурсов](#java-xml)
- [JAVA-EXPRESSION — Клиентский текст парсится как SpEL](#java-expression)
- [JAVA-PATH — Path resolve без ограничения корня](#java-path)
- [JAVA-ZIP-SLIP — ZipEntry становится выходным путём](#java-zip-slip)
- [JAVA-SPRING-BIND — Spring binding в domain entity](#java-spring-bind)
- [JAVA-SECURITY-MATCHER — Порядок matchers и method security](#java-security-matcher)
- [JAVA-THREADLOCAL — ThreadLocal переносит пользователя следующему запросу](#java-threadlocal)
- [JAVA-REGEX-DOS — Регулярное выражение блокирует поток](#java-regex-dos)
- [JAVA-JNDI — Недоверенное имя JNDI lookup](#java-jndi)
- [JAVA-ERROR-LEAK — Stack trace и SQL в API-ошибке](#java-error-leak)
- [JAVA-HOSTNAME-VERIFY — Hostname verifier принимает любой сервер](#java-hostname-verify)
- [JAVA-SPRING-CSRF — CSRF отключён в Spring Security](#java-spring-csrf)
- [JAVA-LDAP-FILTER — Фильтр поиска JNDI собирается конкатенацией](#java-ldap-filter)

<a id="java-object"></a>

<a id="java-object-java-objectinputstream"></a>

## JAVA-OBJECT. Java ObjectInputStream

**Поиск:** скрипт, правило JAVA-OBJECT. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JAVA-OBJECT. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~java
ObjectInputStream in = new ObjectInputStream(stream);
~~~

**Исправление:** Внешний вход — типизированный формат со схемой; legacy — план миграции и фильтрации типов.

~~~java
Message value = parseValidatedMessage(stream);
~~~

**Проверка:** Произвольный граф классов не загружается.

<a id="java-rng"></a>

<a id="java-rng-javautilrandom-near-a-possible-secret"></a>

## JAVA-RNG. java.util.Random в возможном секрете

**Поиск:** скрипт, правило JAVA-RNG. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JAVA-RNG. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~java
Random rng = new Random();
~~~

**Исправление:** Для секретов SecureRandom.nextBytes без предсказуемого seed; хеширование малого пространства не добавляет энтропию.

~~~java
SecureRandom rng = new SecureRandom();
~~~

**Проверка:** Нет предсказуемого seed или резервного генератора; challenge/token имеет достаточную энтропию и совместимый формат, штатные токены работают.

**Вариант A/D:** Публичный PRNG и секретный challenge. **Основание:** 8-bit-oracle, разбор автора и Java-код saarCTF.
Один java.util.Random использовался в публичных значениях и challenge.
Хеш 32-битного значения не создаёт большего пространства секретов.
Сканер: JAVA-RNG; наличие Random вне security-контекста допустимо.

**Патч:** SecureRandom.nextBytes достаточной длины без предсказуемого seed;
публичная статистика не использует состояние генератора секретов.
**Тест:** формат и одноразовость challenge, длина/источник случайности,
сохранение обычного потока проверки. Не считать статистический тест доказательством
криптографической стойкости.

[исходник/разбор 1](https://github.com/saarsec/saarctf-2024/blob/3a06d18974ca177c6dd251a11bdf9b4b334f382a/8-bit-oracle/README.md); [исходник/разбор 2](https://github.com/saarsec/saarctf-2024/blob/3a06d18974ca177c6dd251a11bdf9b4b334f382a/8-bit-oracle/service/_8BitOracle/src/Util.java).

<a id="java-sql"></a>

<a id="java-sql-dynamic-jdbc-sql"></a>

## JAVA-SQL. Динамический JDBC SQL

**Поиск:** скрипт, правило JAVA-SQL. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JAVA-SQL. Regex: executeQuery/executeUpdate/execute/prepareStatement/prepareCall с конкатенацией или String.format. PreparedStatement не защищает уже собранный SQL; переменные SQL и formatter wrappers вручную.

**Уязвимый вариант:**

~~~java
statement.executeQuery("SELECT id FROM notes WHERE name=" + name);
~~~

**Исправление:** PreparedStatement + setString/setLong; identifiers фиксировать.

~~~java
PreparedStatement q = connection.prepareStatement("SELECT id FROM notes WHERE name=?");
q.setString(1, name);
q.executeQuery();
~~~

**Проверка:** Кавычки остаются данными; проверка владельца сохраняется.

<details>
<summary>Развёрнутый пример и ограничения</summary>

```java
// Vulnerable: inputId is interpolated into SQL without an owner constraint.
ResultSet rs = statement.executeQuery("SELECT body FROM notes WHERE id = '" + inputId + "'");
```

**Патч JDBC для приватной заметки:**

```java
import java.sql.*;
import java.util.Optional;

final class NoteReader {
    static Optional<String> read(Connection db, Long userId, long noteId) throws SQLException {
        if (userId == null) throw new SecurityException("authentication required");
        try (PreparedStatement st = db.prepareStatement(
                "SELECT body FROM notes WHERE id = ? AND owner_id = ?")) {
            st.setLong(1, noteId);
            st.setLong(2, userId);
            try (ResultSet rows = st.executeQuery()) {
                return rows.next() ? Optional.of(rows.getString("body")) : Optional.empty();
            }
        }
    }
}
```

Пример предполагает `body NOT NULL`. Если схема разрешает NULL, сохранить
его семантику отдельно от отсутствующей строки. Закрываются statement/result set,
но не переданное соединение: его жизненным циклом управляет вызывающий код.
Входной ID парсится с обработкой ошибок. `PreparedStatement` с уже склеенной
SQL-строкой не исправляет проблему.

**Проверить:** своё/чужое/аноним; неверный и отсутствующий ID; прежние данные;
ошибка БД не выдаёт успешный пустой ответ.

</details>

<a id="java-process"></a>

<a id="java-process-java-process-execution"></a>

## JAVA-PROCESS. Запуск процесса Java

**Поиск:** скрипт, правило JAVA-PROCESS. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JAVA-PROCESS. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~java
Runtime.getRuntime().exec(command);
~~~

**Исправление:** Предпочитать библиотечную операцию либо фиксированную программу с проверенными argv и ограничениями времени и вывода. ProcessBuilder не всегда shell, но shell -c и выбор executable клиентом опасны.

~~~java
runValidatedConversion(inputPath); // fixed executable and validated argv inside
~~~

**Проверка:** Клиент не меняет программу/опасные опции; конвертация работает.

<details>
<summary>Развёрнутый пример и ограничения</summary>

```java
// Vulnerable: ProcessBuilder does not protect an explicit shell command.
Process p = new ProcessBuilder("sh", "-c", "printf '%s' '" + text + "' | sha256sum").start();
```

**Патч для SHA-256 строки:**

```java
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

final class ContentDigest {
    static String of(String text) throws NoSuchAlgorithmException {
        byte[] sum = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(sum);
    }
}
```

`HexFormat` требует Java 17; на старом runtime использовать существующее
проверенное кодирование hex, не обновлять весь сервис ради этого примера.
Не делить один изменяемый `MessageDigest` между потоками. Сохранить ожидаемый
формат ответа; этот digest не заменяет алгоритм хранения паролей.

**Проверить:** известный digest, пустой текст, Unicode и кавычки; `null` отклонён
на входе API; внешняя программа не запускается.

</details>

<a id="java-jackson-types"></a>

<a id="java-jackson-types-jackson-default-typing"></a>

## JAVA-JACKSON-TYPES. Jackson default typing

**Поиск:** скрипт, правило JAVA-JACKSON-TYPES. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JAVA-JACKSON-TYPES. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~java
mapper.enableDefaultTyping();
~~~

**Исправление:** Конкретные DTO; если полиморфизм необходим — ограниченный набор подтипов/валидатор своей версии, не package-wide allowlist.

~~~java
// deserialize into a fixed DTO without client-selected implementation types
~~~

**Проверка:** Неизвестный тип отвергается до побочных эффектов; старый допустимый документ читается.

**Основание:** [первичный материал](https://github.com/FasterXML/jackson-docs/wiki/JacksonPolymorphicDeserialization).

<a id="java-xml"></a>

<a id="java-xml-xml-parser-needs-an-external-resource-policy"></a>

## JAVA-XML. XML parser требует явной политики внешних ресурсов

**Поиск:** скрипт, правило JAVA-XML. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JAVA-XML. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~java
var f = DocumentBuilderFactory.newInstance();
~~~

**Исправление:** Ограничить DTD/entities/schema/XSLT для конкретного factory, включить лимиты. Неподдержанный security feature не игнорировать.

~~~java
var f = DocumentBuilderFactory.newInstance();
f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
// also configure DTD/entity policy and parser-specific limits
~~~

**Проверка:** Parser не читает внешние файлы/URL; допустимый XML и лимиты работают.

**Основание:** [первичный материал](https://docs.oracle.com/en/java/javase/17/security/java-api-xml-processing-jaxp-security-guide.html).

<a id="java-expression"></a>

<a id="java-expression-client-text-parsed-as-spel"></a>

## JAVA-EXPRESSION. Клиентский текст парсится как SpEL

**Поиск:** скрипт, правило JAVA-EXPRESSION. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JAVA-EXPRESSION. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~java
parser.parseExpression(input).getValue(context);
~~~

**Исправление:** Фиксированные операции и аргументы; если DSL нужен, минимальная грамматика и возможности evaluation context. Не отдавать полный reflection клиенту.

~~~java
lookupAllowedOperation(operationId, validatedArguments);
~~~

**Проверка:** Запрещённые операции не достигают runtime; разрешённые вычисления сохранены.

**Основание:** [первичный материал](https://docs.spring.io/spring-framework/reference/core/expressions.html).

<a id="java-path"></a>

<a id="java-path-path-resolve-without-a-root-boundary"></a>

## JAVA-PATH. Path resolve без ограничения корня

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'resolve\(|readAllBytes|new File|Paths.get|toRealPath' .
~~~

Сравнить Path root и target после нормализации/разрешения ссылки; проверить ownership и гонку открытия.

**Уязвимый вариант:**

Files.readAllBytes(base.resolve(name)) читает имя клиента без границы.

**Исправление:** Серверное имя из авторизованного ID либо Path containment, отдельная политика symlink и безопасное открытие; лимит чтения.

**Проверка:** Соседний каталог с общим префиксом, absolute path, symlink, чужой объект и штатный файл.

<details>
<summary>Развёрнутый пример и ограничения</summary>

```java
// Vulnerable: name can move the read outside the permitted directory.
byte[] data = Files.readAllBytes(base.resolve(name));
```

**Патч для существующих файлов в доверенном неизменяемом дереве:**

```java
import java.io.IOException;
import java.nio.file.*;

final class FileBoundary {
    static Path existingFile(Path base, String name) throws IOException {
        if (name == null || name.isEmpty()) throw new IllegalArgumentException("path required");
        Path relative = Path.of(name);
        if (relative.isAbsolute()) throw new IllegalArgumentException("relative path required");
        Path root = base.toRealPath();
        Path target = root.resolve(relative).toRealPath();
        if (!target.startsWith(root) || !Files.isRegularFile(target)) {
            throw new IllegalArgumentException("outside allowed directory");
        }
        return target;
    }
}
```

Здесь `startsWith` — метод **Path**, не строковое сравнение. `toRealPath` требует
существования и учитывает symlink. Если дерево может меняться между проверкой
и открытием, остаётся TOCTOU: нужен подход с безопасным открытием относительно
каталога, поддержанный платформой. Этот фрагмент не предназначен для записи
или распаковки архивов. Проверка права на файл и лимит чтения требуются отдельно.

**Проверить:** разрешённый файл, соседний каталог с похожим именем, абсолютный
путь, ссылка наружу, отсутствие файла, файл другого пользователя.

</details>

**Основание:** [первичный материал](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/nio/file/Path.html).

<a id="java-zip-slip"></a>

<a id="java-zip-slip-zipentry-becomes-an-output-path"></a>

## JAVA-ZIP-SLIP. ZipEntry становится выходным путём

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'ZipInputStream|ZipFile|getName\(|resolve\(' .
~~~

Пройти каждый entry → target → write, включая имена каталогов и metadata links.

**Уязвимый вариант:**

Имя из архива присоединено к каталогу без containment и контроля фактического дерева.

**Исправление:** Валидировать все пути/типы, не следовать недоверенным ссылкам, ограничить размер/entries и публиковать после успеха.

**Проверка:** Обычный архив, absolute/traversal entry, превышение объёма и уборка при отказе.

**Основание:** [первичный материал](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).

<a id="java-spring-bind"></a>

<a id="java-spring-bind-spring-binds-request-data-into-a-domain-entity"></a>

## JAVA-SPRING-BIND. Spring binding в domain entity

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e '@ModelAttribute|@RequestBody|DataBinder|setAllowedFields|BeanUtils' .
~~~

Сверить публичные setters, nested properties и поля владельца с данными запроса.

**Уязвимый вариант:**

Binder пишет owner/admin/status в entity до проверки доступа.

**Исправление:** Отдельный request DTO с разрешёнными полями и явное копирование после auth; ограничения вложенных путей.

**Проверка:** Служебные поля и nested update не меняются; допустимое частичное обновление работает.

<a id="java-security-matcher"></a>

<a id="java-security-matcher-matcher-ordering-and-method-security"></a>

## JAVA-SECURITY-MATCHER. Порядок matchers и method security

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'SecurityFilterChain|requestMatchers|permitAll|PreAuthorize|EnableMethodSecurity' .
~~~

Проверить первый подходящий matcher, все HTTP-методы, dispatch types и включение method security.

**Уязвимый вариант:**

Широкий permitAll срабатывает раньше приватного правила; аннотация метода не активна.

**Исправление:** Явная политика маршрутов с отказом по умолчанию для приватной области, проверка ресурса в service; согласовать публичные endpoint.

**Проверка:** Аноним, обычный user и admin проходят ожидаемые маршруты/методы; error/forward не обходят auth.

<a id="java-threadlocal"></a>

<a id="java-threadlocal-threadlocal-leaks-the-previous-requests-user"></a>

## JAVA-THREADLOCAL. ThreadLocal переносит пользователя следующему запросу

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'ThreadLocal|SecurityContext|Executor|CompletableFuture|remove\(' .
~~~

Сверить set/remove в finally и передачу контекста в thread pool.

**Уязвимый вариант:**

Поток переиспользуется после исключения с прежним principal.

**Исправление:** Штатный security-context lifecycle или явная очистка; async task получает минимальный неизменяемый контекст.

**Проверка:** Последовательные разные пользователи на одном worker и исключение между установкой/очисткой.

<a id="java-regex-dos"></a>

<a id="java-regex-dos-a-regular-expression-blocks-a-worker"></a>

## JAVA-REGEX-DOS. Регулярное выражение блокирует поток

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Pattern.compile|Matcher|matches\(|replaceAll' .
~~~

Проверить вложенные квантификаторы и почти совпадающие длинные строки; timeout запроса не обязательно прерывает matcher.

**Уязвимый вариант:**

Backtracking на вводе клиента занимает worker вне установленного HTTP timeout.

**Исправление:** Упростить паттерн/детерминированный parser, ограничить длину, при нужде совместимый движок с ограниченной сложностью.

**Проверка:** Длинный неуспешный match завершается в бюджете; обычный формат и Unicode сохранены.

<a id="java-jndi"></a>

<a id="java-jndi-dynamic-jndi-lookup-name"></a>

## JAVA-JNDI. Недоверенное имя JNDI lookup

**Поиск:** скрипт, правило JAVA-JNDI. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JAVA-JNDI. Regex: InitialContext.doLookup или ctx/context/initialContext.lookup с нестроковым аргументом. Произвольные имена объектов и косвенные вызовы искать вручную.

Дополнительный ручной поиск для непокрытых форм:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'InitialContext|JndiTemplate|lookup\(|NamingManager' .
~~~

Проследить имя/provider URL и локальные object factories; ограничения удалённого codebase не отменяют остальные эффекты.

**Уязвимый вариант:**

Клиент выбирает ресурс/службу для lookup с привилегиями приложения.

**Исправление:** Закрытая серверная карта доверенных локальных имён, ограниченные providers/factories и совместимый исправленный runtime. Обновление JDK не заменяет проверку входных данных.

**Проверка:** Чужая схема/имя не вызывает lookup; штатный datasource работает.


**Сигнал сканера — пример до:**

~~~java
Object value = context.lookup(requestName);
~~~

**Шаблон исправления:**

~~~java
Object value = context.lookup("java:comp/env/jdbc/Notes");
~~~

Первичная документация: [документация 1](https://docs.oracle.com/en/java/javase/21/docs/api/java.naming/javax/naming/InitialContext.html).

<a id="java-error-leak"></a>

<a id="java-error-leak-stack-traces-and-sql-in-api-errors"></a>

## JAVA-ERROR-LEAK. Stack trace и SQL в API-ошибке

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'printStackTrace|getMessage\(|ResponseEntity|ExceptionHandler' .
~~~

Сравнить локальный журнал и клиентский body для ошибок auth/SQL/parser.

**Уязвимый вариант:**

Клиент получает SQL, пути, connection string или секретные параметры из exception.

**Исправление:** Штатная кодированная ошибка и correlation ID; чувствительные значения редактировать до логирования.

**Проверка:** Диагностика остаётся локально, ответы ошибок не содержат приватных данных.

<a id="java-hostname-verify"></a>

<a id="java-hostname-verify-hostname-verifier-accepts-every-peer"></a>

## JAVA-HOSTNAME-VERIFY. Hostname verifier принимает любой сервер

**Поиск:** скрипт, правило JAVA-HOSTNAME-VERIFY. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JAVA-HOSTNAME-VERIFY. Regex: NoopHostnameVerifier/ALLOW_ALL_HOSTNAME_VERIFIER и setHostnameVerifier с простой true-lambda; сложные callbacks и TrustManager требуют ручного анализа.

**Уязвимый вариант:** Проверка цепочки сертификата без имени не подтверждает нужный сервер.

~~~java
builder.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE);
~~~

**Исправление:** Вернуть стандартный verifier и доверенный trust store; не подменять его callback, всегда возвращающим true.

~~~java
builder.setSSLHostnameVerifier(new DefaultHostnameVerifier());
~~~

**Проверка:** Сертификат доверенного CA для другого hostname отклоняется; свой endpoint работает.

Первичная документация: [документация 1](https://hc.apache.org/httpcomponents-client-5.5.x/current/httpclient5/apidocs/org/apache/hc/client5/http/ssl/NoopHostnameVerifier.html).

<a id="java-spring-csrf"></a>

<a id="java-spring-csrf-spring-security-csrf-disabled"></a>

## JAVA-SPRING-CSRF. CSRF отключён в Spring Security

**Поиск:** скрипт, правило JAVA-SPRING-CSRF. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain JAVA-SPRING-CSRF. Regex: csrf().disable(), csrf(x -> x.disable()) и csrf(AbstractHttpConfigurer::disable). Отдельные security chains и матчеры просматривать вручную.

**Уязвимый вариант:** Cookie-auth операции могут потерять CSRF-защиту при глобальном disable.

~~~java
http.csrf(csrf -> csrf.disable());
~~~

**Исправление:** Сохранить защиту браузерных запросов; исключения ограничить конкретным bearer/webhook контрактом и проверить отсутствие cookie fallback.

~~~java
http.csrf(Customizer.withDefaults());
~~~

**Проверка:** Штатный запрос с CSRF работает, cookie POST без токена отвергнут; разрешённый API сценарий не сломан.

Первичная документация: [документация 1](https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html).

<a id="java-ldap-filter"></a>

<a id="java-ldap-filter-jndi-search-filter-assembled-by-concatenation"></a>

## JAVA-LDAP-FILTER. Фильтр поиска JNDI собирается конкатенацией

**Поиск:** правило сканера JAVA-LDAP-FILTER. Точный контракт детектора: `--explain JAVA-LDAP-FILTER`. Regex с лексическими исключениями: ctx/context/dirContext.search с простым первым аргументом и напрямую склеенным строковым фильтром. Не разрешает тип получателя, заранее собранные фильтры, wrappers и предшествующее экранирование.

**Уязвимый вариант:**

~~~java
ctx.search(base, "(uid=" + name + ")", controls);
~~~

**Исправление:** Используйте аргументы фильтра JNDI с фиксированным фильтром; сохраняйте явную область поиска и авторизацию.

~~~java
ctx.search(base, "(uid={0})", new Object[] { name }, controls);
~~~

**Проверка:** Метасимволы фильтра остаются значениями; недоступные пользователю записи не раскрываются, а допустимые поиски работают.

[Первичный источник 1](https://docs.oracle.com/javase/jndi/tutorial/ldap/search/search.html)
