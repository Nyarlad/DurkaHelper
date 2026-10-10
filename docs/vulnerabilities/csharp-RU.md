<a id="c--net-find-fix-and-verify"></a>

# C# / .NET: поиск и исправление

[English](csharp.md) | Русский

[Вся база](README-RU.md) · [Сканер](../offline-scanner-RU.md) · [Проверка патча](../patch-validation-RU.md)

20 разделов. Формат: **Поиск → Уязвимый вариант → Исправление → Проверка**.
Команды `rg` выполняются в корне локальной копии сервиса и только читают файлы. Субъект/владелец определяется по проверенной сессии, а не данным запроса. Примеры нужно адаптировать к реальным API и контракту.

Автоматические находки — ограниченные синтаксические сигналы для проверки. AST-анализ не разрешает типы и не отслеживает данные между функциями; regex не заменяет парсер языка. Комментарии, строки и одноимённые пользовательские API могут давать совпадения. Проверьте фактическое исполнение, входные данные, авторизацию и границы доверия.

<a id="contents"></a>

## Содержание

- [CS-DESERIALIZE — Типы при десериализации .NET](#cs-deserialize)
- [CS-ENUM — Enum.TryParse требует проверки диапазона](#cs-enum)
- [CS-SQL — Динамический SQL .NET](#cs-sql)
- [CS-GUID-BYTES — Байтовый Guid на границе протокола](#cs-guid-bytes)
- [CS-PROCESS — Создание процесса .NET](#cs-process)
- [CS-IGNORE-FILTERS — Отключение global query filters](#cs-ignore-filters)
- [CS-ALLOWANON — Маршрут с AllowAnonymous](#cs-allowanon)
- [CS-MASS-ASSIGN — Клиентская сущность целиком обновляет БД](#cs-mass-assign)
- [CS-XML — XML settings и внешние ресурсы](#cs-xml)
- [CS-HTML-RAW — Html.Raw и IHtmlContent обходят encoding](#cs-html-raw)
- [CS-PATH — Path.Combine и GetFullPath не проверяют owner](#cs-path)
- [CS-ARCHIVE — ZipArchive entry выходит из каталога](#cs-archive)
- [CS-CLAIMS — Неполная проверка JWT/claims](#cs-claims)
- [CS-ASYNC-VOID — async void скрывает ошибку auth](#cs-async-void)
- [CS-REGEX-TIMEOUT — Regex без бюджета на недоверенном вводе](#cs-regex-timeout)
- [CS-AUTH-FILTER-REDUCE — Упрощение фильтра удаляет обязательное условие доступа](#cs-auth-filter-reduce)
- [CS-COLLIDING-PRINCIPAL — Нормализованная сумма символов вместо уникального user ID](#cs-colliding-principal)
- [CS-JWT-VALIDATION — Ослаблены параметры проверки токенов .NET](#cs-jwt-validation)
- [CS-TLS-VALIDATION — HTTPS validation callback всегда разрешает](#cs-tls-validation)
- [CS-LDAP-FILTER — Фильтр DirectorySearcher собирается конкатенацией](#cs-ldap-filter)

<a id="cs-deserialize"></a>

<a id="cs-deserialize-type-controlled-net-deserialization"></a>

## CS-DESERIALIZE. Типы при десериализации .NET

**Поиск:** скрипт, правило CS-DESERIALIZE. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CS-DESERIALIZE. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~csharp
var formatter = new BinaryFormatter();
~~~

**Исправление:** Явные DTO и поддержанный сериализатор, например System.Text.Json, с проверками схемы и размера; убрать неограниченное создание runtime-типов и мигрировать старые данные.

~~~csharp
var value = JsonSerializer.Deserialize<MessageDto>(json); // validate fields
~~~

**Проверка:** Произвольный тип не создаётся; старые записи мигрируют.

**Вариант A/D:** Десериализация запускает побочные эффекты сеттеров. **FAUST / todo-list, код + патч организаторов.** TypeNameHandling.Objects
позволяет выбрать runtime-тип; у модели Filter установка полей вызывает запись
в БД. Проверка результата после создания объекта может быть слишком поздней.

**Патч:** конкретный DTO без внешнего выбора типа, явная валидация и отдельная
операция сохранения. **Тест:** неизвестный тип не создаёт ни объект, ни запись;
штатный импорт/экспорт сохранён. **Поиск:** CS-DESERIALIZE.

[исходник/разбор 1](https://github.com/fausecteam/faustctf-2024-todo-list-service/blob/e9ee8b8807c64eeb6f71a72e16f709a558525d2c/patches/deserialize.patch); [исходник/разбор 2](https://github.com/fausecteam/faustctf-2024-todo-list-service/blob/e9ee8b8807c64eeb6f71a72e16f709a558525d2c/patches/TodoController.cs); [исходник/разбор 3](https://github.com/fausecteam/faustctf-2024-todo-list-service/blob/e9ee8b8807c64eeb6f71a72e16f709a558525d2c/service/service/Services/Serializer.cs); [исходник/разбор 4](https://github.com/fausecteam/faustctf-2024-todo-list-service/blob/e9ee8b8807c64eeb6f71a72e16f709a558525d2c/service/service/Services/UserManager.cs); [исходник/разбор 5](https://github.com/fausecteam/faustctf-2024-todo-list-service/blob/e9ee8b8807c64eeb6f71a72e16f709a558525d2c/service/service/Models/Filter.cs).

<a id="cs-enum"></a>

<a id="cs-enum-enumtryparse-requires-an-allowed-value-check"></a>

## CS-ENUM. Enum.TryParse требует проверки диапазона

**Поиск:** скрипт, правило CS-ENUM. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CS-ENUM. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~csharp
bool ok = Enum.TryParse(input, out FilterKind kind);
~~~

**Исправление:** После TryParse проверять Enum.IsDefined или явный набор; для Flags — разрешённая маска. Сигнал останется при правильном inline-патче.

~~~csharp
if (!TryParseAllowedFilter(input, out FilterKind kind)) return BadRequest(); // helper validates named allowlist
~~~

**Проверка:** Необъявленные числа/неразрешённые биты отвергаются; штатные фильтры доступны.

**Вариант A/D:** Числовое значение enum вне разрешённого набора. **Основание:** sneakers, авторский разбор RuCTF. TryParse может принять число,
которому не соответствует объявленное имя.
Сканер: CS-ENUM, в том числе на уже исправленных вызовах.

~~~csharp
if (!Enum.TryParse<FilterKind>(input, out var kind) ||
    !Enum.IsDefined(typeof(FilterKind), kind))
    return BadRequest();
~~~

Для Flags требуется отдельная разрешённая маска и политика комбинаций.
**Тест:** все допустимые имена, необъявленные числа, отрицательные/слишком
большие значения и комбинации. Это проверка значения, а не замена auth.

[исходник/разбор 1](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/sneakers/README.md).

<a id="cs-sql"></a>

<a id="cs-sql-dynamic-net-sql"></a>

## CS-SQL. Динамический SQL .NET

**Поиск:** скрипт, правило CS-SQL. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CS-SQL. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~csharp
context.Notes.FromSqlRaw("SELECT * FROM notes WHERE name=" + name);
~~~

**Исправление:** Параметризованный API конкретной ORM или провайдера и разрешённый набор идентификаторов; различать Raw и интерполируемый overload.

~~~csharp
context.Notes.FromSqlRaw("SELECT * FROM notes WHERE name={0}", name);
~~~

**Проверка:** Кавычки — данные; owner_id сохраняется.

<details>
<summary>Развёрнутый пример и ограничения</summary>

```csharp
// Vulnerable: interpolation has already put client data into SQL source.
var rows = await db.Notes
    .FromSqlRaw($"SELECT * FROM Notes WHERE Title = '{title}'")
    .ToListAsync(ct);
```

**Минимальный патч для простого поиска — LINQ с ограничением владельца:**

```csharp
using Microsoft.EntityFrameworkCore;

var rows = await db.Notes
    .Where(n => n.OwnerId == currentUserId && n.Title == title)
    .ToListAsync(ct);
```

Если сырой SQL нужен, `FromSqlInterpolated` принимает интерполированное выражение
как `FormattableString` и параметризует значения. Не преобразовывать его сначала
в обычную `string` и не возвращать затем в `FromSqlRaw`. Метод `FromSql` появился
в EF Core 7; выбрать API своей версии. Имена колонок требуют фиксированного выбора.

**Проверить:** имя с апострофом/Unicode ищется буквально, чужие записи отсутствуют,
пагинация и старые данные работают. Кастомный провайдер и перевод LINQ проверить
на используемой БД, не только на in-memory substitute.

</details>

<a id="cs-guid-bytes"></a>

<a id="cs-guid-bytes-byte-order-guid-protocol-boundary"></a>

## CS-GUID-BYTES. Байтовый Guid на границе протокола

**Поиск:** скрипт, правило CS-GUID-BYTES. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CS-GUID-BYTES. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~csharp
var value = new Guid(wireBytes);
~~~

**Исправление:** Согласовать порядок байтов с другой стороной; использовать canonical text либо явное преобразование по протоколу, не разворачивать весь массив наугад.

~~~csharp
var value = Guid.ParseExact(wireText, "D");
~~~

**Проверка:** Несимметричные известные UUID совпадают в C#/Python; DB и cache сравнивают тот же ID.

<a id="cs-process"></a>

<a id="cs-process-net-process-creation"></a>

## CS-PROCESS. Создание процесса .NET

**Поиск:** скрипт, правило CS-PROCESS. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CS-PROCESS. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~csharp
Process.Start("sh", "-c " + command);
~~~

**Исправление:** Библиотечная операция либо фиксированный executable и ArgumentList. UseShellExecute=false не отменяет явный sh/cmd; учитывать option injection.

~~~csharp
var digest = SHA256.HashData(Encoding.UTF8.GetBytes(text));
~~~

**Проверка:** Кавычки — данные, штатный формат результата совпадает.

<details>
<summary>Развёрнутый пример и ограничения</summary>

```csharp
// Vulnerable on Linux: UseShellExecute=false does not prevent explicit /bin/sh.
var psi = new System.Diagnostics.ProcessStartInfo("/bin/sh") { UseShellExecute = false };
psi.ArgumentList.Add("-c");
psi.ArgumentList.Add("printf '%s' '" + text + "' | sha256sum");
System.Diagnostics.Process.Start(psi);
```

**Патч для SHA-256 текста, .NET 6+:**

```csharp
using System.Security.Cryptography;
using System.Text;

static string DigestText(string text)
{
    ArgumentNullException.ThrowIfNull(text);
    byte[] sum = SHA256.HashData(Encoding.UTF8.GetBytes(text));
    return Convert.ToHexString(sum).ToLowerInvariant();
}
```

Сохранить внешний формат результата и кодировку. Для действительно необходимого
процесса задавать executable и `ArgumentList` отдельно; пользователь всё ещё
не должен выбирать опасные опции программы. SHA-256 содержимого не подходит
как самостоятельное хранение паролей.

**Проверить:** известный digest, пустой текст, Unicode, кавычки и переводы строк;
нет дочернего процесса и утечки его окружения при ошибке.

</details>

**Основание:** [первичный материал](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo.argumentlist).

<a id="cs-ignore-filters"></a>

<a id="cs-ignore-filters-global-query-filters-disabled"></a>

## CS-IGNORE-FILTERS. Отключение global query filters

**Поиск:** скрипт, правило CS-IGNORE-FILTERS. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CS-IGNORE-FILTERS. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~csharp
var rows = db.Notes.IgnoreQueryFilters().ToList();
~~~

**Исправление:** Не отключать tenant/auth-фильтр ради soft-delete. Если bypass нужен администратору, явная авторизация и нужное ограничение в самом запросе.

~~~csharp
var rows = db.Notes.Where(n => n.OwnerId == userId).ToList();
~~~

**Проверка:** Два tenant, удалённая запись и export; проверять SQL реального провайдера.

**Основание:** [первичный материал](https://learn.microsoft.com/en-us/ef/core/querying/filters).

<a id="cs-allowanon"></a>

<a id="cs-allowanon-allowanonymous-route"></a>

## CS-ALLOWANON. Маршрут с AllowAnonymous

**Поиск:** скрипт, правило CS-ALLOWANON. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CS-ALLOWANON. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~csharp
[AllowAnonymous]
public IActionResult PrivateNote() => View();
~~~

**Исправление:** Проверить effective metadata endpoint и ownership. AllowAnonymous может отменить требование Authorize; login/health могут быть публичными по контракту.

~~~csharp
[Authorize]
public IActionResult PrivateNote() => View();
~~~

**Проверка:** Публичный login работает; приватный endpoint и вложенные операции требуют нужные права.

**Основание:** [первичный материал](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/simple).

<a id="cs-mass-assign"></a>

<a id="cs-mass-assign-client-entities-update-the-database-wholesale"></a>

## CS-MASS-ASSIGN. Клиентская сущность целиком обновляет БД

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Update\(|TryUpdateModelAsync|Bind\(|FromBody|SaveChanges' .
~~~

Сверить DTO, entity и изменяемые поля; не передаётся ли второй объект клиента после безопасной загрузки.

**Уязвимый вариант:**

db.Update(clientNote) применяет OwnerId/Role из JSON.

**Исправление:** DTO редактируемых полей, загрузка по ID+owner, явные присваивания; concurrency token если права могут меняться.

**Проверка:** Своё меняется, чужое и owner нет; null/отсутствующее поле различаются по контракту.

<details>
<summary>Развёрнутый пример и ограничения</summary>

```csharp
// Vulnerable: the supplied entity may contain OwnerId and administrative fields.
db.Update(clientNote);
await db.SaveChangesAsync(ct);
```

**Патч:** отдельный DTO редактируемых полей и загрузка принадлежащей пользователю
сущности. Тип DTO объявляется в проекте:

```csharp
public sealed record EditNoteRequest(string? Title, string? Body);
```

Фрагмент действия контроллера с параметрами `id` и `EditNoteRequest dto`:

```csharp
if (dto.Title is null || dto.Body is null)
    return BadRequest();

var note = await db.Notes.SingleOrDefaultAsync(
    n => n.Id == id && n.OwnerId == currentUserId, ct);
if (note is null)
    return NotFound();

note.Title = dto.Title;
note.Body = dto.Body;
await db.SaveChangesAsync(ct);
return NoContent();
```

Показан контракт полного обновления обоих полей, не JSON Merge Patch. При
частичном обновлении отдельно различать отсутствующее поле и явный `null`.
Не передавать в `Update` второй объект из запроса после загрузки безопасного.
Если владельца можно менять конкурентно, проверка при чтении и последующая
запись требуют подходящей транзакции/условного обновления/concurrency token.

**Проверить:** владелец меняет title/body; чужая запись и её владелец не меняются;
присланный OwnerId не применяется; пустая строка сохраняется, если разрешена;
неверный тип отвергается. Неизвестные JSON-поля могут игнорироваться сериализатором —
не обещать их автоматический отказ без отдельной настройки.

</details>

**Основание:** [первичный материал](https://learn.microsoft.com/en-us/aspnet/core/mvc/models/model-binding).

<a id="cs-xml"></a>

<a id="cs-xml-xml-parser-permits-dtd-or-external-resolver"></a>

## CS-XML. XML settings и внешние ресурсы

**Поиск:** скрипт, правило CS-XML. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CS-XML. Regex: DtdProcessing.Parse, XmlResolver=new XmlUrlResolver, ProhibitDtd=false. Точные defaults зависят от framework/API; отсутствие опасной строки не доказывает безопасность.

Дополнительный ручной поиск для непокрытых форм:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'XmlReaderSettings|DtdProcessing|XmlResolver|XmlDocument|XslCompiledTransform' .
~~~

Проверить явные settings и версию .NET; безопасные defaults нельзя переносить на каждый старый API.

**Уязвимый вариант:**

Разрешённый DTD/resolver загружает внешние ресурсы либо раздувает документ.

**Исправление:** DtdProcessing.Prohibit при ненужном DTD, XmlResolver=null и лимиты входа; передать настройки фактически используемому XmlReader. Для XSLT отдельно запретить ненужные document/script.

**Проверка:** Допустимый XML читается, внешние обращения отсутствуют, oversized expansion ограничен.

**Основание:** [первичный материал](https://learn.microsoft.com/en-us/dotnet/api/system.xml.xmlreadersettings).


**Сигнал сканера — пример до:**

~~~csharp
var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() };
~~~

**Шаблон исправления:**

~~~csharp
var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 1048576 };
~~~

Первичная документация: [документация 1](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca3075).

<a id="cs-html-raw"></a>

<a id="cs-html-raw-html-output-without-escaping"></a>

## CS-HTML-RAW. Html.Raw и IHtmlContent обходят encoding

**Поиск:** скрипт, правило CS-HTML-RAW. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CS-HTML-RAW. Regex: Html.Raw и new HtmlString. Проверенный sanitizer не выводится из наличия вызова; доверенная статическая разметка может быть допустима.

Дополнительный ручной поиск для непокрытых форм:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Html.Raw|HtmlString|IHtmlContent|WriteLiteral' .
~~~

Определить происхождение строки и реальный HTML/JS/attribute контекст Razor.

**Уязвимый вариант:**

Html.Raw(model.Text) выводит пользовательский HTML как доверенный.

**Исправление:** Штатный Razor encoding; sanitizer только когда rich text нужен, отдельная сериализация JS.

**Проверка:** Недоверенные теги, атрибуты и URL не могут выполнить скрипт; разрешённый текст и нужное форматирование отображаются корректно.


**Сигнал сканера — пример до:**

~~~csharp
@Html.Raw(Model.About)
~~~

**Шаблон исправления:**

~~~csharp
@Model.About
~~~

Первичная документация: [документация 1](https://learn.microsoft.com/en-us/aspnet/core/security/cross-site-scripting).

<a id="cs-path"></a>

<a id="cs-path-pathcombine-and-getfullpath-do-not-check-ownership"></a>

## CS-PATH. Path.Combine и GetFullPath не проверяют owner

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Path.Combine|GetFullPath|File.Read|File.Write|PhysicalFile' .
~~~

Сравнить полный путь/root с учётом ОС, separator и symlink; проверить право на выбранный ID.

**Уязвимый вариант:**

Абсолютный второй путь заменяет root либо строковый StartsWith путает соседний каталог.

**Исправление:** Серверное имя, корректный containment по компонентам, политика symlink; запись открывать без гонки подмены.

**Проверка:** Windows/Linux варианты, общий префикс, ссылка наружу, собственный/чужой файл.

<a id="cs-archive"></a>

<a id="cs-archive-ziparchive-entries-escape-the-directory"></a>

## CS-ARCHIVE. ZipArchive entry выходит из каталога

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'ZipArchive|ExtractToFile|ExtractToDirectory|FullName' .
~~~

Проверить конкретную версию API и собственный цикл по entries; наличие безопасного helper не защищает ручную запись.

**Уязвимый вариант:**

entry.FullName используется как путь без containment/лимита.

**Исправление:** Валидация root, links и фактического объёма, отдельное временное дерево и атомарная публикация.

**Проверка:** Штатный архив, absolute/traversal, дубли entry, превышение объёма.

**Основание:** [первичный материал](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).

<a id="cs-claims"></a>

<a id="cs-claims-incomplete-jwt-or-claims-validation"></a>

## CS-CLAIMS. Неполная проверка JWT/claims

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'TokenValidationParameters|ValidateIssuer|ValidateAudience|RequireExpirationTime|FindFirst' .
~~~

Сверить серверный issuer/audience/key/algorithm и трактовку отсутствующих claims; подпись не задаёт права объекта.

**Уязвимый вариант:**

Токен другого назначения принимается как auth либо отсутствующий subject превращается в default пользователя.

**Исправление:** Явный validation contract библиотеки, обязательный subject/purpose и resource auth; ротация ключа без бесконечного legacy fallback.

**Проверка:** Неверные issuer/audience/срок/назначение и валидная сессия со старыми данными.

<a id="cs-async-void"></a>

<a id="cs-async-void-async-void-hides-authorization-errors"></a>

## CS-ASYNC-VOID. async void скрывает ошибку auth

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'async void|Task.Run|Authorize|async Task|GetAwaiter' .
~~~

Проследить, что caller дожидается проверки; исключения из фонового действия не должны оставлять успешный ответ.

**Уязвимый вариант:**

Auth/запись запускается без await, обработчик продолжает выдачу данных.

**Исправление:** Task-returning pipeline и await; fail closed при ошибке и request-scoped cancellation.

**Проверка:** False/error/delay проверки не возвращают защищённые данные; корректный путь завершается.

<a id="cs-regex-timeout"></a>

<a id="cs-regex-timeout-untrusted-regex-input-without-a-budget"></a>

## CS-REGEX-TIMEOUT. Regex без бюджета на недоверенном вводе

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'new Regex|Regex.Match|Regex.IsMatch|Regex.Replace' .
~~~

Проверить timeout overload/NonBacktracking своего runtime и длину входа.

**Уязвимый вариант:**

Сложное выражение исчерпывает worker на длинном почти совпадающем тексте.

**Исправление:** Ограничить размер, упростить pattern; поддержанный timeout/NonBacktracking, обработать RegexMatchTimeoutException как отказ.

**Проверка:** Timeout не превращается в разрешение; обычные строки и допустимые regex-конструкции работают.

<a id="cs-auth-filter-reduce"></a>

<a id="cs-auth-filter-reduce-simplification-removes-a-mandatory-authorization-condition"></a>

## CS-AUTH-FILTER-REDUCE. Упрощение фильтра удаляет обязательное условие доступа

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Distinct|Remove|Reduce|AdminFilter|Equals' .
~~~

Сравнить обязательное условие доступа до и после упрощения дерева запроса; проверить структурное равенство фильтров.

**Уязвимый вариант:**

**Основание:** sneakers, авторский разбор RuCTF. Равенство объектов-фильтров и
упрощение выражения могли убрать AdminFilter.

**Искать:** distinct/remove/set/dedup/reduce над AST запросов; структурное
равенство record вместо ожидаемой идентичности; объединение клиентских и
серверных фильтров.

**Исправление:** обязательное условие auth добавлять вне
пользовательского упрощения и проверять перед исполнением. Изменение record
на class из одного разбора не универсальный рецепт.

**Проверка:** эквивалентные/повторённые/вложенные фильтры не расширяют права;
порядок предикатов не влияет на доступ.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/sneakers/README.md).

**Основание:** [первичный материал](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/sneakers/README.md).

<a id="cs-colliding-principal"></a>

<a id="cs-colliding-principal-a-normalized-character-sum-replaces-a-unique-user-id"></a>

## CS-COLLIDING-PRINCIPAL. Нормализованная сумма символов вместо уникального user ID

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'UserId|UserName|ToLower|Reverse|Sum' .
~~~

Сопоставить нормализованное имя, вычисленный ID и ключ owner во всех export/read/update.

**Уязвимый вариант:**

**FAUST / todo-list, код + патч организаторов.** Преобразования имени и сумма
символов используются как идентификатор владельца; разные имена могут совпасть.

**Исправление:** авторизация по стабильному уникальному principal из доверенного
хранилища, согласованная миграция записей. Исправить все пути чтения/экспорта.

**Проверка:** два имени с одинаковым старым ID не получают общий доступ.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/fausecteam/faustctf-2024-todo-list-service/blob/e9ee8b8807c64eeb6f71a72e16f709a558525d2c/patches/deserialize.patch); [исходник/разбор 2](https://github.com/fausecteam/faustctf-2024-todo-list-service/blob/e9ee8b8807c64eeb6f71a72e16f709a558525d2c/patches/TodoController.cs); [исходник/разбор 3](https://github.com/fausecteam/faustctf-2024-todo-list-service/blob/e9ee8b8807c64eeb6f71a72e16f709a558525d2c/service/service/Services/Serializer.cs); [исходник/разбор 4](https://github.com/fausecteam/faustctf-2024-todo-list-service/blob/e9ee8b8807c64eeb6f71a72e16f709a558525d2c/service/service/Services/UserManager.cs); [исходник/разбор 5](https://github.com/fausecteam/faustctf-2024-todo-list-service/blob/e9ee8b8807c64eeb6f71a72e16f709a558525d2c/service/service/Models/Filter.cs).

**Основание:** [первичный материал](https://github.com/fausecteam/faustctf-2024-todo-list-service/blob/e9ee8b8807c64eeb6f71a72e16f709a558525d2c/patches/deserialize.patch).

<a id="cs-jwt-validation"></a>

<a id="cs-jwt-validation-weakened-net-token-validation"></a>

## CS-JWT-VALIDATION. Ослаблены параметры проверки токенов .NET

**Поиск:** скрипт, правило CS-JWT-VALIDATION. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CS-JWT-VALIDATION. Regex: явные false для ValidateLifetime/Issuer/Audience, RequireSignedTokens/ExpirationTime. ValidateIssuerSigningKey=false отдельно не трактуется как отсутствие криптографической проверки.

**Уязвимый вариант:** Отключение lifetime/issuer/audience или требования подписи может принять токен вне назначенного контракта.

~~~csharp
new TokenValidationParameters { ValidateLifetime = false, ValidateAudience = false, RequireSignedTokens = false };
~~~

**Исправление:** Проверять обязательную подпись, ключ, время, издателя и получателя; custom validators должны сохранять эти инварианты.

~~~csharp
new TokenValidationParameters { ValidateLifetime = true, ValidateAudience = true, ValidAudience = "notes", ValidateIssuer = true, ValidIssuer = "auth", RequireSignedTokens = true, RequireExpirationTime = true, IssuerSigningKey = trustedKey };
~~~

**Проверка:** Неподписанный, просроченный и чужой токен не авторизует; штатный токен принимается.

Первичная документация: [документация 1](https://learn.microsoft.com/en-us/dotnet/api/microsoft.identitymodel.tokens.tokenvalidationparameters).

<a id="cs-tls-validation"></a>

<a id="cs-tls-validation-https-validation-callback-always-accepts"></a>

## CS-TLS-VALIDATION. HTTPS validation callback всегда разрешает

**Поиск:** скрипт, правило CS-TLS-VALIDATION. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain CS-TLS-VALIDATION. Regex: DangerousAcceptAnyServerCertificateValidator и простая true-lambda для certificate callbacks. Произвольные методы и body-lambda требуют ручного анализа.

**Уязвимый вариант:** Callback, безусловно принимающий сертификат, обходит стандартную проверку TLS.

~~~csharp
handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
~~~

**Исправление:** Использовать стандартную проверку и доверенный CA; custom trust реализовать без безусловного true.

~~~csharp
var handler = new HttpClientHandler();
var client = new HttpClient(handler);
~~~

**Проверка:** Корректный сертификат работает, чужое имя/CA и истечение дают ошибку.

Первичная документация: [документация 1](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclienthandler.dangerousacceptanyservercertificatevalidator).

<a id="cs-ldap-filter"></a>

<a id="cs-ldap-filter-directorysearcher-filter-concatenates-a-value"></a>

## CS-LDAP-FILTER. Фильтр DirectorySearcher собирается конкатенацией

**Поиск:** правило сканера CS-LDAP-FILTER. Точный контракт детектора: `--explain CS-LDAP-FILTER`. Regex с лексическими исключениями: new DirectorySearcher, первый аргумент которого — строковый литерал, объединённый с идентификатором. Не проверяет присваивания Filter, интерполированные строки, реализации вспомогательных функций и произвольные aliases типов.

**Уязвимый вариант:**

~~~csharp
var query = new DirectorySearcher("(uid=" + name + ")");
~~~

**Исправление:** Используйте проверенный конструктор LDAP-фильтров с экранированием для контекста фильтра и фиксированной политикой атрибутов и области поиска; вспомогательная функция реализуется в приложении.

~~~csharp
var query = new DirectorySearcher(BuildReviewedLdapFilter(name)); // helper implements filter-context escaping
~~~

**Проверка:** Метасимволы не добавляют условия и не расширяют результат; поддерживаемые поисковые запросы остаются совместимыми.

[Первичный источник 1](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.directorysearcher.filter)
