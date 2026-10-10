<a id="rust-find-fix-and-verify"></a>

# Rust: поиск и исправление

[English](rust.md) | Русский

[Вся база](README-RU.md) · [Сканер](../offline-scanner-RU.md) · [Проверка патча](../patch-validation-RU.md)

18 разделов. Формат: **Поиск → Уязвимый вариант → Исправление → Проверка**.
Команды `rg` выполняются в корне локальной копии сервиса и только читают файлы. Субъект/владелец определяется по проверенной сессии, а не данным запроса. Примеры нужно адаптировать к реальным API и контракту.

Автоматические находки — ограниченные синтаксические сигналы для проверки. AST-анализ не разрешает типы и не отслеживает данные между функциями; regex не заменяет парсер языка. Комментарии, строки и одноимённые пользовательские API могут давать совпадения. Проверьте фактическое исполнение, входные данные, авторизацию и границы доверия.

<a id="contents"></a>

## Содержание

- [RUST-UNSAFE-CONVERSION — Непроверенные преобразования и сырые указатели Rust](#rust-unsafe-conversion)
- [RUST-SQL-FORMAT — SQL Rust через format!](#rust-sql-format)
- [RUST-STATIC-MUT — Общее изменяемое состояние Rust](#rust-static-mut)
- [RUST-AUTHORIZATION — Типизированный ID не проверяет owner](#rust-authorization)
- [RUST-SERDE-FIELDS — serde entity принимает служебные поля](#rust-serde-fields)
- [RUST-PANIC-INPUT — unwrap и byte slicing на входе](#rust-panic-input)
- [RUST-COMMAND — Command запускает интерпретатор/опасные опции](#rust-command)
- [RUST-LOCK-AWAIT — Блокировка удерживается через await](#rust-lock-await)
- [RUST-UNBOUNDED-READ — Потенциально неограниченное чтение потока Rust](#rust-unbounded-read)
- [RUST-FFI-OWNERSHIP — FFI удерживает pointer после drop](#rust-ffi-ownership)
- [RUST-SSRF — reqwest redirects и политики URL](#rust-ssrf)
- [RUST-NUMERIC-CAST — as обрезает значение размера](#rust-numeric-cast)
- [RUST-DISTRIBUTED-CAS — Логическая гонка в распределённом состоянии](#rust-distributed-cas)
- [RUST-FFI-LENGTH — В C передаётся объявленная длина вместо длины Rust-буфера](#rust-ffi-length)
- [RUST-PATH-PREFIX — Валидация префикса имени и файловый fallback](#rust-path-prefix)
- [RUST-FFI-ABI — Несовпадение возвращаемого типа C и Rust extern](#rust-ffi-abi)
- [RUST-TLS — Rust HTTP принимает недействительный сертификат](#rust-tls)
- [RUST-JWT-VALIDATION — Rust JWT: отключены обязательные проверки](#rust-jwt-validation)

<a id="rust-unsafe-conversion"></a>

<a id="rust-unsafe-conversion-rust-uncheckedraw-conversion"></a>

## RUST-UNSAFE-CONVERSION. Непроверенные преобразования и сырые указатели Rust

**Поиск:** скрипт, правило RUST-UNSAFE-CONVERSION. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain RUST-UNSAFE-CONVERSION. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~rust
let text = unsafe { std::str::from_utf8_unchecked(data) };
~~~

**Исправление:** Использовать checked API; для необходимого unsafe доказать длину, выравнивание, lifetime, инициализацию и уникальность ссылок. Не убирать unsafe без понимания инвариантов.

~~~rust
let text = std::str::from_utf8(data)?;
~~~

**Проверка:** Неверный UTF-8/длина/индекс, EOF; по возможности Miri/sanitizers в подготовленной среде.

<a id="rust-sql-format"></a>

<a id="rust-sql-format-rust-sql-using-format"></a>

## RUST-SQL-FORMAT. SQL Rust через format!

**Поиск:** скрипт, правило RUST-SQL-FORMAT. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain RUST-SQL-FORMAT. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~rust
sqlx::query(&format!("SELECT * FROM notes WHERE name={}", name));
~~~

**Исправление:** Параметры поддержанного драйвера/ORM, identifiers из allowlist; тип SQL placeholder зависит от БД.

~~~rust
sqlx::query("SELECT * FROM notes WHERE name=$1").bind(name);
~~~

**Проверка:** Кавычки — данные; условие владельца сохраняется.

<a id="rust-static-mut"></a>

<a id="rust-static-mut-shared-mutable-rust-state"></a>

## RUST-STATIC-MUT. Общее изменяемое состояние Rust

**Поиск:** скрипт, правило RUST-STATIC-MUT. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain RUST-STATIC-MUT. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~rust
static mut CURRENT_USER: u64 = 0;
~~~

**Исправление:** Mutex/atomic для настоящего shared state; principal обычно должен быть per-request, один Mutex не исправит смешение пользователей.

~~~rust
static CURRENT_USER: std::sync::Mutex<u64> = std::sync::Mutex::new(0);
~~~

**Проверка:** Конкурентные запросы не делят principal; нет data race и неправильного lock scope.

**Основание:** [первичный материал](https://doc.rust-lang.org/reference/items/static-items.html).

<a id="rust-authorization"></a>

<a id="rust-authorization-a-typed-id-does-not-authorize-its-owner"></a>

## RUST-AUTHORIZATION. Типизированный ID не проверяет owner

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Path<|State<|Extension<|find_by_id|owner|tenant' .
~~~

От extractor пройти до SELECT/UPDATE и проверки сессии; compile-time тип не связывает ID с пользователем.

**Уязвимый вариант:**

Десериализованный NoteId используется для загрузки чужой записи.

**Исправление:** Запрос по ID и серверному owner/policy; проверка tenant у вложенных объектов и задач.

**Проверка:** Своё/чужое/аноним, разные tenant и список/экспорт.

**Основание:** [первичный материал](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).

<a id="rust-serde-fields"></a>

<a id="rust-serde-fields-serde-entities-accept-administrative-fields"></a>

## RUST-SERDE-FIELDS. serde entity принимает служебные поля

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Deserialize|flatten|default|deny_unknown_fields|serde' .
~~~

Сверить DTO/entity, default role и flatten; deny_unknown_fields имеет ограничения совместимости с flatten.

**Уязвимый вариант:**

Клиент присылает owner/admin, default создаёт привилегию при отсутствующем поле.

**Исправление:** Отдельный DTO с разрешёнными полями, явная валидация и серверные auth-поля; не полагаться на тип bool как проверку полномочий.

**Проверка:** Лишнее/отсутствующее поле, null, вложенный объект и обычный payload.

<a id="rust-panic-input"></a>

<a id="rust-panic-input-unwrap-and-byte-slicing-on-request-input"></a>

## RUST-PANIC-INPUT. unwrap и byte slicing на входе

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'unwrap\(|expect\(|\[[0-9]+\.\.|parse::<|from_utf8' .
~~~

Сверить Result/Option и UTF-8 границы; определить, падает task, worker или процесс при panic.

**Уязвимый вариант:**

parse().unwrap() либо &name[..32] паникует на неправильном/коротком/многобайтовом вводе.

**Исправление:** Вернуть контролируемую ошибку, checked get/range и ограничение размера; не скрывать все ошибки пустым default.

**Проверка:** Некорректный UTF-8/число, короткая строка, многобайтовая граница и штатный запрос.

<a id="rust-command"></a>

<a id="rust-command-shell-launched-from-rust"></a>

## RUST-COMMAND. Command запускает интерпретатор/опасные опции

**Поиск:** скрипт, правило RUST-COMMAND. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain RUST-COMMAND. Regex: Command::new с буквальным sh/bash/dash/zsh/cmd/powershell/pwsh. Команда может быть доверенной; arg -c, переменные executable и .args проверять вручную.

Дополнительный ручной поиск для непокрытых форм:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Command::new|\.arg\(|\.args\(|sh|cmd.exe' .
~~~

Сверить executable, каждый argv, окружение/cwd; отдельные аргументы не выключают опции программы.

**Уязвимый вариант:**

Command::new("sh").arg("-c").arg(input) запускает shell с клиентским текстом.

**Исправление:** Библиотечный API или фиксированный executable/argv и политика опций/путей, bounded output/time.

**Проверка:** Кавычки/ведущий дефис остаются данными либо отклоняются; штатная операция совместима.


**Сигнал сканера — пример до:**

~~~rust
Command::new("sh").arg("-c").arg(command).output()?;
~~~

**Шаблон исправления:**

~~~rust
Command::new("/usr/bin/file").arg("--").arg(validated_name).output()?;
~~~

Первичная документация: [документация 1](https://doc.rust-lang.org/std/process/struct.Command.html).

<a id="rust-lock-await"></a>

<a id="rust-lock-await-holding-locks-across-await"></a>

## RUST-LOCK-AWAIT. Блокировка удерживается через await

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'lock\(|\.await|Mutex|RwLock|DashMap' .
~~~

Проверить область guard, повторный вход и порядок нескольких locks.

**Уязвимый вариант:**

Запрос держит lock во время I/O, второй путь ждёт ресурс и создаёт deadlock/истощение.

**Исправление:** Минимальная критическая секция, снимок/версия и повторная атомарная проверка; не отпускать lock между auth и mutation без защиты.

**Проверка:** Два запроса с barrier, cancellation и медленный upstream не блокируют всё приложение.

<a id="rust-unbounded-read"></a>

<a id="rust-unbounded-read-potentially-unbounded-rust-stream-read"></a>

## RUST-UNBOUNDED-READ. Потенциально неограниченное чтение потока Rust

**Поиск:** правило сканера RUST-UNBOUNDED-READ. Точный контракт детектора: `--explain RUST-UNBOUNDED-READ`. Regex с лексическими исключениями: stream/socket/request/reader.read_to_end/read_to_string. Имена получателя — подсказки, а не типы; уже ограниченный поток может дать совпадение, другие имена и wrappers могут быть пропущены.

Дополнительный ручной поиск форм, которые не покрывает автоматическое правило:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'read_to_end|read_to_string|read_line|collect\(|to_bytes' .
~~~

Проследите ограничения фактически прочитанных байтов и затраченного времени, в том числе для chunked-потоков.

**Уязвимый вариант:**

Управляемый клиентом поток накапливается в памяти до EOF.

**Исправление:** Ограничьте чтение, обнаруживайте limit+1 и задайте подходящий timeout; Read::take сам по себе молча останавливается на лимите.

**Проверка:** Проверьте EOF, limit-1, limit, limit+1 и медленный бесконечный источник; допустимые документы максимального размера должны обрабатываться.


**Пример для сканера до исправления:**

~~~rust
stream.read_to_end(&mut payload)?;
~~~

**Шаблон исправления:**

~~~rust
let mut bounded = stream.take(MAX_BYTES + 1);
bounded.read_to_end(&mut payload)?;
if payload.len() as u64 > MAX_BYTES { return Err(too_large()); }
~~~

<a id="rust-ffi-ownership"></a>

<a id="rust-ffi-ownership-ffi-retains-a-pointer-after-drop"></a>

## RUST-FFI-OWNERSHIP. FFI удерживает pointer после drop

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'CString|into_raw|from_raw|as_ptr|extern|free' .
~~~

Сравнить lifetime, allocator и контракт удержания pointer обеими сторонами.

**Уязвимый вариант:**

C сохраняет as_ptr временного Rust-объекта; C free освобождает allocation другого allocator.

**Исправление:** Явная передача владения и парная функция освобождения; keep-alive до callback, FFI-safe типы и обработка panic boundary.

**Проверка:** Отложенный callback, повторное освобождение, ошибка C и штатный teardown.

**Основание:** [первичный материал](https://doc.rust-lang.org/nomicon/ffi.html).

<a id="rust-ssrf"></a>

<a id="rust-ssrf-reqwest-redirects-and-url-policies"></a>

## RUST-SSRF. reqwest redirects и политики URL

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'reqwest|Client::builder|redirect|Url::parse|resolve' .
~~~

Сверить URL, redirect policy и transport DNS; тип Url означает только успешный разбор.

**Уязвимый вариант:**

Разрешённый первый URL перенаправляет к другому trust zone.

**Исправление:** Серверная карта или policy назначения на каждом переходе и реальном соединении; лимиты.

**Проверка:** Mock DNS/redirect/timeout, обычный upstream и запрет недопустимых схем.

**Основание:** [первичный материал](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

<a id="rust-numeric-cast"></a>

<a id="rust-numeric-cast-as-truncates-a-size-value"></a>

## RUST-NUMERIC-CAST. as обрезает значение размера

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e ' as u8| as u16| as u32| as usize|wrapping_|unchecked_' .
~~~

Сверить исходный диапазон и целевой тип до allocation/index/DB ID.

**Уязвимый вариант:**

Широкое число обрезается через as, разные ID/размеры становятся одним.

**Исправление:** TryFrom/checked arithmetic и ограничения протокола; отрицательные значения отвергать до unsigned.

**Проверка:** Максимум, максимум+1, отрицательное и штатное значение, release/debug поведение.

<a id="rust-distributed-cas"></a>

<a id="rust-distributed-cas-logical-races-in-distributed-state"></a>

## RUST-DISTRIBUTED-CAS. Логическая гонка в распределённом состоянии

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'etcd|txn|compare|round|version' .
~~~

Сравнить revision при чтении и записи между workers; process-local Mutex не защищает удалённую транзакцию.

**Уязвимый вариант:**

**RuCTF / rustest, автор.** Несколько запросов проходили проверку одной версии
раунда и независимо записывали результат.

**Исправление:** транзакция хранилища/CAS по версии и атомарное потребление одноразового
состояния. Mutex одного процесса недостаточен при нескольких workers.

**Проверка:** параллельные ответы дают ровно один переход; retries не начисляют
результат дважды.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/HackerDom/ructf-2023/blob/0cc333e44f2ba6908ff6c5d613146e3b00173315/writeups/rustest/README.md).

**Основание:** [первичный материал](https://github.com/HackerDom/ructf-2023/blob/0cc333e44f2ba6908ff6c5d613146e3b00173315/writeups/rustest/README.md).

<a id="rust-ffi-length"></a>

<a id="rust-ffi-length-passing-declared-length-instead-of-rust-buffer-length-to-c"></a>

## RUST-FFI-LENGTH. В C передаётся объявленная длина вместо длины Rust-буфера

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'extern|as_ptr|as_mut_ptr|size_t|memcpy' .
~~~

Сопоставить pointer и length на Rust/C сторонах: длина выделенного среза, не объявленная клиентом.

**Уязвимый вариант:**

**DEF CON / bisbee, код.** FFI store_data получает decoded_data.as_ptr()
и независимо выбранный block_size; C копирует size байт.

**Исправление:** проверить заявленный размер против реального среза и лимита,
передавать длину проверенного буфера.

**Проверка:** размер меньше/равен/больше,
ошибка декодирования, пустой ввод.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/service/src/main.rs); [исходник/разбор 2](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv.c); [исходник/разбор 3](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv.h); [исходник/разбор 4](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_hashmap.c); [исходник/разбор 5](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_hashmap.h); [исходник/разбор 6](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_list.c).

**Основание:** [первичный материал](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/service/src/main.rs).


**Вариант A/D:** в FlagDrive (ENOWARS10) ёмкость контейнера считали по всей структуре вместе со служебным флагом, а данные предназначались только для массива токена. Считать длину/ёмкость самого подмассива, отказаться от неверного reinterpretation и отдельно сохранять owner-проверку. Тест: максимальная длина токена и максимум+1 не меняют соседний признак полномочий. [Авторский разбор](https://github.com/enowars/enowars10-service-flagdrive/blob/d1575098fe2c516460136bb5fba11d9a1c4af3f7/documentation/FLAGSTORE_1.md). Это ошибка границ и преобразования памяти в конкретном сервисе, не утверждение о дефекте компилятора.

<a id="rust-path-prefix"></a>

<a id="rust-path-prefix-prefix-validation-and-filesystem-fallback"></a>

## RUST-PATH-PREFIX. Валидация префикса имени и файловый fallback

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'username|canonicalize|create_dir|fs::read|fs::write' .
~~~

Сравнить проверенный префикс и целый путь; проверить UTF-8 boundary и альтернативный filesystem fallback.

**Уязвимый вариант:**

**DEF CON / bisbee, код.** Проверяется часть username, целое имя используется
в пути; при промахе внутренней БД происходит чтение файла.

**Исправление:** проверять полное имя и границы UTF-8, серверный storage path,
одинаковая auth-политика основного и fallback пути.

**Проверка:** короткое/длинное/многобайтовое имя, разделители в хвосте, промах БД.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/service/src/main.rs); [исходник/разбор 2](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv.c); [исходник/разбор 3](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv.h); [исходник/разбор 4](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_hashmap.c); [исходник/разбор 5](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_hashmap.h); [исходник/разбор 6](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_list.c).

**Основание:** [первичный материал](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/service/src/main.rs).

<a id="rust-ffi-abi"></a>

<a id="rust-ffi-abi-c-and-rust-extern-return-types-disagree"></a>

## RUST-FFI-ABI. Несовпадение возвращаемого типа C и Rust extern

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'extern|store_data|c_void|size_t' .
~~~

Сравнить C header/реализацию и Rust declaration: return type, signedness, layout и calling convention.

**Уязвимый вариант:**

**DEF CON / bisbee, код + header.** C store_data возвращает void,
Rust объявляет i8 и использует полученный результат для выбора fallback.

**Исправление:** общий ABI-контракт/генерация bindings; статус только через действительно
возвращаемое значение одинакового типа, обработка ошибок без неинициализированного
результата.

**Проверка:** build с предупреждениями, размеры/знаковость/тип результата,
штатные ошибки хранения.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/service/src/main.rs); [исходник/разбор 2](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv.c); [исходник/разбор 3](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv.h); [исходник/разбор 4](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_hashmap.c); [исходник/разбор 5](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_hashmap.h); [исходник/разбор 6](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_list.c).

**Основание:** [первичный материал](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/service/src/main.rs).

<a id="rust-tls"></a>

<a id="rust-tls-rust-http-accepts-invalid-certificates"></a>

## RUST-TLS. Rust HTTP принимает недействительный сертификат

**Поиск:** скрипт, правило RUST-TLS. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain RUST-TLS. Regex: danger_accept_invalid_certs/hostnames(true), включая reqwest/native-tls-подобные builders. Значения из переменных и custom verifier вручную.

**Уязвимый вариант:** Опасные builder flags отключают проверку сертификата/имени.

~~~rust
let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build()?;
~~~

**Исправление:** Использовать стандартную проверку; для внутреннего CA добавить доверенный root, не отключая проверки.

~~~rust
let client = reqwest::Client::builder().add_root_certificate(trusted_ca).build()?;
~~~

**Проверка:** Свой CA/hostname работает; чужой сертификат/hostname отвергнут.

Первичная документация: [документация 1](https://docs.rs/reqwest/latest/reqwest/struct.ClientBuilder.html).

<a id="rust-jwt-validation"></a>

<a id="rust-jwt-validation-rust-jwt-checks-disabled"></a>

## RUST-JWT-VALIDATION. Rust JWT: отключены обязательные проверки

**Поиск:** скрипт, правило RUST-JWT-VALIDATION. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain RUST-JWT-VALIDATION. Regex: insecure_disable_signature_validation, validate_exp/validate_aud=false и старые dangerous_*decode. API зависит от версии jsonwebtoken.

**Уязвимый вариант:** Отключённая подпись или expiry делает разобранные claims недостаточным основанием для доступа.

~~~rust
validation.insecure_disable_signature_validation();
validation.validate_exp = false;
~~~

**Исправление:** Использовать проверяющий decode с доверенным ключом и контрактом Validation; проверить результат до доступа.

~~~rust
let mut validation = Validation::new(Algorithm::RS256);
validation.set_audience(&["notes"]);
validation.set_issuer(&["auth"]);
validation.set_required_spec_claims(&["exp", "sub", "iss", "aud"]);
~~~

**Проверка:** Неверная подпись, истечение и отсутствие обязательного поля отклоняются.

Первичная документация: [документация 1](https://docs.rs/jsonwebtoken/latest/jsonwebtoken/struct.Validation.html).
