<a id="c--c-find-fix-and-verify"></a>

# C / C++: поиск и исправление

[English](c-cpp.md) | Русский

[Вся база](README-RU.md) · [Сканер](../offline-scanner-RU.md) · [Проверка патча](../patch-validation-RU.md)

28 разделов. Формат: **Поиск → Уязвимый вариант → Исправление → Проверка**.
Команды `rg` выполняются в корне локальной копии сервиса и только читают файлы. Субъект/владелец определяется по проверенной сессии, а не данным запроса. Примеры нужно адаптировать к реальным API и контракту.

Автоматические находки — ограниченные синтаксические сигналы для проверки. AST-анализ не разрешает типы и не отслеживает данные между функциями; regex не заменяет парсер языка. Комментарии, строки и одноимённые пользовательские API могут давать совпадения. Проверьте фактическое исполнение, входные данные, авторизацию и границы доверия.

<a id="contents"></a>

## Содержание

- [C-BOUNDS — Неограниченное копирование C/C++](#c-bounds)
- [C-FORMAT — Переменная как format string](#c-format)
- [C-SHELL — Shell в C/C++](#c-shell)
- [C-PRNG — Обычный PRNG/LCG в возможном секрете](#c-prng)
- [C-SNPRINTF-FORMAT — Переменная как формат ограниченного printf](#c-snprintf-format)
- [C-RECV-TERMINATOR — Результат recv/read используется как индекс](#c-recv-terminator)
- [C-ATOI — atoi без проверки результата](#c-atoi)
- [C-REALLOC — Перезапись единственного указателя realloc](#c-realloc)
- [C-SIZE-OVERFLOW — Переполнение арифметики размера](#c-size-overflow)
- [CPP-LIFETIME — Указатель/view переживает владельца](#cpp-lifetime)
- [C-PARTIAL-IO — TCP не сохраняет границы сообщений](#c-partial-io)
- [C-SIGNED-LENGTH — Знаковая длина становится большим size_t](#c-signed-length)
- [C-DOUBLE-FREE — Несколько владельцев освобождают один объект](#c-double-free)
- [C-UNINITIALIZED — Выдача padding и незаполненного хвоста](#c-uninitialized)
- [C-TEMPFILE-RACE — Предсказуемое имя и check-then-open](#c-tempfile-race)
- [C-JIT-RETURN — Не все пути JIT-функции завершаются](#c-jit-return)
- [C-HEADER-SECRET — Особая ветка по заголовку меняет секрет](#c-header-secret)
- [C-OBJECT-TOCTOU — Проверили объект, затем заново прочитали изменяемую ссылку](#c-object-toctou)
- [C-EXEC-FAILURE — Ошибка exec оставляет дочерний процесс на серверном пути](#c-exec-failure)
- [CPP-CACHED-LIFETIME — Кэш хранит указатель после освобождения объекта](#cpp-cached-lifetime)
- [C-BLOCK-TAIL — Обработка блока по четыре байта портит хвост буфера](#c-block-tail)
- [C-ALLOC-FAILURE — Ошибка выделения памяти превращается в запись по NULL](#c-alloc-failure)
- [C-FD-NUL — Утечка fd усиливает off-by-one в read_line](#c-fd-nul)
- [C-REENTRANCY-AUTH — Callback между auth-проверкой и подписью](#c-reentrancy-auth)
- [C-BUILTIN-TYPES — Не проверен тип аргумента в одной перегрузке builtin](#c-builtin-types)
- [C-HASH-INDEX — Индекс хеш-таблицы сдвинут за верхнюю границу](#c-hash-index)
- [C-STRNCPY — strncpy может оставить строку без NUL](#c-strncpy)
- [C-COPY-LENGTH — Длина копирования берётся напрямую из strlen источника](#c-copy-length)

<a id="c-bounds"></a>

<a id="c-bounds-unbounded-cc-copy"></a>

## C-BOUNDS. Неограниченное копирование C/C++

**Поиск:** скрипт, правило C-BOUNDS. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain C-BOUNDS. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~c
strcpy(destination, source);
~~~

**Исправление:** Проверять ёмкость/длину до копирования. snprintf проверять по результату; механический strncpy не решает всё.

~~~c
size_t n = strlen(source);
if (n >= capacity) return ERROR;
memcpy(destination, source, n + 1);
~~~

**Проверка:** Пустой/граничный/слишком большой вход; ASan/UBSan если доступны.

<details>
<summary>Развёрнутый пример и ограничения</summary>

```c
/* Vulnerable: capacity and available source length are unchecked. */
char dst[64];
memcpy(dst, src, client_len);
dst[client_len] = '\0';
```

**Патч для поля протокола, которое является C-строкой без встроенного NUL:**

<!-- example: c-copy-text -->
```c
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

bool copy_text(char *dst, size_t capacity, const char *src,
               size_t available, size_t requested) {
    if (dst == NULL || src == NULL || capacity == 0) return false;
    if (requested > available || requested >= capacity) return false;
    if (memchr(src, '\0', requested) != NULL) return false;
    memmove(dst, src, requested);
    dst[requested] = '\0';
    return true;
}
```

`available` — фактически доступные байты, не заявленный клиентом размер.
Знаковую длину проверить на отрицательность **до** перевода в `size_t`.
`memmove` допускает перекрытие; при отказе функция не меняет dst. Вызывающий
код обязан обработать `false`, а не отправлять прежнее содержимое буфера.

**Проверить:** пустая строка, capacity−1, capacity, недостаточный src,
нулевая вместимость, NUL внутри текста; при отказе буфер не изменён.
Для бинарных данных встроенный NUL допустим: нужен иной контракт с явной длиной.
Молчаливое усечение через `strncpy` может испортить ID/данные checker.

</details>

<a id="c-format"></a>

<a id="c-format-variable-used-as-a-format-string"></a>

## C-FORMAT. Переменная как format string

**Поиск:** скрипт, правило C-FORMAT. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain C-FORMAT. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~c
printf(message);
~~~

**Исправление:** Фиксированный формат и проверенные аргументы; бинарным данным явная длина.

~~~c
printf("%s", message);
~~~

**Проверка:** Символы процента печатаются текстом.

<details>
<summary>Развёрнутый пример и ограничения</summary>

```c
/* Vulnerable: message controls the format and argument interpretation. */
printf(message);
```

**Патч, если message — корректная NUL-терминированная строка:**

<!-- example: c-write-message -->
```c
#include <stdbool.h>
#include <stdio.h>

bool write_message(FILE *out, const char *message) {
    if (out == NULL || message == NULL) return false;
    return fputs(message, out) != EOF;
}
```

Альтернатива — `fprintf(out, "%s", message)` с фиксированным форматом.
Для сетевого буфера с известной длиной использовать проверенный размер и
`fwrite`, не предполагать наличие NUL. Ошибку записи обработать отдельно.

**Проверить:** строка с `%s`, `%%` и Unicode выводится буквально; пустая строка
допустима; текст не получает лишний перевод строки, если это важно протоколу.

</details>

<a id="c-shell"></a>

<a id="c-shell-cc-shell-execution"></a>

## C-SHELL. Shell в C/C++

**Поиск:** скрипт, правило C-SHELL. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain C-SHELL. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~c
system(command);
~~~

**Исправление:** execve/posix_spawn с фиксированной программой/argv; проверить аргументы и ошибки.

~~~c
run_fixed_tool(validated_filename); // fixed executable + argv inside
~~~

**Проверка:** Спецсимволы не интерпретируются shell.

<a id="c-prng"></a>

<a id="c-prng-ordinary-prnglcg-near-a-possible-secret"></a>

## C-PRNG. Обычный PRNG/LCG в возможном секрете

**Поиск:** скрипт, правило C-PRNG. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain C-PRNG. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~c
srand((unsigned)time(NULL));
token = rand();
~~~

**Исправление:** Для секрета системный CSPRNG/поддержанная криптобиблиотека, проверка результата. Обычная игровая случайность может использовать PRNG.

~~~c
if (!fill_from_os_csprng(token, sizeof token)) return ERROR; // implement using supported OS/library API
~~~

**Проверка:** Нет seed от времени/const и предсказуемого fallback; формат токена совместим.

**Вариант A/D:** Идентификатор доступа из LCG со временем в seed. **ENOWARS / piratesay, автор.** Идентификатор разрешал сменить пользователя,
а генератор зависел от времени старта.

**Патч:** системный CSPRNG и серверная привязка credential к пользователю.
Скрытый константный seed не является надёжным исправлением.
**Тест:** новые идентификаторы/старые сессии по плану перехода, ошибка источника
энтропии без fallback. **Поиск:** C-PRNG; самодельные генераторы требуют чтения.

[исходник/разбор 1](https://github.com/enowars/enowars8-service-piratesay/blob/32973478dbe903d0a2446539ecbddf3b1c334e60/documentation/README.md); [исходник/разбор 2](https://github.com/enowars/enowars8-service-piratesay/blob/32973478dbe903d0a2446539ecbddf3b1c334e60/service_source/src/cli.c); [исходник/разбор 3](https://github.com/enowars/enowars8-service-piratesay/blob/32973478dbe903d0a2446539ecbddf3b1c334e60/service_source/src/session.c).

<a id="c-snprintf-format"></a>

<a id="c-snprintf-format-variable-format-in-bounded-printf"></a>

## C-SNPRINTF-FORMAT. Переменная как формат ограниченного printf

**Поиск:** скрипт, правило C-SNPRINTF-FORMAT. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain C-SNPRINTF-FORMAT. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~c
snprintf(out, capacity, message);
~~~

**Исправление:** Фиксированный формат. Лимит размера буфера не делает недоверенную format string безопасной; проследить собственные wrappers/macros.

~~~c
snprintf(out, capacity, "%s", message);
~~~

**Проверка:** Проценты выводятся как текст; длина/усечение обработаны; внутренний wrapper может оставаться сигналом.

**Вариант A/D:** Format string внутри «безопасной» обёртки. **ENOWARS / piratesay, автор.** Ограниченная запись в буфер и фильтрация
нескольких спецификаторов не мешали следующему слою снова интерпретировать
пользовательский текст как формат.

**Патч:** фиксированный формат на последнем sink, данные отдельным аргументом;
проследить macro → wrapper → printf-family. **Тест:** проценты печатаются
буквально, усечение обрабатывается. **Поиск:** C-FORMAT, C-SNPRINTF-FORMAT;
произвольные имена обёрток автоматически не распознаются.

[исходник/разбор 1](https://github.com/enowars/enowars8-service-piratesay/blob/32973478dbe903d0a2446539ecbddf3b1c334e60/documentation/README.md); [исходник/разбор 2](https://github.com/enowars/enowars8-service-piratesay/blob/32973478dbe903d0a2446539ecbddf3b1c334e60/service_source/src/cli.c); [исходник/разбор 3](https://github.com/enowars/enowars8-service-piratesay/blob/32973478dbe903d0a2446539ecbddf3b1c334e60/service_source/src/session.c).

<a id="c-recv-terminator"></a>

<a id="c-recv-terminator-recvread-result-used-as-an-index"></a>

## C-RECV-TERMINATOR. Результат recv/read используется как индекс

**Поиск:** скрипт, правило C-RECV-TERMINATOR. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain C-RECV-TERMINATOR. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~c
n = recv(fd, buffer, sizeof buffer, 0);
buffer[n] = '\0';
~~~

**Исправление:** Оставить место для NUL, проверить отрицательную длину/EOF до индексации, учитывать неполное чтение. Сигнал может остаться на правильном коде.

~~~c
ssize_t n = recv(fd, buffer, sizeof buffer - 1, 0);
if (n <= 0) return ERROR;
buffer[n] = '\0';
~~~

**Проверка:** recv=-1, EOF, полный буфер, короткое чтение и обычное сообщение.

<a id="c-atoi"></a>

<a id="c-atoi-atoi-without-checked-conversion"></a>

## C-ATOI. atoi без проверки результата

**Поиск:** скрипт, правило C-ATOI. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain C-ATOI. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~c
int size = atoi(input);
~~~

**Исправление:** Полный разбор числа: знак, диапазон, end pointer и errno; проверить арифметику до allocation/copy.

~~~c
// use strtol/strtoull with errno, end pointer, sign and application bounds checks
~~~

**Проверка:** Пусто, хвост текста, отрицательное число, overflow, граничный допустимый размер.

**Основание:** [первичный материал](https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/rules/error-handling-err/err34-c/).

<a id="c-realloc"></a>

<a id="c-realloc-overwriting-the-only-pointer-with-realloc"></a>

## C-REALLOC. Перезапись единственного указателя realloc

**Поиск:** скрипт, правило C-REALLOC. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain C-REALLOC. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~c
buffer = realloc(buffer, size);
~~~

**Исправление:** Проверенный ненулевой size, временный указатель и обработка ошибки. Отдельно обработать size=0 по контракту, не полагаться на переносимую семантику realloc(p,0).

~~~c
void *next = realloc(buffer, size);
if (next == NULL) { /* preserve buffer; handle error */ }
else { buffer = next; }
~~~

**Проверка:** Fault injection allocation error сохраняет старый buffer; нет утечки/double free.

**Основание:** [первичный материал](https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/recommendations/memory-management-mem/mem04-c/).

<a id="c-size-overflow"></a>

<a id="c-size-overflow-size-arithmetic-overflow"></a>

## C-SIZE-OVERFLOW. Переполнение арифметики размера

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'malloc|calloc|resize|reserve|sizeof|memcpy' .
~~~

Перед умножением/сложением проверить SIZE_MAX и application limit; знак до cast.

**Уязвимый вариант:**

malloc(count * sizeof(Item)) выделяет меньше, чем последующее копирование после overflow.

**Исправление:** Проверенное умножение/сложение и фактическая capacity; отдельно обработать ноль и allocation failure.

**Проверка:** Ноль, граница, переполнение произведения/суммы, отрицательный вход и прежний буфер.

<details>
<summary>Развёрнутый пример и ограничения</summary>

```c
/* Vulnerable: count * sizeof(Item) can overflow. */
Item *items = malloc(count * sizeof(*items));
```

**Патч проверки арифметики и согласованного лимита:**

<!-- example: c-array-bytes -->
```c
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool array_bytes(size_t count, size_t item_size, size_t max_bytes, size_t *out) {
    if (out == NULL || item_size == 0) return false;
    if (count > SIZE_MAX / item_size) return false;
    size_t total = count * item_size;
    if (total > max_bytes) return false;
    *out = total;
    return true;
}
```

Перед `malloc` вызвать с `sizeof(*items)` и лимитом по контракту; проверить
результат выделения. Нулевой count обрабатывать отдельно согласно протоколу:
не выводить ошибку только из того, что `malloc(0)` вернул NULL. Размер out при
отказе не использовать. При добавлении заголовка/терминатора проверить также
сложение; эта функция проверяет только произведение.

**Проверить:** ноль, единица, ровно допустимый бюджет, превышение бюджета,
произведение больше SIZE_MAX; ошибка не ведёт к копированию в старый/NULL-буфер.

</details>

<a id="cpp-lifetime"></a>

<a id="cpp-lifetime-a-pointer-or-view-outlives-its-owner"></a>

## CPP-LIFETIME. Указатель/view переживает владельца

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'c_str\(|string_view|span|return.*data|return.*&' .
~~~

Найти владельца данных и его destruction/reallocation; проверить async callback и lambda captures.

**Уязвимый вариант:**

Возвращён c_str временной string или string_view локального буфера.

**Исправление:** Вернуть владеющий объект/копию; при async передать владение до завершения, view сам по себе lifetime не продлевает.

**Проверка:** Результат существует после возврата, следующий вызов его не портит, async дожидается окончания.

<details>
<summary>Развёрнутый пример и ограничения</summary>

```cpp
// Vulnerable: the temporary string dies before the returned pointer is used.
const char* make_label(const std::string& name) {
    return (std::string("hello ") + name).c_str();
}
```

**Патч: вернуть владеющий объект, а не указатель в уничтоженное хранилище:**

<!-- example: cpp-label -->
```cpp
#include <string>

std::string make_label(const std::string& name) {
    return std::string("hello ") + name;
}
```

Вызывающий код хранит `std::string label = make_label(name);`. Его `c_str()`
можно передать синхронному API, которое не удерживает указатель дольше жизни
строки. Для асинхронной операции нужно передать владение/копию. `string_view`
сам по себе не продлевает жизнь строки и не является исправлением.

**Проверить:** результат существует после выхода из функции; последовательные
вызовы не меняют прошлые результаты; пустое имя и Unicode; асинхронный путь
удерживает данные до завершения операции.

</details>

<a id="c-partial-io"></a>

<a id="c-partial-io-tcp-does-not-preserve-message-boundaries"></a>

## C-PARTIAL-IO. TCP не сохраняет границы сообщений

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'recv|read\(|send|write\(|Content-Length|length' .
~~~

Сверить frame length с накопленными байтами и циклы short read/write, EINTR/EOF.

**Уязвимый вариант:**

Один recv принят за целый запрос; send передал только часть приватного ответа, следующий кадр склеился.

**Исправление:** Явный framing и ограниченный накопительный буфер, проверка частичных операций и timeout; не менять протокол checker.

**Проверка:** Фрагментация по каждому байту, два кадра вместе, EOF посредине и обычное сообщение.

<a id="c-signed-length"></a>

<a id="c-signed-length-signed-lengths-become-huge-size_t-values"></a>

## C-SIGNED-LENGTH. Знаковая длина становится большим size_t

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'ssize_t|size_t|uint32_t|int.*len|memcpy|recv' .
~~~

Проследить все casts между чтением/разбором и allocation/index.

**Уязвимый вариант:**

Отрицательный read или пользовательский int приводится к unsigned до проверки.

**Исправление:** Проверить error/sign/range до преобразования, сверить вместимость источника и приёмника.

**Проверка:** read=-1, EOF, отрицательное поле, максимум и нормальный payload.

<a id="c-double-free"></a>

<a id="c-double-free-multiple-owners-free-the-same-object"></a>

## C-DOUBLE-FREE. Несколько владельцев освобождают один объект

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'free\(|delete|unique_ptr|shared_ptr|goto.*fail' .
~~~

Пройти success/error cleanup и передачу владения; найти два shared_ptr из одного raw pointer.

**Уязвимый вариант:**

Error path и внешний caller освобождают объект дважды, либо reset уничтожает ещё используемый объект.

**Исправление:** Единый owner/RAII и явная передача владения; обнуление одного alias не исправляет остальные.

**Проверка:** Ошибка на каждом шаге создания, повторный cleanup, нормальный жизненный цикл.

<a id="c-uninitialized"></a>

<a id="c-uninitialized-exposing-padding-or-uninitialized-tails"></a>

## C-UNINITIALIZED. Выдача padding и незаполненного хвоста

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'malloc|struct|send|write|sizeof|memcpy' .
~~~

Сравнить реально заполненные поля с sizeof отправляемого struct и padding.

**Уязвимый вариант:**

send(fd, &record, sizeof record, ...) выдаёт padding либо остаток предыдущего содержимого.

**Исправление:** Явная сериализация полей и длины, инициализация буфера; не публиковать native layout как протокол.

**Проверка:** Разные компиляторы/layout, короткий ввод, отсутствие незаполненных байтов в ответе.

<a id="c-tempfile-race"></a>

<a id="c-tempfile-race-temporary-filename-without-atomic-creation"></a>

## C-TEMPFILE-RACE. Предсказуемое имя и check-then-open

**Поиск:** скрипт, правило C-TEMPFILE-RACE. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain C-TEMPFILE-RACE. Regex: tmpnam/tempnam/mktemp. Самописные схемы имени, reopen после mkstemp и TOCTOU по каталогу остаются ручными.

Дополнительный ручной поиск для непокрытых форм:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'tmpnam|mktemp|access\(|stat\(|fopen|open\(' .
~~~

Проследить промежуток existence check → open и права родительского каталога.

**Уязвимый вариант:**

Имя в общем /tmp проверено, затем открыто с перезаписью по подменённой ссылке.

**Исправление:** Атомарное создание mkstemp/open с O_EXCL и нужной политикой links, private temp dir, restrictive mode; descriptor-based работа.

**Проверка:** Коллизия имени, symlink, параллельное создание, ошибка записи и cleanup.


**Сигнал сканера — пример до:**

~~~native
char name[L_tmpnam];
tmpnam(name);
FILE *f = fopen(name, "w");
~~~

**Шаблон исправления:**

~~~native
char name[] = "/tmp/app-XXXXXX";
int fd = mkstemp(name);
if (fd < 0) return ERROR;
unlink(name);
/* use fd; close(fd) on every exit */
~~~

Первичная документация: [документация 1](https://pubs.opengroup.org/onlinepubs/9799919799/functions/mkstemp.html).

<a id="c-jit-return"></a>

<a id="c-jit-return-not-every-jit-function-path-terminates"></a>

## C-JIT-RETURN. Не все пути JIT-функции завершаются

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'return|emit|jit|compile|bytecode' .
~~~

Построить выходы CFG функции: условный return не закрывает другую ветвь и fall-through.

**Уязвимый вариант:**

**Основание:** dcs, авторский разбор RuCTF: условный return ошибочно считался
достаточным; выполнение продолжалось за телом функции.
**Искать:** самодельные VM/JIT/DSL, проверка return через поиск узла вместо
анализа достижимости, размещение констант рядом с инструкциями.

**Исправление:** анализ графа потока: каждый достижимый выход обязан возвращать
значение либо завершаться определённой ошибкой. Разделять код и данные,
проверять индексы/типы до генерации.

**Проверка:** обе ветви условия, вложенные
условия, пустая функция и штатные вычисления. Запретить JIT целиком можно
только если сохранён функциональный контракт.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/dcs/README.md).

**Основание:** [первичный материал](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/dcs/README.md).

<a id="c-header-secret"></a>

<a id="c-header-secret-a-special-header-branch-changes-a-secret"></a>

## C-HEADER-SECRET. Особая ветка по заголовку меняет секрет

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'getenv|HTTP_USER_AGENT|SECRET_KEY|constructor' .
~~~

Прочитать init/constructor и ветви debug/test: клиентский заголовок не должен менять ключ.

**Уязвимый вариант:**

**Основание:** reversaar, анализ C-исходника saarCTF: специальный путь,
связанный с HTTP_USER_AGENT, изменял SECRET_KEY.
**Искать:** constructor/init-хуки, getenv заголовков, magic constants,
debug/test/admin-ветки в release, скрытые переключатели подписи.

**Исправление:** удалить именно посторонний переход состояния; конфигурация секретов
не зависит от клиентского запроса. Просмотреть код запуска, не только маршруты.

**Проверка:** разные заголовки не меняют ключ, права и формат хранения; обычная
инициализация сохранена. Сканер не содержит сигнатуры конкретного magic value;
связь входа с секретом проверяется вручную.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/saarsec/saarctf-2024/blob/3a06d18974ca177c6dd251a11bdf9b4b334f382a/reversaar/service/src/array.c).

**Основание:** [первичный материал](https://github.com/saarsec/saarctf-2024/blob/3a06d18974ca177c6dd251a11bdf9b4b334f382a/reversaar/service/src/array.c).

<a id="c-object-toctou"></a>

<a id="c-object-toctou-re-reading-mutable-references-after-authorization"></a>

## C-OBJECT-TOCTOU. Проверили объект, затем заново прочитали изменяемую ссылку

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'background|fork|exec|open|read' .
~~~

Найти повторное чтение изменяемого объекта после проверки и внешнего вызова; сверить identity/snapshot.

**Уязвимый вариант:**

**RuCTF / memos, автор.** Между проверкой доступа к фону и чтением фона
выполнялась внешняя операция; другой запрос мог заменить выбранный объект.

**Исправление:** работать с тем же проверенным снимком/дескриптором, либо атомарно
проверять версию перед использованием.

**Проверка:** контролируемое чередование
двух запросов через барьер, штатная длительная обработка.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/HackerDom/ructf-2023/blob/0cc333e44f2ba6908ff6c5d613146e3b00173315/writeups/memos/README.md).

**Основание:** [первичный материал](https://github.com/HackerDom/ructf-2023/blob/0cc333e44f2ba6908ff6c5d613146e3b00173315/writeups/memos/README.md).

<a id="c-exec-failure"></a>

<a id="c-exec-failure-failed-exec-leaves-a-child-on-the-server-path"></a>

## C-EXEC-FAILURE. Ошибка exec оставляет дочерний процесс на серверном пути

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'fork|execve|execvp|waitpid' .
~~~

Пройти ветвь каждого отрицательного возврата fork/exec и завершение child, включая аргументы сверх лимита.

**Уязвимый вариант:**

**RuCTF / memos, автор.** После неудачного execve дочерний процесс мог продолжить
логику сервиса.

**Исправление:** проверять fork/exec/wait; после ошибки exec в дочерней ветви завершаться
через _exit с ошибкой, закрывая лишние дескрипторы.

**Проверка:** исполняемый файл
недоступен, аргументы превышают лимит, fork неуспешен — второй сервер не возникает.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/HackerDom/ructf-2023/blob/0cc333e44f2ba6908ff6c5d613146e3b00173315/writeups/memos/README.md).

**Основание:** [первичный материал](https://github.com/HackerDom/ructf-2023/blob/0cc333e44f2ba6908ff6c5d613146e3b00173315/writeups/memos/README.md).

<a id="cpp-cached-lifetime"></a>

<a id="cpp-cached-lifetime-cached-pointers-survive-object-destruction"></a>

## CPP-CACHED-LIFETIME. Кэш хранит указатель после освобождения объекта

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'cache|delete|free|flush|shared_ptr|weak_ptr' .
~~~

Найти владельца cached pointer и момент освобождения; проследить вызов метода после eviction.

**Уязвимый вариант:**

**RuCTF / perune, автор.** Последующий обход кэша вызывал виртуальный метод
у освобождённого объекта.

**Исправление:** явное владение, удаление всех ссылок при destruction, безопасные
handles/weak references или проверяемый generation ID.

**Проверка:** разные порядки
создания/удаления/flush, доступный sanitizer; не считать отсутствие падения
доказательством.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/HackerDom/ructf-2023/blob/0cc333e44f2ba6908ff6c5d613146e3b00173315/writeups/perune/readme.md).

**Основание:** [первичный материал](https://github.com/HackerDom/ructf-2023/blob/0cc333e44f2ba6908ff6c5d613146e3b00173315/writeups/perune/readme.md).

<a id="c-block-tail"></a>

<a id="c-block-tail-four-byte-block-processing-corrupts-the-tail"></a>

## C-BLOCK-TAIL. Обработка блока по четыре байта портит хвост буфера

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'xor|chacha|uint32_t|length|remaining' .
~~~

Проверить обработку остатка длины 1–3 байта при шаге четыре; сопоставить фактическую allocation.

**Уязвимый вариант:**

**ECSC / Diese HSM, автор.** XOR проходил за конец при длине, не кратной слову.

**Исправление:** полные блоки плюс отдельный ограниченный хвост, проверка выравнивания.

**Проверка:** длины 0–9, края буфера, canary и допустимые nonce.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/README.md); [исходник/разбор 2](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/webapp/src/classes/Utils.class.php); [исходник/разбор 3](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/hsm/src/msg.c).

**Основание:** [первичный материал](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/README.md).

<a id="c-alloc-failure"></a>

<a id="c-alloc-failure-allocation-failure-becomes-a-null-write"></a>

## C-ALLOC-FAILURE. Ошибка выделения памяти превращается в запись по NULL

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'malloc|calloc|alloc|memcpy' .
~~~

Проследить NULL/ошибку allocation до первой записи, включая собственный allocator и адресное пространство firmware.

**Уязвимый вариант:**

**ECSC / Diese HSM, автор + код.** Результат allocator не проверяется;
в firmware адрес 0 доступен.

**Исправление:** checked size arithmetic, лимит сообщения, обработка allocation failure
во всей цепочке.

**Проверка:** отказ каждого выделения и усечённый пакет.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/README.md); [исходник/разбор 2](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/webapp/src/classes/Utils.class.php); [исходник/разбор 3](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/hsm/src/msg.c).

**Основание:** [первичный материал](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/README.md).

<a id="c-fd-nul"></a>

<a id="c-fd-nul-descriptor-leaks-amplify-a-read_line-off-by-one"></a>

## C-FD-NUL. Утечка fd усиливает off-by-one в read_line

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'read_line|open|close|fopen|fclose' .
~~~

Просмотреть закрытие fd в ветвях login error и запись NUL при заполненном буфере.

**Уязвимый вариант:**

**ECSC / CookingNonna, автор.** Неудачный login оставлял fd, а терминатор
мог записаться за полный буфер.

**Исправление:** единый cleanup для всех отказов; резервировать байт под NUL, проверять
read/EOF и возвращаемые значения open относительно -1.

**Проверка:** capacity 0/1/max, длинная строка, серия отказов без роста fd.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/CookingNonna/README.md).

**Основание:** [первичный материал](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/CookingNonna/README.md).

<a id="c-reentrancy-auth"></a>

<a id="c-reentrancy-auth-a-callback-runs-between-authorization-and-signing"></a>

## C-REENTRANCY-AUTH. Callback между auth-проверкой и подписью

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'callback|SignToken|Len|ByRef' .
~~~

Найти вызов пользовательской функции после owner-check; проверить, может ли она менять подписываемые аргументы.

**Уязвимый вариант:**

**ICC / MaScroll, автор.** Переопределяемый Len мог изменить аргумент по ссылке
после проверки владельца.

**Исправление:** валидировать неизменяемую копию, не вызывать пользовательский код
между проверкой и чувствительной операцией.

**Проверка:** callback изменяет исходный объект, но подписывается только проверенный.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/MaScroll/README.md).

**Основание:** [первичный материал](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/MaScroll/README.md).

<a id="c-builtin-types"></a>

<a id="c-builtin-types-one-builtin-overload-omits-argument-type-checks"></a>

## C-BUILTIN-TYPES. Не проверен тип аргумента в одной перегрузке builtin

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'FastRand|CryptoRand|variant|overload|builtin' .
~~~

Сравнить типы всех аргументов каждой перегрузки, включая общий первый аргумент и error path.

**Уязвимый вариант:**

**ICC / MaScroll, автор.** Вариант вызова генератора пропускал проверку типа,
а ошибка памяти затрагивала криптографическое состояние.

**Исправление:** единая проверка type/arity/length для всех перегрузок, корректные
владение и буферы.

**Проверка:** матрица типов и числа аргументов;
ошибка не меняет состояние RNG/подписи.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/MaScroll/README.md).

**Основание:** [первичный материал](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/MaScroll/README.md).

<a id="c-hash-index"></a>

<a id="c-hash-index-hash-table-indices-exceed-the-upper-boundary"></a>

## C-HASH-INDEX. Индекс хеш-таблицы сдвинут за верхнюю границу

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'TABLE_SIZE|capacity|hash|table\[' .
~~~

Для каждой ветви вычислить min/max индекса и размер массива; проверить insert/find и переключение структур.

**Уязвимый вариант:**

**DEF CON / bisbee, код + header.** Формула остаток по TABLE_SIZE плюс один
используется для массива из TABLE_SIZE элементов.

**Исправление:** индекс в диапазоне [0, capacity), согласованный со всеми операциями;
проверить перенос между list и hashmap и счётчики при обновлении.

**Проверка:** первый/последний bucket, collision, повторное обновление, переключение
представления.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/service/src/main.rs); [исходник/разбор 2](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv.c); [исходник/разбор 3](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv.h); [исходник/разбор 4](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_hashmap.c); [исходник/разбор 5](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_hashmap.h); [исходник/разбор 6](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_list.c).

**Основание:** [первичный материал](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/service/src/main.rs).

<a id="c-strncpy"></a>

<a id="c-strncpy-strncpy-may-omit-nul-termination"></a>

## C-STRNCPY. strncpy может оставить строку без NUL

**Поиск:** скрипт, правило C-STRNCPY. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain C-STRNCPY. Regex: strncpy. Наличие последующего NUL и фактическая ёмкость анализируются вручную; memcpy без проверки длины не является исправлением.

**Уязвимый вариант:** strncpy при длинном входе не добавляет терминатор; последующее строковое API читает за буфером.

~~~native
strncpy(out, input, sizeof out);
puts(out);
~~~

**Исправление:** Выбрать контракт: отклонять слишком длинный вход или явно обрезать с местом для NUL. Для бинарных данных передавать длину вместо строкового API.

~~~native
size_t n = bounded_input_length;
if (n >= sizeof out) return ERROR;
memcpy(out, input, n);
out[n] = '\0';
~~~

**Проверка:** Вход длиной capacity-1/capacity/capacity+1 и пустой не вызывает чтения за границей; тихое усечение не меняет identity.

Первичная документация: [документация 1](https://pubs.opengroup.org/onlinepubs/9799919799/functions/strncpy.html).

<a id="c-copy-length"></a>

<a id="c-copy-length-copy-length-comes-directly-from-source-strlen"></a>

## C-COPY-LENGTH. Длина копирования берётся напрямую из strlen источника

**Поиск:** правило сканера C-COPY-LENGTH. Точный контракт детектора: `--explain C-COPY-LENGTH`. Regex с лексическими исключениями: memcpy/memmove с простыми первыми двумя аргументами и strlen/strnlen непосредственно в выражении длины. Не доказывает отсутствие предшествующих проверок или фактические размеры буферов; одноимённые пользовательские API и макросы требуют проверки.

**Уязвимый вариант:**

~~~native
memcpy(dest, input, strlen(input) + 1);
~~~

**Исправление:** Перед копированием проверьте доступную для чтения длину источника и ёмкость назначения, включая завершающий символ и переполнение арифметики.

~~~native
size_t n = validated_length;
if (n >= capacity) return ERROR;
memcpy(dest, input, n + 1);
~~~

**Проверка:** Проверьте пустой ввод, границы ёмкости, отсутствие завершающего символа и переполнение; по возможности используйте санитайзеры.

[Первичный источник 1](https://pubs.opengroup.org/onlinepubs/9799919799/functions/memcpy.html)
