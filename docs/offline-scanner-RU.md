<a id="offline-source-scanner"></a>
# Офлайн-сканер исходников

[English](offline-scanner.md) | Русский

[Каталог](vulnerabilities/README-RU.md) · [Рабочий процесс оператора](defense-RU.md) · [Разработка](development-RU.md)

Scanner 1.8.0 использует 174 локальных правила: 30 Python AST, 143 regex и одно правило ограниченного анализа JS-токенов. Подсказки конкретных frameworks также расширяют существующие правила. Это детерминированный помощник для review с ограничениями ресурсов; он не является базой CVE, dependency resolver, детектором эксплойтов или движком межпроцедурного taint-анализа.

<a id="safe-first-scan"></a>
## Первый безопасный scan

Свидетельство: `REVIEWED`; исторические прогоны записываются отдельно. Эффект: `READ-ONLY` (перенаправление stdout создаёт выбранный вами файл вывода). Рабочий каталог: корень DurkaHelper. Требования: Python 3.10+, разрешённая локальная копия сервиса и приватный каталог вывода. Входной код не исполняется, сетевых запросов нет. Rollback: не нужен; проверяйте вывод перед передачей другим.

```bash
python3 -I -S scripts/defense_scan.py /path/to/service --patches
python3 -I -S scripts/defense_scan.py /path/to/service --json
python3 -I -S scripts/defense_scan.py --list-rules
python3 -I -S scripts/defense_scan.py --explain PY-SQL
```

Используйте показанный выше isolated/no-site режим интерпретатора, чтобы не загружать Python startup files, контролируемые целью. Сканер загружает свой доверенный rule pack, а не правила из сканируемого каталога. Не устанавливайте зависимости и не импортируйте цель только ради её изучения.

<a id="reading-a-finding"></a>
## Как читать находку

Каждая находка содержит путь относительно root и физическую строку, стабильный rule ID, статическое объяснение, шаблон исправления, рекомендации проверки и точную ссылку на каталог. Новые metadata добавляют family, применимый CWE, review priority, signal kind и limitations. Это классификация для review, а не доказательство достижимости или эксплуатируемости.

Находки не включают raw source lines, argv, environment или обнаруженные значения секретов. Имена файлов и hashes всё равно могут быть чувствительными. Текстовый вывод безопасно представляет неподдерживаемые консолью символы; JSON переносим.

Корректное исправление может сохранить сигнал: например, проверенный dynamic URL или bounded reader всё ещё может совпадать с правилом. И наоборот, удаление или перенос кода может убрать совпадение, не исправляя авторизацию. Изучайте настоящий путь source-to-sink и проверяйте поведение.

<a id="infrastructure-context"></a>
## Контекст инфраструктуры

Необязательный [пример context](../config/scanner-context.example.json) строго не содержит секретов:

```json
{
  "schema": "durkahelper.scanner-context.v1",
  "infrastructure": ["docker-desktop", "compose", "vulnbox", "team-lan", "s4dfarm", "neo", "packmate"],
  "role": "both"
}
```

Свидетельство: `REVIEWED`; эффект `READ-ONLY`; рабочий каталог и требования те же, что для первого scan. Ожидается: те же применимые правила остаются включёнными, но получают контекстные приоритеты и объяснения. Это не подразумевает runtime discovery или разрешение на действия.

```bash
python3 -I -S scripts/defense_scan.py /path/to/service \
  --context config/scanner-context.example.json --json
```

Допустимые роли: defender, administrator и both. Context никогда не отключает правила, не выполняет команды, не разрешает сетевые операции и не раскрывает состояние работающего Docker. Его нормализованный смысл входит в scope fingerprint отчёта.

<a id="inputs-and-limits"></a>
## Входы и ограничения

Поддерживаемые семейства исходников и конфигурации: Python, JavaScript/TypeScript, PHP, Go, Java, C#/.NET, C/C++, Ruby, Rust, SQL, templates, Dockerfiles, shell и распространённые форматы конфигурации. Язык определяется по имени файла; поддерживаемое имя не доказывает язык или версию runtime.

По умолчанию: 1 MiB на файл, 20 000 файлов, 10 000 находок. Сканер исключает распространённые dependency/build/cache-каталоги и похожие на секреты имена файлов, например форматы private keys и .env, не являющиеся примерами. Явные исключения записываются в scope. Оцените, требуется ли отдельный разрешённый review для excluded/generated/vendor code.

Свидетельство: `REVIEWED`; эффект `READ-ONLY`; рабочий каталог — корень. Эти параметры меняют покрытие и, следовательно, сопоставимость:

```bash
python3 -I -S scripts/defense_scan.py /path/to/service \
  --exclude generated --max-bytes 1048576 --max-files 20000 --max-findings 10000 --json
```

Symlink leaves, nonregular files, нечитаемые или нестабильные файлы, parsing failures и превышенные limits дают incomplete/partial, а не ложный clean success. Обычные ancestor links macOS отличаются от небезопасных input leaves. Никогда не ослабляйте эти защиты ради зелёного отчёта.

Regex-сканирование использует ограниченные перекрывающиеся окна: до 12 физических строк и 8 192 символов в окне с перекрытием в шесть строк. Слишком длинные физические строки пропускаются с partial issue. Шаблоны за границей окна, неизвестные wrappers и сгенерированные строки могут быть пропущены. У новых code-only детекторов есть лексические исключения; старые regex-детекторы всё ещё могут находить совпадения в комментариях или строковых примерах.

Python-анализ — ограниченный синтаксический обход AST с ограниченным отслеживанием import aliases/scalars и консервативной инвалидацией. Он не разрешает произвольные types, branches, dynamic imports или значения между function calls. Ошибки parse/node-limit сообщаются. Обработка aliases в JavaScript ограничена; это не полный parser или scope/taint engine.

<a id="json-scope-and-comparison"></a>
## JSON, scope и сравнение

Отчёты включают tool version, timestamp, offline flag, scope, findings, issues, skipped counts, scanned counts, partial и exit code. Scope v2 связывает canonical root identity, rule fingerprint, path semantics, exclusions, limits и scanner context. Порядок context нормализуется перед hashing. Сравнения между версиями или scope не взаимозаменяемы.

Свидетельство: `REVIEWED`; эффект `READ-ONLY`. Рабочий каталог — корень; нужны два приватных JSON-отчёта заведомо сопоставимых scans. Ожидается: множества new/existing/not-observed либо exit 2 при неполном сравнении. Входные файлы не изменяются.

```bash
python3 -I -S scripts/defense_diff.py before-scan.json after-scan.json --json
```

Старые отчёты остаются читаемыми там, где это поддержано, но отсутствующий scope, различия v1/v2, изменения версии или partial reports не позволяют получить безусловно сопоставимый результат. Сопоставление использует path/line/rule: перенос строки может выглядеть как удалённый и добавленный сигнал. «Not observed» никогда не означает «уязвимость исправлена».

| Exit | Значение |
|---|---|
| 0 | Полный поддерживаемый scan без находок либо полное сравнение без новых сигналов, требующих действий |
| 1 | Находки или новые сигналы, требующие review |
| 2 | Invalid, partial, blocked или incomparable result; также отсутствие поддерживаемых входов |

<a id="coverage-and-next-steps"></a>
## Покрытие и следующие шаги

Свидетельство: `REVIEWED`; эффект `READ-ONLY`; рабочий каталог — корень. Проверка анализирует только безвредные строки; snippets не исполняются.

```bash
python3 scripts/scanner_coverage.py --check
python3 scripts/scanner_coverage.py --json
```

Ledger показывает пары rule/language, независимо написанные positives/negatives и честно отмеченные пробелы старых правил. Примеры «до/после» из metadata не считаются независимыми свидетельствами. Для исправлений используйте [каталог](vulnerabilities/README-RU.md) и [проверку патчей](patch-validation-RU.md); для контейнерной политики — [deployment audit](local-tools-RU.md#deployment-audit), не утверждая, что YAML regex доказывает runtime safety.

<a id="framework-and-database-boundaries"></a>

## Границы framework и базы данных

| Область | Расширенные сигналы | Ручная проверка |
|---|---|---|
| Flask | Явные debugger/session settings; auth order включая put/patch/delete; credentials в app.logger | Проверяйте зарегистрированный HTTP endpoint, не только вызов функции. Сохраняйте HttpOnly; не включайте Secure поверх HTTP-only checker. |
| Psycopg | SQL(не-литерал), сырые/неизвестные части format/join/as_string; известный quoting подавляет этот сигнал | Bind values через реальный драйвер. Identifier экранирует имя, но не разрешает выбирать любую таблицу. |
| PostgreSQL | ROLE/USER bypass, значимые PUBLIC grants, роли доступа к файлам/программам сервера | Проверьте runtime-роль, наследование и ownership. Меняйте только согласованные права сервиса; проверьте запросы, миграции и восстановление. |
| JS/TS | SQL из request в известных pg/mysql bindings, reflective credentialed cors, отключённый session HttpOnly, прямые credentials в логах | Bind values, allowlist origins, сохраните HttpOnly и логируйте категории. Проверьте ошибки auth, sessions, реальные response headers и checker. |

JS-подсказки используют ограниченные токены, не полноценный парсер: 100 000 токенов на файл, 128 вложенных delimiters, 2 048 токенов на выражение. Распознаются точные default/namespace imports и прямые конструкторы драйверов. Наблюдаемое переприсваивание/parameter shadowing консервативно отключает binding во всём файле. Именованные импорты, неоднозначные regex, templates, динамические keys/spreads, полученные соединения, custom loggers и потоки между файлами проверяются вручную. Helper redact() не считается доверенным и не исполняется: его результат вне прямого поиска значений.

Сигналы Docker privilege/socket/root-user остаются включены. Проверьте локальные Compose/Dockerfile, затем deployment-model audit для bind, backend exposure, mounts, image pins и runtime policy. Скан исходников не проверяет работающий daemon. LIVE и закрытый PCAP описаны в [захвате трафика](traffic-capture-RU.md).

Версия 1.8.0 повышает semantic revision до v3. Старые revision-v2 отчёты читаются, но старое/новое сравнение завершается exit 2. Перед проверкой патча пересканируйте обе копии одной версией и с одинаковым контекстом; карточки с digest вручную заполнять не нужно.
