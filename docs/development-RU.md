<a id="development-contracts-and-rule-coverage"></a>
# Разработка, контракты и покрытие правил

[English](development.md) | Русский

[Руководство для участников](../CONTRIBUTING-RU.md) · [Релизный чеклист](release-checklist-RU.md)

<a id="architecture"></a>
## Архитектура

Ядро остаётся на стандартной библиотеке Python 3.10+. Сканирование исходников, сравнение отчётов, защитные операции, упаковка и синтетические интеграции имеют отдельные entrypoints. Никогда не импортируйте целевой сервис, не выполняйте его install hooks или shell-команды из профиля и не включайте онлайн-обновления незаметно.

| Область | Источник истины |
|---|---|
| Поведение и метаданные сканера | [defense_scan.py](../scripts/defense_scan.py), [набор правил](../rules/defense.json) |
| Scope/context | [scope v2](../schemas/scanner-scope.v2.schema.json), [context v1](../schemas/scanner-context.v1.schema.json) |
| Операции | [defense_ops.py](../scripts/defense_ops.py), [profile](../schemas/profile.v1.schema.json), [snapshot](../schemas/snapshot.v1.schema.json), [comparison](../schemas/comparison.v1.schema.json) |
| Recovery/evidence | [backup manifest](../schemas/backup-manifest.v1.schema.json), [events](../schemas/event.v1.schema.json), [validation records](../schemas/validation-record.v1.schema.json) |
| Политика deployment | [model](../schemas/deployment-model.v1.schema.json), [policy](../schemas/deployment-policy.v1.schema.json), [audit](../schemas/deployment-audit.v1.schema.json) |
| Внешние артефакты | [v2 complete-target/image-export manifest](../schemas/toolchain-manifest.v2.schema.json), [устаревший v1 inventory](../schemas/toolchain-manifest.v1.schema.json), [pins](../config/toolchain.lock.json) |

Профили декларативны. Адаптеры платформ используют фиксированные read-only команды, прошедшие review. Invalid/partial/incomparable input завершается кодом 2; обычные находки и проваленные проверки — кодом 1. Запись новых артефактов требует явного пути; операционные изменения требуют явного разрешения и ограниченного rollback.

<a id="add-or-change-a-rule"></a>
## Добавление или изменение правила

1. Опишите инвариант, языковой API и ссылки на первоисточники.
2. При одинаковой семантике расширяйте существующий ID/семейство; не дублируйте детектор ради увеличения счётчика.
3. Напишите на английском title, reason, fix, check, limitations, family, подходящий CWE, review priority и signal kind. Сохраняйте существующие IDs и anchors каталога.
4. Добавьте независимо написанные positive и safe/context-negative строки в corpus fixtures. Для каждой заявленной языковой формы нужны как минимум два разных положительных и два отрицательных примера.
5. Проверьте комментарии/строковые примеры, aliases/rebinding/shadowing, одноимённые пользовательские функции и безопасные альтернативы, соответствующие движку.
6. Добавьте или обновите точный контракт детектора и рекомендации по патчу в связанном разделе каталога.
7. Запустите targeted tests, ledger, полный suite и относящиеся к изменению платформенные проверки.

Авторские примеры правила «до/после» не считаются независимыми свидетельствами. Повторяющиеся строки исходников не увеличивают покрытие. Новые правила должны соответствовать независимой цели; пробелы старых правил остаются видимыми и не заменяются придуманным покрытием.

Текущий реестр: 174 правила, 251 пара правило-язык и 347 независимых fixture-записей. Эти числа не утверждают, что каждая старая пара соответствует новой цели.

Свидетельство: `REVIEWED`; эффект `READ-ONLY` для coverage и временный `WORKSPACE-WRITE` для unit tests. Рабочий каталог — корень; нужны Python 3.10+ и ripgrep. Ожидается отсутствие новых обязательных пробелов покрытия, падающих тестов и сломанных локальных ссылок.

```bash
python3 scripts/scanner_coverage.py --check --json
python3 -m unittest discover -s tests -v
```

Тестовый код никогда не исполняет уязвимые fixture-строки. Контейнерные fixtures запускаются отдельно по выбору и требуют согласованных daemon/workspace. Дорогие regex, malformed documents, oversized files, path/race failures, поведение no-network/no-exec и вывод без секретов входят в обязательную регрессию.

<a id="versioning"></a>
## Версионирование

Версии CLI обозначают поведение, а не обещание прохождения всех deployment gates. Сохраняйте обратно совместимые flags и стабильные rule IDs. Расширение вывода может потребовать minor version; изменение смысла требует нового schema/scope-контракта и согласованного обновления потребителей.

Scanner 1.8.0 сохраняет scope v2 и повышает semantic revision до bounded-source-signals.v3. Readers читают старую семантику v2, но старый/новый scope несопоставимы (exit 2). Перед проверкой патча пересканируйте обе стороны одной версией сканера и с одинаковым контекстом. Любое изменение scope или очистки метаданных должно одновременно обновлять defense_diff, patch-check, tests и docs.

Toolchain manifest v2 различает `complete-target` и намеренно частичный scope `image-export`, привязывая полноту к сопровождаемому контракту deployment. Исторические v1 image и mixed inventories читаются только как частичные устаревшие данные и не могут быть собраны как полный комплект. При переносе полных комплектов требуется независимо сохранённый ожидаемый digest манифеста. Структурно полный и аутентифицированный манифест всё ещё требует независимой репетиции офлайн-runtime и проверки лицензий.

Человекочитаемые статусы проверки: PASS/FAIL/PARTIAL/BLOCKED/NOT_RUN/SKIPPED_NOT_APPLICABLE; validation-record.v1 использует их варианты в нижнем регистре. Не превращайте not_run в pass.

<a id="evidence-and-ci"></a>
## Свидетельства и CI

Записывайте commit/tree, platform/interpreter, версии инструментов, команды, scope, результаты и ограничения. Проверяйте точно распакованный bundle, а не только checkout. Исторические свидетельства — неизменяемый контекст, а не сертификация следующего commit.

Ручной macOS ARM64 workflow — один ограниченный job на standard runner с минимальными permissions и закреплёнными action SHAs. Он проверяет архитектуру, тесты ядра, CLI и упаковку; он не обращается к приватным тестовым хостам и не валидирует Docker Desktop или физических LAN-клиентов. Используйте только включённую квоту и перед dispatch проверяйте, что платные расходы отключены.
