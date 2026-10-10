<a id="patch-verification-deployment-and-rollback"></a>
# Проверка патчей, deployment и rollback

[English](patch-validation.md) | Русский

[Шпаргалка защитника](defense-cheatsheet-RU.md) · [Каталог](vulnerabilities/README-RU.md)

За deployment каждого сервиса отвечает один человек. Все начальные проверки выполняются на изолированной локальной копии разрешённого сервиса. Адаптируйте production-команды только после подтверждения его фактического контракта запуска и данных. Обычный ручной маршрут: сохранить оригиналы, применить небольшой патч, прогнать regression/normal-user/checker проверки и повторить скан. Карточки и ручное переписывание hashes не нужны; раздел 4 — необязательная расширенная проверка evidence, не условие ручного исправления.

<a id="1-preserve-the-before-state"></a>
## 1. Сохраните исходное состояние

Запишите ревизию кода и локальный diff, неизменяемый image ID, источники конфигурации, текущие данные и способ rollback. Это разные активы: откат кода не должен восстанавливать старую БД поверх записей новых раундов.

Свидетельство: `REVIEWED`; эффект `READ-ONLY`; рабочий каталог — checkout сервиса с Git. Ожидается: фактическая ревизия и существующие изменения. Вывод может содержать приватные пути; не транслируйте его. Rollback: не нужен.

```bash
git status --short
git rev-parse HEAD
git diff --check
```

Без Git приватно скопируйте только изменяемые файлы подходящими backup tools; проверка checksum может быть автоматической. Никогда не используйте общий git add, reset --hard или git clean как универсальный рабочий процесс. [Файловый backup](local-tools-RU.md#backup-and-staging-restore) ограничен, но базы данных требуют нативных консистентных dumps или проверенной процедуры копирования в остановленном состоянии.

<a id="2-required-behavioral-matrix"></a>
## 2. Обязательная матрица поведения

| Проверка | Успешный результат |
|---|---|
| Регрессия дефекта | Один и тот же тест безопасного поведения падает до и проходит после |
| Обычный пользователь | Работают login, create/read/update и ожидаемый sharing |
| Авторизация | Владелец проходит; другой пользователь/tenant и анонимный caller получают отказ без side effects |
| Старые данные | Записи до патча сохраняют формат и доступность |
| Persistence | Новые записи переживают согласованный изолированный restart |
| Альтернативные пути | Lists, exports, files, jobs и затронутые routes соблюдают то же правило |
| Границы ввода | Empty/wrong-type/Unicode/maximum values соответствуют контракту |
| Отказ зависимости | Ограниченный, очищенный отказ без авторизации по умолчанию |
| Checker | Сохраняются настоящая семантика турнира и SLA |

Проверяйте отсутствие запрещённых эффектов, а не только status codes: denied reads не содержат чужого body, denied writes оставляют rows неизменными, blocked URLs никогда не вызывают HTTP client. [PY-SQL](vulnerabilities/python-RU.md#py-sql) содержит небольшой пример приватной заметки; проверяйте интеграцию route/session вместе с helper.

<a id="3-match-the-deployment-mechanism"></a>
## 3. Учитывайте механизм deployment

| Механизм | Необходимое действие / ловушка |
|---|---|
| Source bind mount | Обновляйте только проверенные файлы; restart нужен только если его требует процесс |
| Код скопирован в image | Соберите новый закреплённый image и пересоздайте собственный сервис; один restart не пересобирает image |
| Native binary | Проверьте architecture/libraries/permissions и совместимость данных |
| API и workers | Согласованно обновите зависимые процессы; старые workers могут сохранить старое поведение |

Изучите entrypoints на предмет destructive initialization/migrations и найдите persistent data. Не перенастраивайте игровые сети, не удаляйте volumes и не пересобирайте посторонние компоненты ради source patch.

До production-одобрения отрепетируйте точную rollback-команду на копии. Она должна восстанавливать code/image с сохранением текущих данных. Держите старый image локально; изменяемый тег latest не является целью rollback.

<a id="4-bound-evidence-to-this-patch"></a>
## 4. Привяжите свидетельства к этому патчу

Соберите before/after snapshots и scans с одним предполагаемым scope, затем health и фактические regression-test records. Результат из другого прогона не подтверждает статус этого патча.

[Schema validation-record](../schemas/validation-record.v1.schema.json) использует lowercase statuses. Attributes каждой записи должны содержать точный SHA-256 входов before_snapshot, after_snapshot, before_scanner, after_scanner и health под соответствующими ключами *_sha256, а также один общий run_id. Время записи должно быть позже зависимых evidence.

Если deployment audit обязателен, включите его audit/model/policy hashes в ту же запись. Аудит пересчитывается по model/policy; его source hash должен соответствовать точной runtime configuration, зафиксированной в after-snapshot. Он проверяет заявленную конфигурацию, а не фактическое состояние работающего daemon.

Свидетельство: `REVIEWED`; эффект `READ-ONLY`; рабочий каталог — корень. Требования: подлинные приватные evidence по примерным путям, актуальные hashes/timestamps и совпадающий scope. Ожидается: 0/pass, 1/regression или 2/incomplete. Никогда не придумывайте pass records только ради выполнения условия приёмки. Rollback: не нужен.

```bash
python3 scripts/defense_ops.py patch-check \
  --before ../private-results/before.json --after ../private-results/after.json \
  --before-scanner ../private-results/before-scan.json \
  --after-scanner ../private-results/after-scan.json \
  --health-result ../private-results/health.json \
  --validation-record ../private-results/regression.json \
  --deployment-audit ../private-results/deployment-audit.json \
  --deployment-model ../private-deployment/run-01/runtime-model.json \
  --deployment-policy ../private-deployment/run-01/runtime-policy.json \
  --require-deployment-audit
```

Для изменений только исходников без deployment audit явно уберите все четыре deployment arguments. Обязательные health/scanner/validation evidence всё равно нужны. Отсутствующие, устаревшие, partial, not-run, несовпадающие или несопоставимые свидетельства не могут дать clean pass.

Для ожидаемого drift требуется явно проверенная [approved-drift record](../schemas/approved-drift.v1.schema.json), привязанная к обоим snapshot hashes и точным классифицированным изменениям; передайте её через --approved-drift. Общее wildcard-разрешение не поддерживается.

<a id="5-apply-observe-revert-if-necessary"></a>
## 5. Примените, наблюдайте, при необходимости откатите

После явного разрешения используйте только отрепетированный путь deployment собственного сервиса. Сразу повторите health, фактические операции пользователей/checker и чтение старых данных, затем наблюдайте полный релевантный интервал раунда. При сбое сохраните очищенную incident timeline.

Сначала откатите code/image по записанному плану. Восстановление данных — отдельное решение с серьёзными последствиями: старый dump может стереть данные нового раунда. Не меняйте попутно ключи, schemas или runtime.
