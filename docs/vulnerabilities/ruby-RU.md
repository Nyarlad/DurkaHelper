<a id="ruby--rails-find-fix-and-verify"></a>

# Ruby / Rails: поиск и исправление

[English](ruby.md) | Русский

[Вся база](README-RU.md) · [Сканер](../offline-scanner-RU.md) · [Проверка патча](../patch-validation-RU.md)

18 разделов. Формат: **Поиск → Уязвимый вариант → Исправление → Проверка**.
Команды `rg` выполняются в корне локальной копии сервиса и только читают файлы. Субъект/владелец определяется по проверенной сессии, а не данным запроса. Примеры нужно адаптировать к реальным API и контракту.

Автоматические находки — ограниченные синтаксические сигналы для проверки. AST-анализ не разрешает типы и не отслеживает данные между функциями; regex не заменяет парсер языка. Комментарии, строки и одноимённые пользовательские API могут давать совпадения. Проверьте фактическое исполнение, входные данные, авторизацию и границы доверия.

<a id="contents"></a>

## Содержание

- [RUBY-OBJECT — Ruby Marshal/небезопасный YAML](#ruby-object)
- [RUBY-SHELL — Shell-строка Ruby](#ruby-shell)
- [RUBY-EVAL — Ruby eval/ERB из данных](#ruby-eval)
- [RUBY-PERMIT-ALL — Rails разрешает все параметры](#ruby-permit-all)
- [RUBY-CONSTANTIZE — Строка выбирает Ruby-класс](#ruby-constantize)
- [RUBY-HTML-SAFE — Ruby html_safe/raw](#ruby-html-safe)
- [RUBY-SQL — Интерполяция в SQL Ruby](#ruby-sql)
- [RUBY-IDOR — ActiveRecord find без области владельца](#ruby-idor)
- [RUBY-PATH — send_file и File.join на имени клиента](#ruby-path)
- [RUBY-REDIRECT — redirect_to принимает внешний return_to](#ruby-redirect)
- [RUBY-CSRF — Пропущенная forgery protection](#ruby-csrf)
- [RUBY-REGEX-ANCHOR — ^ и $ проверяют строку внутри многострочного поля](#ruby-regex-anchor)
- [RUBY-YAML-VERSION — YAML.load зависит от версии Psych](#ruby-yaml-version)
- [RUBY-DESERIALIZE-COOKIE — Подписанная cookie не обязательно секретна](#ruby-deserialize-cookie)
- [RUBY-SSRF — Net::HTTP/open-uri на вводе клиента](#ruby-ssrf)
- [RUBY-CALLBACKS — Callbacks выполняют эффект до проверки прав](#ruby-callbacks)
- [RUBY-TLS — Ruby HTTPS без проверки peer](#ruby-tls)
- [RUBY-REDIRECT-INPUT — Rails redirect напрямую принимает параметры запроса](#ruby-redirect-input)

<a id="ruby-object"></a>

<a id="ruby-object-ruby-marshal-or-unsafe-yaml"></a>

## RUBY-OBJECT. Ruby Marshal/небезопасный YAML

**Поиск:** скрипт, правило RUBY-OBJECT. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain RUBY-OBJECT. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~ruby
record = Marshal.load(payload)
~~~

**Исправление:** Внешний формат — JSON или ограниченный YAML.safe_load с явной политикой классов/aliases и схемой; legacy мигрировать отдельно.

~~~ruby
record = JSON.parse(payload) # validate DTO schema and size
~~~

**Проверка:** Произвольные объекты не создаются; старые законные данные сохранены.

<a id="ruby-shell"></a>

<a id="ruby-shell-ruby-shell-string"></a>

## RUBY-SHELL. Shell-строка Ruby

**Поиск:** скрипт, правило RUBY-SHELL. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain RUBY-SHELL. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~ruby
system(command)
~~~

**Исправление:** Фиксированный executable + отдельные argv; запрет выбора опасных опций. Backticks и %x тоже вызывают shell.

~~~ruby
system("/usr/bin/file", "--", filename)
~~~

**Проверка:** Спецсимволы не становятся командами; штатные файлы обрабатываются.

<a id="ruby-eval"></a>

<a id="ruby-eval-ruby-evalerb-from-data"></a>

## RUBY-EVAL. Ruby eval/ERB из данных

**Поиск:** скрипт, правило RUBY-EVAL. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain RUBY-EVAL. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~ruby
result = eval(input)
~~~

**Исправление:** Данные не исполнять; фиксированный ERB-шаблон + переменные или ограниченный парсер.

~~~ruby
result = JSON.parse(input) # validate expected schema
~~~

**Проверка:** Синтаксис Ruby не исполняется; штатный формат читается.

<a id="ruby-permit-all"></a>

<a id="ruby-permit-all-rails-permits-all-parameters"></a>

## RUBY-PERMIT-ALL. Rails разрешает все параметры

**Поиск:** скрипт, правило RUBY-PERMIT-ALL. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain RUBY-PERMIT-ALL. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~ruby
attrs = params.permit!
~~~

**Исправление:** Явный набор редактируемых полей, owner/role из сервера; nested params ограничить отдельно.

~~~ruby
attrs = params.require(:note).permit(:title, :body)
~~~

**Проверка:** Owner/role/вложенные неизвестные поля не применяются; допустимое частичное изменение работает.

**Основание:** [первичный материал](https://guides.rubyonrails.org/action_controller_overview.html#strong-parameters).

<a id="ruby-constantize"></a>

<a id="ruby-constantize-string-selects-a-ruby-class"></a>

## RUBY-CONSTANTIZE. Строка выбирает Ruby-класс

**Поиск:** скрипт, правило RUBY-CONSTANTIZE. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain RUBY-CONSTANTIZE. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~ruby
klass = params[:type].constantize
~~~

**Исправление:** Фиксированная карта типов с безопасным DTO. safe_constantize меняет обработку ошибки поиска, не ограничивает выбор класса.

~~~ruby
klass = {"text" => TextNote}.fetch(validated_type)
~~~

**Проверка:** Неизвестный тип не создаёт объектов; законные типы совместимы.

**Основание:** [первичный материал](https://api.rubyonrails.org/classes/ActiveSupport/Inflector.html).

<a id="ruby-html-safe"></a>

<a id="ruby-html-safe-ruby-html_saferaw"></a>

## RUBY-HTML-SAFE. Ruby html_safe/raw

**Поиск:** скрипт, правило RUBY-HTML-SAFE. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain RUBY-HTML-SAFE. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~ruby
value = params[:text].html_safe
~~~

**Исправление:** Autoescape по контексту; для предусмотренного HTML sanitizer. Не путать обработку HTML с исходником ERB.

~~~ruby
value = params[:text] # render with automatic escaping
~~~

**Проверка:** Теги и кавычки — текст, разрешённое форматирование сохранилось.

**Основание:** [первичный материал](https://guides.rubyonrails.org/security.html).

<a id="ruby-sql"></a>

<a id="ruby-sql-ruby-sql-interpolation"></a>

## RUBY-SQL. Интерполяция в SQL Ruby

**Поиск:** скрипт, правило RUBY-SQL. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain RUBY-SQL. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~ruby
Note.where("title = '#{title}'")
~~~

**Исправление:** Параметры/hash conditions; сортировка и имена полей из фиксированной карты. Сырой SQL внутри параметра не исправляется сам.

~~~ruby
Note.where(title: title, owner_id: current_user.id)
~~~

**Проверка:** Кавычки — данные; чужой owner не читается.

**Основание:** [первичный материал](https://guides.rubyonrails.org/active_record_querying.html).

<a id="ruby-idor"></a>

<a id="ruby-idor-activerecord-lookup-outside-the-owners-scope"></a>

## RUBY-IDOR. ActiveRecord find без области владельца

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e '\.find\(|find_by|params\[:id\]|current_user' .
~~~

Сверить read/update/destroy/export и association scope; strong params не выполняют авторизацию объекта.

**Уязвимый вариант:**

Note.find(params[:id]) получает запись любого пользователя.

**Исправление:** Поиск через current_user.notes либо явная policy/shared-access область; owner не из params.

**Проверка:** Своё/чужое/аноним, экспорт/удаление и предусмотренное sharing.

**Основание:** [первичный материал](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).

<a id="ruby-path"></a>

<a id="ruby-path-client-filenames-reach-send_file-and-filejoin"></a>

## RUBY-PATH. send_file и File.join на имени клиента

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'send_file|File.join|File.read|Pathname|realpath' .
~~~

Проследить filename до открытия; join не проверяет containment, realpath не убирает TOCTOU.

**Уязвимый вариант:**

send_file(params[:path]) выбирает произвольный ресурс.

**Исправление:** Серверный storage ID после policy check, контролируемый root и links, лимит/Content-Disposition.

**Проверка:** Чужой ID, абсолютный путь, ссылка наружу и штатная загрузка.

<a id="ruby-redirect"></a>

<a id="ruby-redirect-redirect_to-accepts-an-external-return_to"></a>

## RUBY-REDIRECT. redirect_to принимает внешний return_to

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'redirect_to|return_to|allow_other_host|url_from' .
~~~

Сверить версию Rails и настройки open-redirect protection; raw return_to не превращать в доверенный URL.

**Уязвимый вариант:**

Внешнее назначение разрешено параметром/allow_other_host.

**Исправление:** Серверная карта путей либо штатный безопасный механизм версии Rails с проверкой host.

**Проверка:** Внутренний переход работает, внешний origin и неоднозначный путь отклоняются.

**Основание:** [первичный материал](https://guides.rubyonrails.org/security.html).

<a id="ruby-csrf"></a>

<a id="ruby-csrf-rails-controller-disables-csrf"></a>

## RUBY-CSRF. Пропущенная forgery protection

**Поиск:** скрипт, правило RUBY-CSRF. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain RUBY-CSRF. Regex: skip_forgery_protection, skip_before_action/filter :verify_authenticity_token и allow_forgery_protection=false. only/except анализировать вручную.

Дополнительный ручной поиск для непокрытых форм:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'skip_forgery_protection|skip_before_action|protect_from_forgery|csrf' .
~~~

Проверить исключения controller и применение cookie auth на JSON endpoint.

**Уязвимый вариант:**

Cookie-сессия сохраняется, а CSRF middleware отключено ради удобства API.

**Исправление:** Восстановить проверку для cookie-auth; token API отделить явно, не отключать весь controller.

**Проверка:** Правильный token принимается, чужой origin/пустой token отклоняются; API-клиент совместим.

**Основание:** [первичный материал](https://guides.rubyonrails.org/security.html).


**Сигнал сканера — пример до:**

~~~ruby
skip_forgery_protection
skip_before_action :verify_authenticity_token
~~~

**Шаблон исправления:**

~~~ruby
protect_from_forgery with: :exception
~~~

Первичная документация: [документация 1](https://api.rubyonrails.org/classes/ActionController/RequestForgeryProtection/ClassMethods.html).

<a id="ruby-regex-anchor"></a>

<a id="ruby-regex-anchor--and--match-a-line-inside-a-multiline-value"></a>

## RUBY-REGEX-ANCHOR. ^ и $ проверяют строку внутри многострочного поля

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'validates|format:|Regexp|match\?|\^|\$' .
~~~

Сравнить начало/конец строки и всего поля; проверить переводы строк и timeout regexp.

**Уязвимый вариант:**

Валидатор имени использует ^...$ и принимает подходящую строку внутри большего значения.

**Исправление:** Для целого значения \A и \z, проверка типа/длины; при разрешённых multiline выбрать соответствующий контракт.

**Проверка:** Переводы строк в начале/конце/середине и штатный Unicode.

**Основание:** [первичный материал](https://guides.rubyonrails.org/security.html).

<a id="ruby-yaml-version"></a>

<a id="ruby-yaml-version-yamlload-behavior-depends-on-psych-version"></a>

## RUBY-YAML-VERSION. YAML.load зависит от версии Psych

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'YAML.load|Psych.load|safe_load|unsafe_load|Gemfile.lock' .
~~~

Сверить фактическую Psych/Ruby версию и allowed classes/aliases; RUBY-OBJECT намеренно не считает каждый load unsafe.

**Уязвимый вариант:**

Ожидают safe semantics нового Psych, запускают старую версию с созданием произвольных объектов.

**Исправление:** Явный safe_load с минимальным набором типов и схемой; фиксировать совместимые зависимости локально.

**Проверка:** Произвольный класс/alias и старый допустимый документ; на фактическом runtime.

**Основание:** [первичный материал](https://docs.ruby-lang.org/en/3.3/Psych.html).

<a id="ruby-deserialize-cookie"></a>

<a id="ruby-deserialize-cookie-signed-cookies-are-not-necessarily-confidential"></a>

## RUBY-DESERIALIZE-COOKIE. Подписанная cookie не обязательно секретна

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'cookies.signed|cookies.encrypted|session\[|secret_key_base' .
~~~

Посмотреть, что хранится в cookie; отличить целостность от шифрования и ключ подписи от доступа к объекту.

**Уязвимый вариант:**

В signed cookie кладут приватный текст, полагая что подпись его скрывает.

**Исправление:** Для конфиденциальности encrypted cookie либо серверный session store; минимальные данные и срок, безопасная ротация ключей.

**Проверка:** Обычная сессия читается, клиент не видит приватное содержимое, изменённая cookie отвергается.

<a id="ruby-ssrf"></a>

<a id="ruby-ssrf-client-input-reaches-nethttp-or-open-uri"></a>

## RUBY-SSRF. Net::HTTP/open-uri на вводе клиента

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Net::HTTP|URI.open|open-uri|Faraday|HTTParty' .
~~~

Найти URL parser, redirects и DNS в реальном adapter.

**Уязвимый вариант:**

URL/redirect ведёт к внутреннему ресурсу с доверием к приложению.

**Исправление:** Фиксированное назначение либо единая политика всех переходов/соединения и лимиты; URI.parse не авторизация.

**Проверка:** Mock redirect/DNS, запрещённая схема, timeout и штатный upstream.

**Основание:** [первичный материал](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

<a id="ruby-callbacks"></a>

<a id="ruby-callbacks-callbacks-cause-effects-before-authorization"></a>

## RUBY-CALLBACKS. Callbacks выполняют эффект до проверки прав

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'before_save|after_save|after_commit|after_find|validate|authorize' .
~~~

Сопоставить policy check, instantiation, callbacks и transaction boundary.

**Уязвимый вариант:**

Модель пишет файл/отправляет задачу в callback до auth либо до commit.

**Исправление:** Авторизация до изменения; внешние эффекты после подтверждённого commit, идемпотентность и компенсация по контракту.

**Проверка:** Rollback/отказ не оставляет эффектов, повторная задача не дублирует результат.

<a id="ruby-tls"></a>

<a id="ruby-tls-ruby-https-peer-verification-disabled"></a>

## RUBY-TLS. Ruby HTTPS без проверки peer

**Поиск:** скрипт, правило RUBY-TLS. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain RUBY-TLS. Regex: VERIFY_NONE. Не определяет, применён ли объект к реальному соединению.

**Уязвимый вариант:** VERIFY_NONE делает TLS-соединение непроверенным.

~~~ruby
http.verify_mode = OpenSSL::SSL::VERIFY_NONE
~~~

**Исправление:** Вернуть проверку peer/hostname и доверенный CA; проверить настройки используемого HTTP-клиента.

~~~ruby
http.verify_mode = OpenSSL::SSL::VERIFY_PEER
http.ca_file = trusted_ca_file
~~~

**Проверка:** Штатный сервер доступен, неверный сертификат не даёт полезного ответа.

Первичная документация: [документация 1](https://docs.ruby-lang.org/en/master/OpenSSL/SSL/SSLContext.html).

<a id="ruby-redirect-input"></a>

<a id="ruby-redirect-input-rails-redirect-takes-request-params-directly"></a>

## RUBY-REDIRECT-INPUT. Rails redirect напрямую принимает параметры запроса

**Поиск:** правило сканера RUBY-REDIRECT-INPUT. Точный контракт детектора: `--explain RUBY-REDIRECT-INPUT`. Regex с лексическими исключениями: redirect_to с params[...] или request.params[...], с необязательной открывающей скобкой. Defaults фреймворка могут уже запрещать внешние hosts; aliases, вспомогательные функции и allow_other_host требуют проверки.

**Уязвимый вариант:**

~~~ruby
redirect_to params[:next]
~~~

**Исправление:** Используйте маршруты, выбранные сервером, или явную политику redirect; сохраняйте проверки host в Rails и учитывайте установленную версию фреймворка.

~~~ruby
redirect_to account_path
~~~

**Проверка:** Чужие адреса и адреса вида //host отклоняются; обычная навигация работает.

[Первичный источник 1](https://api.rubyonrails.org/classes/ActionController/Redirecting.html)
