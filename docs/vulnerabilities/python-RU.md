<a id="python-find-fix-and-verify"></a>

# Python: поиск и исправление

[English](python.md) | Русский

[Вся база](README-RU.md) · [Сканер](../offline-scanner-RU.md) · [Проверка патча](../patch-validation-RU.md)

40 разделов. Формат: **Поиск → Уязвимый вариант → Исправление → Проверка**.
Команды `rg` выполняются в корне локальной копии сервиса и только читают файлы. Субъект/владелец определяется по проверенной сессии, а не данным запроса. Примеры нужно адаптировать к реальным API и контракту.

Автоматические находки — ограниченные синтаксические сигналы для проверки. AST-анализ не разрешает типы и не отслеживает данные между функциями; regex не заменяет парсер языка. Комментарии, строки и одноимённые пользовательские API могут давать совпадения. Проверьте фактическое исполнение, входные данные, авторизацию и границы доверия.

<a id="contents"></a>

## Содержание

- [PY-EVAL — Выполнение текста как Python](#py-eval)
- [PY-SHELL — Shell в Python](#py-shell)
- [PY-DESERIALIZE — Десериализация объектов Python](#py-deserialize)
- [PY-YAML — YAML с потенциально опасным Loader](#py-yaml)
- [PY-SQL — SQL собирается строковым выражением](#py-sql)
- [PY-ORM-BOOL — Python and/or в ORM](#py-orm-bool)
- [PY-TEMPLATE — Динамический исходник шаблона](#py-template)
- [PY-TLS — TLS verify=False](#py-tls)
- [PY-DEBUG — Веб-отладчик Python](#py-debug)
- [PY-JWT — Подпись JWT отключена](#py-jwt)
- [PY-ARCHIVE — Распаковка требует проверки путей](#py-archive)
- [PY-TEMP — Неатомарное имя временного файла](#py-temp)
- [PY-XML — XML с разрешёнными сущностями](#py-xml)
- [PY-WEAK-HASH — MD5/SHA1: проверить назначение](#py-weak-hash)
- [PY-RNG — Обычный PRNG в возможном секрете](#py-rng)
- [PY-FILE — Динамический путь выдачи файла](#py-file)
- [PY-URL — Динамический исходящий URL](#py-url)
- [PY-CRC — CRC/Adler как возможная защита целостности](#py-crc)
- [PY-XPATH — Строковая сборка XPath](#py-xpath)
- [PY-UUID-BYTES — Граница UUID bytes/bytes_le](#py-uuid-bytes)
- [PY-ASSERT-AUTH — Проверка доступа через assert](#py-assert-auth)
- [PY-DJANGO-HOSTS — Любой host разрешён через ALLOWED_HOSTS Django](#py-django-hosts)
- [PY-HTML-SAFE — Явное отключение HTML-экранирования](#py-html-safe)
- [PY-MASS-ASSIGN — Поля запроса становятся атрибутами модели](#py-mass-assign)
- [PY-DECORATOR-AUTH — Маршрут зарегистрирован до auth-декоратора](#py-decorator-auth)
- [PY-ASYNC-CONTEXT — Глобальный current_user между async-запросами](#py-async-context)
- [PY-REDIRECT — Открытый redirect и доверие next](#py-redirect)
- [PY-PASSWORD-HASH — Быстрый digest вместо хранения пароля](#py-password-hash)
- [PY-ZIP-LIMITS — Архив: traversal, symlink и распаковочный объём](#py-zip-limits)
- [PY-JSON-DUPLICATES — Разные парсеры выбирают разные повторные ключи](#py-json-duplicates)
- [PY-CACHE-KEY — Коллизии ключей кэша авторизации](#py-cache-key)
- [PY-JWT-DEPENDENCY — Уязвимая зависимость проверки JWT](#py-jwt-dependency)
- [PY-CHALLENGE-STATE — Challenge раскрывается до фиксации commitment](#py-challenge-state)
- [PY-SSL-CONTEXT — Отключённая проверка TLS-контекста](#py-ssl-context)
- [PY-CSRF-EXEMPT — Исключение Django view из CSRF](#py-csrf-exempt)
- [PY-JWT-ALGORITHMS — Алгоритм JWT берётся из выражения](#py-jwt-algorithms)
- [PY-JWT-CLAIMS — Проверки срока и адресата JWT отключены](#py-jwt-claims)
- [PY-REGEX-DYNAMIC — Динамический шаблон регулярного выражения](#py-regex-dynamic)
- [PY-AUTH-DECORATOR — Маршрут Flask регистрируется до защиты login_required](#py-auth-decorator)
- [PY-LOG-CREDENTIALS — Значение, похожее на credential, напрямую передаётся в logging](#py-log-credentials)

<a id="py-eval"></a>

<a id="py-eval-executing-text-as-python"></a>

## PY-EVAL. Выполнение текста как Python

**Поиск:** скрипт, правило PY-EVAL. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-EVAL. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~python
eval(payload)
~~~

**Исправление:** Для данных — JSON + схема; для DSL — ограниченный парсер. Не переносить код в другой eval.

~~~python
import json
value = json.loads(payload)
if not isinstance(value, dict):
    raise ValueError('object required')
~~~

**Проверка:** Допустимый документ читается; выражения Python не исполняются; есть лимит размера.

<a id="py-shell"></a>

<a id="py-shell-python-shell-execution"></a>

## PY-SHELL. Shell в Python

**Поиск:** скрипт, правило PY-SHELL. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-SHELL. AST: shell=True через явный аргумент или inline **dict, shell helpers, буквальный argv shell у subprocess и asyncio.create_subprocess_exec. Значения argv из переменных, wrappers и сложное ветвление не вычисляются.

**Уязвимый вариант:**

~~~python
import subprocess
subprocess.run(command, shell=True)
~~~

**Исправление:** Фиксированный executable и список argv без shell; аргументы ограничить контрактом утилиты.

~~~python
import subprocess
subprocess.run(['/usr/bin/file', '--', filename], shell=False, check=True, timeout=3)
~~~

**Проверка:** Спецсимволы остаются частью аргумента; опасные опции не проходят; штатная операция работает.

<details>
<summary>Развёрнутый пример и ограничения</summary>

**Узнать:** пользовательский текст склеивается в команду с `shell=True`.

```python
# Vulnerable: data becomes part of an interpreter command.
digest = subprocess.check_output("printf '%s' '" + text + "' | sha256sum", shell=True)
```

**Патч для SHA-256 содержимого:**

<!-- example: py-sha256 -->
```python
import hashlib

def digest_text(text):
    if not isinstance(text, str):
        raise ValueError("text must be a string")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
```

Сохранить ожидаемую кодировку и формат ответа. Оболочка `sha256sum` печатает
дополнительные поля/перевод строки; API мог их обрабатывать отдельно. Если
команда нужна для другой функции, см. [ограничения аргументов](README-RU.md).

**Проверить:** известный digest, пустой текст, кавычки, перевод строки, Unicode;
отсутствие запуска внешней программы. Для хеширования паролей этот рецепт не подходит.

</details>

<a id="py-deserialize"></a>

<a id="py-deserialize-python-object-deserialization"></a>

## PY-DESERIALIZE. Десериализация объектов Python

**Поиск:** скрипт, правило PY-DESERIALIZE. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-DESERIALIZE. AST: pickle/dill/shelve, jsonpickle.decode/loads, joblib.load, pandas.read_pickle, Unpickler(...).load и простое локальное присваивание Unpickler. numpy.load и numpy.lib.format.read_array — только известный allow_pickle=True (именованный либо третий/второй позиционный аргумент соответственно). Учтены import aliases, простые scalar присваивания и inline **dict; defaults старых версий, mutable dict, wrappers и доверенность данных проверять вручную.

**Уязвимый вариант:**

~~~python
import pickle
value = pickle.loads(data)
~~~

**Исправление:** Для обмена обычными данными использовать JSON со схемой;
для числовых массивов NumPy сохранить `.npy`/`.npz` с `allow_pickle=False`
и проверкой dtype/формы/лимитов, как показано ниже. JSON не является универсальной
заменой этих форматов. Старые доверенные записи мигрировать отдельно;
не загружать клиентский pickle для конвертации.

~~~python
import json
value = json.loads(data)  # validate schema
~~~

**Проверка:** Ранее созданные данные читаются; неизвестные поля/типы и объектные массивы отклоняются; проверяются dtype, форма и объём данных.

<details>
<summary>Развёрнутый пример и ограничения</summary>

**Узнать:** pickle приходит из cookie, тела запроса, загрузки или строки в БД,
которую ранее мог записать клиент. Base64 не делает содержимое доверенным.

```python
# Vulnerable with untrusted raw input: loading can execute code.
profile = pickle.loads(raw)
```

**Патч для простого обмена профилем**, если протокол уже допускает JSON
или согласован его совместимый переход:

<!-- example: py-profile -->
```python
import json

def decode_profile(raw):
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {"display_name"}:
        raise ValueError("unexpected profile fields")
    if not isinstance(value["display_name"], str):
        raise ValueError("display_name must be a string")
    return {"display_name": value["display_name"]}
```

HTTP-слой ограничивает размер тела до чтения; JSON-схема не ограничивает стоимость
парсинга автоматически. Роль и владелец определяются на сервере. Не оставлять
fallback в `pickle.loads` при ошибке JSON. Не переводить старые записи
небезопасным парсером, пока не доказано доверие к их происхождению.

**Проверить:** корректное имя, Unicode и допустимое пустое значение; массив,
число и неизвестное служебное поле отклоняются; старые данные/клиенты совместимы.
Если checker требует прежний формат, замена парсера без плана миграции не готова к выкладке.

</details>


Объектный JSON тоже требует проверки: jsonpickle.decode не равен обычному json.loads. [jsonpickle](https://jsonpickle.readthedocs.io/en/latest/), [joblib.load](https://joblib.readthedocs.io/en/stable/generated/joblib.load.html) и [pandas.read_pickle](https://pandas.pydata.org/docs/reference/api/pandas.read_pickle.html) предупреждают о недоверенном входе. Установить происхождение сериализованного объекта до загрузки.

**NumPy и объектные массивы.** `numpy.load` с `allow_pickle=True` разрешает
объектную десериализацию из файла. У `numpy.load` это третий позиционный аргумент,
у `numpy.lib.format.read_array` — второй. Установить, может ли клиент заменить
файл или запись в хранилище: расширение `.npy`/`.npz` доверие не доказывает.
[numpy.load](https://numpy.org/doc/stable/reference/generated/numpy.load.html),
[read_array](https://numpy.org/doc/stable/reference/generated/numpy.lib.format.read_array.html).

~~~python
import numpy as np
values = np.load(upload_path, allow_pickle=True)
~~~

Для контракта числового `.npy` предложенный патч сохраняет формат массива:

~~~python
import numpy as np
values = np.load(upload_path, allow_pickle=False)
if not isinstance(values, np.ndarray) or values.dtype.kind not in "iuf":
    raise ValueError("numeric array required")
~~~

Проверить допустимые dtype, размерность и количество элементов по контракту.
Ограничить размер входа до загрузки; проверки уже созданного массива не заменяют
лимиты памяти. `allow_pickle=False` отклоняет прежние object arrays: сначала
спланировать миграцию доверенных данных, не включать небезопасный fallback.
Для `.npz` сохранять предусмотренный API контейнера и закрывать `NpzFile`;
пример выше предназначен только для одиночного числового `.npy`.

Ручной поиск параметров и версии без импорта анализируемого проекта:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'numpy|allow_pickle|read_array|requirements|poetry.lock|uv.lock' .
~~~

После совпадения связать импорт с вызовом, проверить lock-файл/метаданные
развёрнутого окружения и фактический источник файла. Сканер не определяет
версию, доверенность файла и значения словарей-переменных. Отсутствующий
`allow_pickle` не получает сигнал: значение по умолчанию проверить для версии.
Проверка патча: числовые массивы прежних dtype/формы читаются, object array
отвергается без выполнения его содержимого, oversized вход ограничен; старые
данные сохраняются по плану миграции.

<a id="py-yaml"></a>

<a id="py-yaml-yaml-with-a-potentially-unsafe-loader"></a>

## PY-YAML. YAML с потенциально опасным Loader

**Поиск:** скрипт, правило PY-YAML. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-YAML. AST: yaml.load/load_all/unsafe_load/unsafe_load_all; SafeLoader/CSafeLoader/BaseLoader/CBaseLoader исключаются, включая import aliases, позиционный Loader и inline **dict. BaseLoader/CBaseLoader возвращают scalars строками; defaults конкретной версии, wrappers и лимиты ресурсов проверить вручную.

**Уязвимый вариант:**

~~~python
import yaml
value = yaml.load(data, Loader=yaml.Loader)
~~~

**Исправление:** safe_load, затем проверить типы/поля и ограничить размер/сложность документа.

~~~python
import yaml
value = yaml.safe_load(data)  # validate schema
~~~

**Проверка:** Обычный YAML работает; теги объектов и неожиданные структуры отвергаются.

`yaml.BaseLoader` и `yaml.CBaseLoader` не создают произвольные Python-объекты
и не получают этот сигнал. Они превращают скаляры в строки: например, `false`
не становится `False`, а непустая строка в условии истинна. Такой loader допустим,
если приложение явно проверяет и преобразует строки согласно схеме;
заменять им `SafeLoader` во всём сервисе без проверки типов нельзя.
`SafeLoader`/`CSafeLoader` сохраняют стандартные YAML-типы, но не заменяют схему
и лимиты размера/вложенности. Включение собственных constructors проверить
отдельно. [PyYAML: loaders и типы](https://pyyaml.org/wiki/PyYAMLDocumentation).

~~~python
import yaml
raw_settings = yaml.load(data, Loader=yaml.BaseLoader)
# Strings are expected; validate structure and convert fields separately.
~~~

Для wrappers, переопределений loader и версий:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'yaml[.]|Loader|add_constructor|PyYAML|requirements|poetry.lock|uv.lock' .
~~~

Сопоставить вызов с импортом, выбранным loader и зарегистрированными
constructors; версию проверить по lock-файлу и метаданным развёртывания,
не импортируя сервис. Дополнительно проверить числа, булевы значения, даты,
пустые scalars и прежние документы на фактическом runtime. Если контракт уже
использует `BaseLoader`, отсутствие PY-YAML означает только отсутствие
известной опасной объектной загрузки, а не доказанную безопасность парсинга.

<a id="py-sql"></a>

<a id="py-sql-sql-assembled-from-string-expressions"></a>

## PY-SQL. SQL собирается строковым выражением

**Поиск:** правило сканера PY-SQL. Подробности: `--explain PY-SQL`. AST: строковая сборка в SQL-вызовах и keywords, включая простые присваивания. Импортированные psycopg/psycopg2.sql SQL(не-литерал) и format/join с неизвестными или сырыми частями дают сигнал. Литеральный SQL с известными Identifier/Literal/Placeholder подавляет только этот сигнал, но не проверку прав на таблицу. Изменяемые объекты, wrappers, межфункциональные потоки и версии драйверов требуют ручного анализа.

**Уязвимый вариант:**

~~~python
db.execute("SELECT id FROM notes WHERE name=%s" % name)
~~~

**Исправление:** Параметры драйвера вместо подстановки; identifiers выбирать из фиксированного набора. Placeholder зависит от драйвера.

~~~python
db.execute("SELECT id FROM notes WHERE name=?", (name,))  # sqlite3
~~~

**Проверка:** Кавычки остаются данными; ограничения владельца и обычные запросы работают корректно.

Фиксированный SQL не становится инъекцией от разделения на строковые литералы:

~~~python
db.execute("SELECT " + "1")
db.execute(f"SELECT 1")
~~~

Такие формы не получают PY-SQL. Исключение ограничено литералами, их сложением
и f-строкой без подстановок; общего вычисления константных выражений нет.
Например, `.format()` остаётся синтаксическим сигналом и требует просмотра.
Исчезновение сигнала не проверяет право на объект, смысл фиксированного запроса
или настройки драйвера. Для пользовательских значений сохранить bind-параметры,
а не заменять один вид интерполяции другим.
[sqlite3: параметры запроса](https://docs.python.org/3/library/sqlite3.html#how-to-use-placeholders-to-bind-values-in-sql-queries).

<details>
<summary>Развёрнутый пример и ограничения</summary>

**Узнать:** `execute(f"...")`, `%`, `.format()` или конкатенация внутри SQL;
объект выбирается без проверки владельца.

```python
# Vulnerable: client_id controls SQL; ownership is not constrained.
row = db.execute(f"SELECT body FROM notes WHERE id = '{client_id}'").fetchone()
```

**Минимальный патч для приватных заметок в sqlite3:**

<!-- example: py-read-note -->
```python
def read_private_note(db, user_id, note_id):
    if user_id is None:
        raise PermissionError("authentication required")
    row = db.execute(
        "SELECT body FROM notes WHERE id = ? AND owner_id = ?",
        (note_id, user_id),
    ).fetchone()
    if row is None:
        raise LookupError("not found")
    return row[0]
```

Маркер `?` относится к sqlite3. В psycopg использовать `%s` **в SQL** и отдельный
кортеж значений; не применять Python-оператор `%` к запросу. Имена столбцов
не становятся безопасными от передачи как параметров значений.

**Проверить:** владелец читает старую запись; другой пользователь и аноним — нет;
строковый ID с кавычкой обрабатывается как значение; список/экспорт соблюдают
тот же контроль. Если ID строго числовой, валидировать его по контракту.

</details>

**Вариант A/D:** SQL blacklist не учитывает взаимодействие параметров. **ECSC / fonograph, автор.** Фильтр символов не предотвращал изменение
границ соседних строковых аргументов.
**Патч:** параметры драйвера вместо ручной сборки и blacklist.
**Тест:** кавычки/backslash в каждом параметре и их комбинации, обычный текст.
**Поиск:** PY-SQL; «есть sanitize» не снимает сигнал.

[исходник/разбор 1](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/fonograph/README.md); [исходник/разбор 2](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/fonograph/backend/db.py); [исходник/разбор 3](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/fonograph/backend/handlers.py).

<a id="py-orm-bool"></a>

<a id="py-orm-bool-python-andor-used-in-an-orm-expression"></a>

## PY-ORM-BOOL. Python and/or в ORM

**Поиск:** скрипт, правило PY-ORM-BOOL. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-ORM-BOOL. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~python
User.find(User.name == name and User.password == password)
~~~

**Исправление:** Композиция конкретной ORM: Beanie find(cond1, cond2), SQLAlchemy and_(...). Python and/or может отбросить условие.

~~~python
User.find(User.name == name, User.password == password)  # Beanie
~~~

**Проверка:** Оба предиката присутствуют в фактическом запросе; неверный пароль и доступ к чужому объекту отклоняются. Из четырёх пар верного/неверного имени и пароля только одна авторизуется.

**Вариант A/D:** Python and вместо композиции Beanie. **Основание:** explorers CTF Cup, анализ кода и закреплённой зависимости
Beanie 1.23.6. Полная авторизация с MongoDB здесь не воспроизводилась.
Сканер на исходнике обнаружил PY-ORM-BOOL.

~~~python
# before
User.find(User.username == name and User.password == password)
# after: Beanie accepts multiple criteria
User.find(User.username == name, User.password == password)
~~~

**Тест:** четыре комбинации верного/неверного имени и пароля, разные пользователи,
пустые значения; проверить фактически сформированный фильтр. Для другой ORM
использовать её API, а не копировать синтаксис.

[исходник/разбор 1](https://github.com/C4T-BuT-S4D/ctfcup-2023-ad/blob/53d6b9b7369448ac6c5d7d8e9458f66b25271e8a/services/explorers/src/app/api.py); [исходник/разбор 2](https://github.com/C4T-BuT-S4D/ctfcup-2023-ad/blob/53d6b9b7369448ac6c5d7d8e9458f66b25271e8a/services/explorers/src/requirements.txt).

<a id="py-template"></a>

<a id="py-template-dynamic-template-source"></a>

## PY-TEMPLATE. Динамический исходник шаблона

**Поиск:** скрипт, правило PY-TEMPLATE. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-TEMPLATE. AST: render_template_string/from_string по имени метода, первый позиционный аргумент либо source=, включая import aliases и inline **dict. Нелитеральный исходник даёт review; кастомные одноимённые методы могут совпадать. Переменные dict, wrappers, тип окружения, доверие к исходнику и autoescape проверять вручную.

**Уязвимый вариант:**

~~~python
from flask import render_template_string
render_template_string(source=user_text)
~~~

**Исправление:** Фиксированный шаблон + параметры; проверить autoescape и контекст HTML/JS.

~~~python
from flask import render_template_string
render_template_string(source='<p>{{ message }}</p>', message=user_text)
~~~

**Проверка:** Синтаксис шаблона показывается текстом; штатная верстка сохранена.

`source=` у Flask `render_template_string` и Jinja `Environment.from_string`
задаёт именно исходник. Autoescape экранирует вывод, но не запрещает вычисление
выражений из недоверенного исходника. Параметр `message` в фиксированном шаблоне
остаётся данными. Проверить aliases импортов, wrappers и перенесённые в конфиг
шаблоны: сканер не устанавливает происхождение строки.
[Flask: render_template_string](https://flask.palletsprojects.com/en/stable/api/#flask.render_template_string),
[Jinja: from_string](https://jinja.palletsprojects.com/en/stable/api/#jinja2.Environment.from_string).

<details>
<summary>Развёрнутый пример и ограничения</summary>

**Узнать:** `render_template_string` или `Environment.from_string` получает
строку из запроса, в том числе после конкатенации с HTML.

```python
# Vulnerable: the user controls template source.
return render_template_string(request.form["message"])
```

**Патч Flask:**

```python
from flask import render_template, request

message = request.form["message"]
return render_template("message.html", message=message)
```

`templates/message.html` — фиксированный файл проекта:

```html
<p>{{ message }}</p>
```

Не добавлять `|safe`. Flask по умолчанию включает autoescape для HTML-шаблонов;
проверить, что приложение его не отключило. Экранирование HTML и запрет компиляции
пользовательского шаблона — две разные границы.

**Проверить:** строка `{{ 2 + 3 }}` выводится буквально, а не как результат
выражения; кавычки и HTML отображаются как текст; обычное сообщение сохранено.
Если функция сервиса именно редактор шаблонов, эта замена меняет контракт:
нужен отдельный дизайн допустимого языка, а не этот быстрый патч.

</details>

<a id="py-tls"></a>

<a id="py-tls-tls-verifyfalse"></a>

## PY-TLS. TLS verify=False

**Поиск:** скрипт, правило PY-TLS. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-TLS. AST: verify=False, простая локальная скалярная переменная или inline **dict; учитывается порядок перезаписи ключей. Известны requests Session/session и httpx Client/AsyncClient, включая подходящие with/async with; requests Session.send и httpx.stream также распознаются. Общий поиск методов get/post/put/patch/delete/request остаётся эвристикой без доказанного типа. Переменные dict, свойства клиента, runtime config и wrappers не вычисляются.

**Уязвимый вариант:**

~~~python
import requests
requests.get(url, verify=False)
~~~

**Исправление:** Вернуть проверку TLS; при необходимости задать доверенный CA bundle.

~~~python
import requests
requests.get(url, verify=True, timeout=3)
~~~

**Проверка:** Доверенный CA и правильное имя сервера принимаются; неверный, просроченный сертификат или сертификат другого host отклоняется без обходного режима.

У `requests.Session.send` параметр `verify` действует на отправку подготовленного
запроса, в том числе внутри `with requests.session() as session`.
При использовании собственного CA сохранить нужную цепочку доверия;
не отключать проверку ради исправления ошибки сертификата.
Для prepared requests отдельно проверить способ объединения настроек окружения.
[Requests: подготовленные запросы и TLS](https://requests.readthedocs.io/en/latest/user/advanced/).

~~~python
import requests
with requests.session() as session:
    with session.send(prepared_request, verify=False, timeout=3) as response:
        response.raise_for_status()
~~~

В таком вызове вернуть `verify=True` либо передать путь к принятому CA bundle.
Сканер проверяет явно переданный флаг, но не восстанавливает URL внутри
`prepared_request`, настройки адаптера и политику доверия всего приложения.

У `httpx.Client`/`AsyncClient` проверка задаётся в конструкторе. `verify`
у клиентского `stream` не является допустимым параметром; модульный
`httpx.stream` принимает его. Пример сохранения потокового чтения с проверкой TLS:

~~~python
import httpx
with httpx.Client(verify=True, timeout=3) as client:
    with client.stream('GET', approved_url) as response:
        response.raise_for_status()
        # Read inside the context, bounded by the service contract.
~~~

Для своего CA использовать поддерживаемый текущим HTTPX `ssl.SSLContext`.
Контекстный блок закрывает ответ; сам TLS не проверяет допустимость адресата,
поэтому динамический `approved_url` сохраняет PY-URL до ручного просмотра.
[HTTPX: Client и stream](https://www.python-httpx.org/api/).

<a id="py-debug"></a>

<a id="py-debug-python-web-debugger-enabled"></a>

## PY-DEBUG. Веб-отладчик Python

**Поиск:** правило сканера PY-DEBUG. Подробности: `--explain PY-DEBUG`. AST: явные debug/use_debugger=True в run/run_simple (старый поиск по имени). Для известного импортированного Flask: DEBUG=True через config[index]/update/from_mapping и app.debug=True. Поддерживаются inline dict и aliases; пользовательские фабрики, runtime overrides, файлы конфигурации и ветвления требуют ручной проверки.

**Уязвимый вариант:**

~~~python
app.run(debug=True)
~~~

**Исправление:** Отключить debug/use_debugger в игровом процессе; сохранить приватную диагностику с удалением секретов из вывода.

~~~python
app.run(debug=False)
~~~

**Проверка:** Ошибки без консоли и stack trace; все штатные маршруты доступны.

<a id="py-jwt"></a>

<a id="py-jwt-jwt-signature-verification-disabled"></a>

## PY-JWT. Подпись JWT отключена

**Поиск:** скрипт, правило PY-JWT. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-JWT. AST: options.verify_signature=False, включая inline **kwargs/options и порядок перезаписи dict. Только jose.jwt.decode и jwt.decode_complete также связывают options с четвёртым позиционным аргументом; generic jwt.decode позиционно неоднозначен между версиями. Legacy verify=False сохраняется для generic jwt.decode, но не для двух известных современных API. *args, mutable dict, wrappers и настройки экземпляра вручную; явно дублированные positional/keyword algorithms/options не трактуются как исполнимый JWT-вызов.

**Уязвимый вариант:**

~~~python
import jwt
claims = jwt.decode(token, options={'verify_signature': False})
~~~

**Исправление:** Проверять подпись, фиксированный алгоритм, назначение токена
и обязательные claims; существующий ключ — из защищённого конфига. Пример ниже
для PyJWT 2.x; у python-jose другой формат обязательных claims, см.
[PY-JWT-CLAIMS](#py-jwt-claims).

~~~python
import jwt
claims = jwt.decode(token, key, algorithms=['HS256'], audience='service', options={'require': ['exp', 'sub', 'aud']})
~~~

**Проверка:** Неверная подпись, срок и назначение отвергаются; совместимость старых сессий проверена.

У известных `jose.jwt.decode` и `jwt.decode_complete` inline options могут быть
четвёртым позиционным аргументом:

~~~python
from jose import jwt
claims = jwt.decode(token, key, ['HS256'], {'verify_signature': False})
~~~

У обычного `jwt.decode` позиционный контракт неоднозначен без версии:
в PyJWT 1.7.1 третий аргумент — `verify`, четвёртый — `algorithms`, пятый —
`options`; в 2.10.1 algorithms/options занимают третью/четвёртую позиции.
Сканер не определяет установленный пакет или версию и не интерпретирует эти
позиции для общего `jwt.decode`.
[PyJWT 1.7.1](https://github.com/jpadilla/pyjwt/blob/1.7.1/jwt/api_jwt.py),
[PyJWT 2.10.1](https://github.com/jpadilla/pyjwt/blob/2.10.1/jwt/api_jwt.py).

`verify=False` не отключает проверку в PyJWT 2.x `decode_complete`;
в python-jose 3.5.0 у `decode` такого аргумента нет, вызов завершается TypeError.
Эти две формы не получают PY-JWT только за legacy-аргумент. У общего
`jwt.decode(..., verify=False)` сигнал остаётся версионной эвристикой для старого
API. Реальное `options={'verify_signature': False}` продолжает обнаруживаться.
[python-jose 3.5.0: decode](https://github.com/mpdavis/python-jose/blob/3.5.0/jose/jwt.py).

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'decode_complete|jwt[.]decode|from jose|from jwt|import jwt|PyJWT|python-jose|verify_signature|options=|requirements|poetry.lock|uv.lock' .
~~~

После совпадения установить импорт, реальную версию по lock-файлу/метаданным,
позиции аргументов, параметры экземпляра и место использования результата.
Непроверенное чтение claims для диагностики не должно становиться авторизацией.
`decode_complete` возвращает структуру с `payload`, а не только claims:
при правке сохранить контракт возврата. Ошибка парсинга или TypeError не должна
включать fallback, принимающий токен без проверки.

Семантика JWT в этих трёх разделах сверена по исходникам зафиксированных
версий; библиотеки JWT в этой проверке не запускались. Номера версий обозначают
проверенный API, а не рекомендацию устанавливать старую версию: для сервиса
сверить поддерживаемую версию, её исправления безопасности и контракт вызова.

<a id="py-archive"></a>

<a id="py-archive-archive-extraction-requires-path-review"></a>

## PY-ARCHIVE. Распаковка требует проверки путей

**Поиск:** скрипт, правило PY-ARCHIVE. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-ARCHIVE. AST: любой extractall остаётся эвристикой (включая ZIP); extract — только у известных tarfile.open/TarFile/TarFile.open через import aliases, конструктор, простое присваивание или with/as. shutil.unpack_archive — только с известным format tar/gztar/bztar/xztar/zstdtar, включая третий позиционный аргумент. filter='data' или tarfile.data_filter (также import alias/inline **dict) снимает сигнал, но не доказывает безопасность. Неизвестный/custom filter требует review; формат по расширению, extraction_filter, версия, квоты, wrappers и сложный поток управления проверяются вручную.

Сигнал при пропущенном `filter` требует просмотра версии и
`TarFile.extraction_filter`: начиная с Python 3.14 штатный default — `data`,
раньше он был эквивалентен `fully_trusted`. Переопределение на экземпляре,
классе или в подклассе меняет поведение. Даже безопасный default не подавляет
эвристику сканера. [tarfile: фильтры](https://docs.python.org/3/library/tarfile.html#extraction-filters).

**Уязвимый вариант:** недоверенный tar извлекается без ограничения путей,
типов членов и UNIX-метаданных.

~~~python
import tarfile
with tarfile.open(upload_path) as archive:
    archive.extract(member, destination, filter='fully_trusted')
~~~

**Исправление:** Для архива данных на исправленном runtime явно применить
`data` или `tarfile.data_filter`. Это предложение для распаковки в новый
закрытый от чужой записи каталог; лимиты диска, памяти, CPU и числа файлов
настраиваются отдельно. Без поддержки фильтра нужен совместимый обновлённый
runtime: небезопасный fallback не является исправлением.

~~~python
import tarfile
with tarfile.open(upload_path) as archive:
    archive.extract(member, new_destination, filter=tarfile.data_filter)
~~~

Для `shutil` правило рассматривает только явно выбранный встроенный tar-формат:

~~~python
import shutil
shutil.unpack_archive(upload_path, new_destination, format='gztar', filter='data')
~~~

`format='zip'` не получает этот сигнал; ZIP не принимает параметр `filter`.
Не переносить на ZIP приведённый патч. Формат из расширения, пользовательские
распаковщики и замена регистрации даже встроенного формата требуют просмотра
реальной функции. [shutil.unpack_archive](https://docs.python.org/3/library/shutil.html#shutil.unpack_archive).

`data_filter` ограничивает выход за каталог и опасные типы/метаданные, но может
разрешать внутренние ссылки. Он не даёт изоляцию от гонки с другим процессом,
меняющим каталог, и не ограничивает распаковочный объём. Операции с архивами,
которым нужны владельцы, права UNIX или специальные файлы, требуют отдельной
политики совместимости. После ошибки возможен частичный результат: его нельзя
объявлять завершённой загрузкой или публиковать; новый каталог упрощает очистку.
[PEP 706: назначение и ограничения](https://peps.python.org/pep-0706/).

Поддержка API ещё не означает наличие всех исправлений. Релизы от 1 октября
2026 — 3.10.22, 3.11.17, 3.12.15, 3.13.16 и 3.14.8 — включают исправления обходов
tar-фильтров; для дистрибутива проверить эквивалентные backports.
[Объявление Python](https://blog.python.org/2026/10/python-31022-31117/).

**Проверка:** На фактическом исправленном runtime проверить обычные файлы,
требуемые внутренние ссылки и метаданные; выход за корень, внешние ссылки,
специальные файлы, повторы имён и превышение квот — по принятой политике.
После отказа сервис не использует неполный результат. Проверить отдельно
Linux/macOS и используемую файловую систему, если на них развёрнут сервис.
Исчезновение PY-ARCHIVE не заменяет эти проверки.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'tarfile|extractall|[.]extract[(]|unpack_archive|register_unpack_format|extraction_filter|data_filter|errorlevel|FROM python|requires-python' .
~~~

После совпадения установить импорт/тип архива, источник входа, формат,
переопределённый фильтр, обработку ошибок и доступ к каталогу назначения.
Версию и backports сверить по образу/метаданным развёртывания без импорта
целевого проекта. Общий поиск `extractall` также отмечает ZIP и неизвестные
объекты: это повод проверить конкретный API, а не доказанный tar traversal.

<a id="py-temp"></a>

<a id="py-temp-non-atomic-temporary-filename"></a>

## PY-TEMP. Неатомарное имя временного файла

**Поиск:** скрипт, правило PY-TEMP. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-TEMP. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~python
import tempfile
name = tempfile.mktemp()
~~~

**Исправление:** TemporaryFile/NamedTemporaryFile/mkstemp: работать с уже открытым файлом.

~~~python
import tempfile
with tempfile.TemporaryFile() as output:
    output.write(data)
~~~

**Проверка:** Параллельные запросы получают разные временные файлы, не делят данные и не могут перезаписать существующий файл или ссылку.

<a id="py-xml"></a>

<a id="py-xml-xml-entity-resolution-enabled"></a>

## PY-XML. XML с разрешёнными сущностями

**Поиск:** скрипт, правило PY-XML. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-XML. AST: XMLParser по имени метода; lxml.etree.XMLPullParser/ETCompatXMLParser/iterparse — по разрешённому имени импорта, включая aliases. Сигнал только при известном resolve_entities=True, в том числе scalar переменная или inline **dict. Defaults, версия lxml, DTD, тип входа и wrappers проверяются вручную; сканер не определяет применимость CVE.

**Уязвимый вариант:**

~~~python
from lxml import etree
parser = etree.ETCompatXMLParser(resolve_entities=True)
~~~

**Исправление:** Если внешние сущности и DTD не нужны контракту, отключить
их загрузку и разрешение явно. `no_network=True` само по себе не запрещает
обращение к локальным файлам через сущности.

~~~python
from lxml import etree
parser = etree.ETCompatXMLParser(resolve_entities=False, load_dtd=False, no_network=True)
~~~

Те же параметры проверить у `XMLPullParser` и `iterparse`. Когда штатному
формату нужны внутренние сущности, для поддерживающей это версии рассмотреть
`resolve_entities='internal'` и проверить лимиты. `False` может изменить дерево
и текст документа; выбор режима должен сохранять нужные операции сервиса.

**Проверка:** Обычный XML и используемые внутренние сущности обрабатываются
по контракту; внешняя сущность с локальным URI и сетевым URI не раскрывает данные
и не вызывает обращения наружу. Проверить custom resolvers, последующую
обработку дерева и лимиты объёма/вложенности: создание парсера само по себе
не доказывает, что именно его передают всем точкам разбора.

Для вызовов без явной настройки и версионных defaults требуется ручная проверка:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'lxml|XMLParser|XMLPullParser|ETCompatXMLParser|iterparse|resolve_entities|requirements|poetry.lock|uv.lock' .
~~~

Сопоставить импорт, API и версию из lock-файла/метаданных развёртывания, затем
проследить путь недоверенного XML. В lxml до 6.1 `iterparse` и
`ETCompatXMLParser` по умолчанию разрешали внешние сущности и могли читать
локальные файлы; исправление 6.1.0 изменило default на `'internal'`.
Обновление не исправляет явное `resolve_entities=True`. Сканер ищет явную
опасную настройку и не устанавливает наличие CVE по версии.
[Advisory GHSA-vfmq-68hx-4jfw / CVE-2026-41066](https://github.com/lxml/lxml/security/advisories/GHSA-vfmq-68hx-4jfw).

<a id="py-weak-hash"></a>

<a id="py-weak-hash-md5sha1-review-the-purpose"></a>

## PY-WEAK-HASH. MD5/SHA1: проверить назначение

**Поиск:** скрипт, правило PY-WEAK-HASH. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-WEAK-HASH. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~python
import hashlib
digest = hashlib.md5(password)
~~~

**Исправление:** Пароли — password KDF, целостность с секретом — HMAC. Обычный checksum не обязательно требует изменения. Параметры KDF подобрать под нагрузку.

~~~python
import hashlib
digest = hashlib.scrypt(password, salt=salt, n=16384, r=8, p=1)
~~~

**Проверка:** Есть версия формата/миграция старых паролей; стоимость не нарушает SLA.

<a id="py-rng"></a>

<a id="py-rng-non-cryptographic-randomness-near-a-possible-secret"></a>

## PY-RNG. Обычный PRNG в возможном секрете

**Поиск:** скрипт, правило PY-RNG. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-RNG. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~python
import random
token = str(random.getrandbits(128))
~~~

**Исправление:** Для токенов и секретов использовать secrets или поддержанный криптографический генератор с достаточной энтропией; обрабатывать ошибки генератора. Публичную случайность отделить от секретов. Симуляция на random может быть корректной.

~~~python
import secrets
token = secrets.token_urlsafe(32)
~~~

**Проверка:** Нет предсказуемого резервного генератора; формат токена и сессии остаются совместимыми.

<a id="py-file"></a>

<a id="py-file-dynamic-file-serving-path"></a>

## PY-FILE. Динамический путь выдачи файла

**Поиск:** скрипт, правило PY-FILE. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-FILE. AST: send_file по имени метода, первый позиционный аргумент либо path_or_file=, включая import aliases и inline **dict. Нелитеральный путь даёт review и после безопасного поиска owned record; кастомный одноимённый метод может совпадать. Авторизацию, файловый корень, ссылки, wrappers и переменные dict проверить вручную.

**Уязвимый вариант:**

~~~python
from flask import send_file
result = send_file(path_or_file=user_path)
~~~

**Исправление:** Серверный путь по ID после проверки владельца; для имени — разрешённый корень и политика ссылок. Сигнал может остаться после исправления.

~~~python
from flask import send_file
record = load_owned_file(file_id, current_user.id)
result = send_file(path_or_file=record.storage_path)
~~~

**Проверка:** Чужой ID, выход из каталога и внешние symlinks отклоняются; собственные старые файлы доступны.

`path_or_file=` соответствует современному Flask API. `load_owned_file` в примере
обозначает обязательную реализованную проверку владельца и получение серверного
пути; одного переименования переменной недостаточно. Этот исправленный вызов
сохраняет PY-FILE, поскольку сканер не проверяет авторизацию, ссылки и гонку
подмены файла. Также проверить, что динамический аргумент не является уже
открытым доверенным файловым объектом: API допускает и такую штатную форму.
[Flask: send_file](https://flask.palletsprojects.com/en/stable/api/#flask.send_file).

<a id="py-url"></a>

<a id="py-url-dynamic-outbound-url"></a>

## PY-URL. Динамический исходящий URL

**Поиск:** скрипт, правило PY-URL. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-URL. AST: requests/httpx и urlopen; известные Session/session, requests.sessions.Session/session, Client/AsyncClient через import aliases, локальное присваивание или непосредственный конструктор. with/as поддержан для requests Session и httpx Client, async with/as — для httpx AsyncClient; факты присваиваний инвалидируются после области. request(method,url), httpx.stream и Client/AsyncClient.stream(method,url) используют второй аргумент либо url=. Литерал URL не сигналит; wrappers, возвращённые клиенты, mutable config и сложные связи вручную. Проверки URL/DNS/redirect не анализируются.

**Уязвимый вариант:**

~~~python
import requests
response = requests.get(user_url)
~~~

**Исправление:** Фиксированный разрешённый endpoint либо явная политика назначения, схемы и порта; проверка разрешённых DNS-адресов и каждого redirect; timeout и лимит ответа.

~~~python
import requests
response = requests.get('https://api.example.invalid/status', timeout=3, allow_redirects=False)
~~~

**Проверка:** Требуемые источники работают; запрещённые схемы/внутренние адреса/редиректы отвергаются приложением.

Переход к context API и потоковому чтению не меняет источник URL:

~~~python
import httpx
async def fetch(user_url):
    async with httpx.AsyncClient(timeout=3, follow_redirects=False) as client:
        async with client.stream('GET', user_url) as response:
            response.raise_for_status()
            # Bound response reads; the URL has not been authorized yet.
~~~

Исправление выбирается по контракту: фиксированный серверный endpoint, как
выше, или проверенный динамический адрес с политикой схемы, host, порта,
пути и redirect. Динамический URL из allowlist всё равно получает PY-URL:
сканер не доказывает качество этой проверки. Литерал URL не получает сигнал,
но его наличие не доказывает безопасность DNS, proxy или последующих redirect.

Потоковый ответ нужно закрывать и при превышении лимита, отмене операции и
ошибке чтения. `async with client.stream(...)` закрывает его при выходе;
в ручном streaming API нужен гарантированный `aclose()`. Для долгоживущего
сервиса сохранить жизненный цикл и переиспользование клиента, а не создавать
новый пул в каждой итерации. [HTTPX: async streaming](https://www.python-httpx.org/async/).

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'requests|httpx|urlopen|base_url|proxies|proxy=|trust_env|allow_redirects|follow_redirects|HTTP_PROXY|HTTPS_PROXY|NO_PROXY' .
~~~

После совпадения проследить вход до полного URL, соединить client/base_url,
proxy и настройки окружения. Проверить фактическое разрешение адреса и каждый
переход, доступ к внутренним адресам, перенос credentials между адресатами,
таймауты и лимит ответа. `timeout` отдельной операции не всегда ограничивает
всю цепочку. Объекты Request/PreparedRequest, возвращённые фабрикой клиенты,
переопределённые transports и межфункциональные связи требуют ручного анализа.
Эту проверку выполнять в разрешённом тестовом окружении; сканер сеть не использует.

**Вариант A/D:** Проверили hostname, но приняли клиентский URL целиком. **FAUST / quickr-maps, код.** Строка server вставляется в URL, проверяется
лишь hostname, затем URL передаётся requests. Возможные изменения path/query
остаются отдельной границей проверки.

**Патч:** клиент выбирает символическое имя из таблицы серверов; весь URL,
маршрут и owner строит сервер. **Тест:** разделители URL не меняют маршрут,
порт или субъект. **Поиск:** PY-URL, включая исправленное обнаружение url=.
Полная цепочка обхода здесь не воспроизводилась.

[исходник/разбор 1](https://github.com/fausecteam/faustctf-2024-quickr-maps/blob/fe77e8f1926117b788108f7614271f3133a1f607/location_portal/src/main.py); [исходник/разбор 2](https://github.com/fausecteam/faustctf-2024-quickr-maps/blob/fe77e8f1926117b788108f7614271f3133a1f607/private_loc/main.go).

<a id="py-crc"></a>

<a id="py-crc-crcadler-near-an-integrity-boundary"></a>

## PY-CRC. CRC/Adler как возможная защита целостности

**Поиск:** скрипт, правило PY-CRC. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-CRC. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~python
import zlib
tag = zlib.crc32(payload)
~~~

**Исправление:** Для аутентичности HMAC/подпись; для ID — уникальный серверный ключ и ownership. Обычный checksum может оставаться CRC.

~~~python
import hmac
tag = hmac.digest(key, payload, 'sha256')
~~~

**Проверка:** Изменённое сообщение без ключа не принимается; договорённость о формате и старые данные сохранены.

<a id="py-xpath"></a>

<a id="py-xpath-xpath-assembled-from-strings"></a>

## PY-XPATH. Строковая сборка XPath

**Поиск:** скрипт, правило PY-XPATH. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-XPATH. AST: xpath/XPath по имени метода и строковое выражение в первом аргументе, включая простое присваивание. Строковые литералы, их Add-конкатенация и f-строки без FormattedValue не сигналят; %, format и f-строки с подстановкой остаются review. Произвольные выражения не вычисляются; wrappers, переменные XPath и доверенность данных проверяются вручную.

**Уязвимый вариант:**

~~~python
node.xpath("//user[name='%s']" % username)
~~~

**Исправление:** Связать значение переменной XPath в поддержанном API; не собирать синтаксис кавычками. Само выражение должно быть фиксированным.

~~~python
node.xpath("//user[name=$name]", name=username)
~~~

**Проверка:** Кавычки/скобки — данные, область поиска и ownership не расширяются.

Фиксированное выражение, разделённое на литералы, не получает PY-XPATH:

~~~python
node.xpath("//" + "user")
node.xpath(f"//user")
~~~

Исключены только распознанные строки без подставляемых значений, их сложение
и f-строки без подстановок. Сканер не выполняет XPath и не вычисляет произвольные
Python-выражения. Переменные XPath связывают данные; названия осей, узлов и сам
текст выражения должны задаваться серверной политикой. Указать правильный API
для конкретной библиотеки: пример с `name=` относится к lxml.
[lxml: параметры XPath](https://lxml.de/xpathxslt.html#the-xpath-method).

<a id="py-uuid-bytes"></a>

<a id="py-uuid-bytes-uuid-bytesbytes_le-protocol-boundary"></a>

## PY-UUID-BYTES. Граница UUID bytes/bytes_le

**Поиск:** скрипт, правило PY-UUID-BYTES. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-UUID-BYTES. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~python
import uuid
value = uuid.UUID(bytes_le=wire_bytes)
~~~

**Исправление:** Согласовать wire-формат между всеми языками/кэшем/БД; canonical text либо документированный порядок 16 байт. Наличие bytes_le само по себе нормально.

~~~python
import uuid
value = uuid.UUID(wire_text)  # canonical text contract
~~~

**Проверка:** Одинаковые known vectors дают один UUID в обеих средах; round-trip и старые ссылки сохранены.

**Вариант A/D:** UUID меняет смысл между C# и Python. **RuCTF / hyperborea-legends, автор.** Разный порядок байтов UUID в кэше
и основном пути менял объект, к которому относились права.

**Патч:** один документированный wire-формат и преобразование на границе;
предпочтительно canonical text, если совместим с протоколом.
**Тест:** несимметричные known vectors, round-trip между языками и старые записи.
**Поиск:** PY-UUID-BYTES, CS-GUID-BYTES — только места для проверки.

[исходник/разбор 1](https://github.com/HackerDom/ructf-2023/blob/0cc333e44f2ba6908ff6c5d613146e3b00173315/writeups/hyperborea-legends/README.md).

<a id="py-assert-auth"></a>

<a id="py-assert-auth-access-control-using-assert"></a>

## PY-ASSERT-AUTH. Проверка доступа через assert

**Поиск:** скрипт, правило PY-ASSERT-AUTH. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-ASSERT-AUTH. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~python
assert note.owner_id == current_user.id
~~~

**Исправление:** Явная ветвь отказа, работающая при -O; не заменять обычные тестовые assert без причины.

~~~python
if note.owner_id != current_user.id:
    raise PermissionError('access denied')
~~~

**Проверка:** Чужой объект отклоняется и при обычном, и при оптимизированном запуске; своё действие работает.

<a id="py-django-hosts"></a>

<a id="py-django-hosts-django-wildcard-allowed_hosts"></a>

## PY-DJANGO-HOSTS. Любой host разрешён через ALLOWED_HOSTS Django

**Поиск:** скрипт, правило PY-DJANGO-HOSTS. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-DJANGO-HOSTS. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~python
ALLOWED_HOSTS = ["*"]
~~~

**Исправление:** Явные фактические имена/IP из контракта, включая checker. get_host вместо сырого Host; доверенные proxy-заголовки отдельно.

~~~python
ALLOWED_HOSTS = ["service.internal"]
~~~

**Проверка:** Неизвестный Host отвергается; штатный host/checker работает.

**Основание:** [первичный материал](https://docs.djangoproject.com/en/5.2/ref/settings/#allowed-hosts).

<a id="py-html-safe"></a>

<a id="py-html-safe-html-escaping-explicitly-bypassed"></a>

## PY-HTML-SAFE. Явное отключение HTML-экранирования

**Поиск:** скрипт, правило PY-HTML-SAFE. Запуск: из DurkaHelper — python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-HTML-SAFE. Это синтаксический сигнал, не проверка потока данных: проследить вход, валидацию и все вызовы найденного API.

**Уязвимый вариант:**

~~~python
html = mark_safe(message)
~~~

**Исправление:** Передавать данные в autoescaped шаблон; для разрешённого HTML sanitizer по контракту. HTML escaping не защищает JS/URL-контекст.

~~~python
html = message
~~~

**Проверка:** Кавычки и теги остаются текстом; штатное форматирование не потеряно.

**Основание:** [первичный материал](https://docs.djangoproject.com/en/5.2/topics/security/).

<a id="py-mass-assign"></a>

<a id="py-mass-assign-request-fields-become-model-attributes"></a>

## PY-MASS-ASSIGN. Поля запроса становятся атрибутами модели

**Поиск:** скрипт, правило PY-MASS-ASSIGN. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-MASS-ASSIGN. AST: setattr с нелитеральным именем атрибута. **kwargs, setattr-wrapper, ORM update и конструкторы автоматически не покрыты; оставить ручной поиск ниже.

Дополнительный ручной поиск для непокрытых форм:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'setattr|__dict__|model_validate|update\(|request.json' .
~~~

Проследить список полей до ORM; найти owner/role/tenant и вложенные DTO.

**Уязвимый вариант:**

setattr(model, key, value) в цикле по клиентскому JSON применяет служебные поля.

**Исправление:** Явный DTO разрешённых полей; запрет лишних полей по контракту, проверка типов во время выполнения, owner из сессии.

**Проверка:** Частичный update работает; owner, role, вложенный объект и null не меняют права.


**Сигнал сканера — пример до:**

~~~python
for field, value in payload.items():
    setattr(account, field, value)
~~~

**Шаблон исправления:**

~~~python
account.display_name = validate_display_name(payload['display_name'])
~~~

<a id="py-decorator-auth"></a>

<a id="py-decorator-auth-a-route-is-registered-before-the-authorization-wrapper"></a>

## PY-DECORATOR-AUTH. Маршрут зарегистрирован до auth-декоратора

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e '@.*route|@.*get|@.*post|login_required|permission_required' .
~~~

Развернуть порядок применения декораторов и посмотреть функцию, реально сохранённую в router.

**Уязвимый вариант:**

Auth оборачивает локальное имя, но router уже хранит необёрнутую функцию.

**Исправление:** Поставить auth внутрь route-регистрации либо использовать штатную dependency/policy фреймворка; проверить каждый HTTP-метод.

**Проверка:** Запрос без сессии через реальный router отклоняется; прямой unit-вызов сам по себе недостаточен.

<a id="py-async-context"></a>

<a id="py-async-context-global-current_user-leaks-across-async-requests"></a>

## PY-ASYNC-CONTEXT. Глобальный current_user между async-запросами

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'global|current_user|ContextVar|threading.local|asyncio' .
~~~

Найти записи principal и await между записью и использованием; проверить reset ContextVar в finally.

**Уязвимый вариант:**

Общая переменная или thread-local обслуживает несколько coroutine одного потока.

**Исправление:** Request-scoped объект/ContextVar с восстановлением токена; заданиям передавать явный проверенный контекст.

**Проверка:** Два запроса с barrier и разные пользователи; исключение не оставляет чужой контекст.

<a id="py-redirect"></a>

<a id="py-redirect-dynamic-redirect-destination"></a>

## PY-REDIRECT. Открытый redirect и доверие next

**Поиск:** скрипт, правило PY-REDIRECT. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-REDIRECT. AST: flask.redirect/werkzeug.utils.redirect с первым позиционным аргументом либо location=; django.shortcuts.redirect — с первым аргументом либо to=. Поддержаны import aliases и inline **dict; литерал или известное простое scalar значение не сигналит. Анализ доверия, wrappers, runtime kwargs, разрешения маршрутов и reverse-proxy redirects вручную.

Дополнительный ручной поиск для непокрытых форм:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'redirect\(|next|return_url|urljoin' .
~~~

Проследить построение Location: относительный путь не должен превращаться в network-path URL или иной origin.

**Уязвимый вариант:**

redirect(request.args["next"]) выбирает внешний адрес; проверка startswith("/") недостаточна.

**Исправление:** Разрешённые внутренние маршруты/серверная карта, либо полноценный разбор origin и нормализация один раз.

**Проверка:** Штатный переход работает; абсолютный URL, двойной slash, backslash и кодированные разделители отклоняются.


**Сигнал сканера — пример до:**

~~~python
from flask import redirect
return_url = request.args['next']
response = redirect(return_url)
~~~

**Шаблон исправления:**

~~~python
from flask import redirect
response = redirect('/profile')
~~~

Первичная документация: [документация 1](https://docs.djangoproject.com/en/5.2/ref/utils/#django.utils.http.url_has_allowed_host_and_scheme).

Именованные аргументы не меняют границу доверия:

~~~python
from flask import redirect
response = redirect(location=request.args['next'])
~~~

~~~python
from django.shortcuts import redirect
response = redirect(to=request.GET['next'])
~~~

У Flask/Werkzeug это `location=`, у Django — `to=`. Django также принимает имя
view и объект с `get_absolute_url()`: проверить смысл цели и итоговый Location,
а не считать каждую динамическую цель внешним URL. При фиксированном маршруте
можно использовать `redirect(location='/profile')` во Flask или
`redirect(to='profile')` в Django, если такой именованный маршрут определён.
Сохранить требуемые параметры и поведение метода/status; навязанная замена
всех переходов одним маршрутом меняет контракт сервиса.
[Flask: redirect](https://flask.palletsprojects.com/en/stable/api/#flask.redirect),
[Django 5.2: redirect](https://docs.djangoproject.com/en/5.2/topics/http/shortcuts/#redirect).

Динамическая цель после полноценной проверки остаётся сигналом. Сканер
не воспроизводит URLconf, `get_absolute_url`, нормализацию браузера или
effective Host/proxy; эти связи проверяются вручную на штатных переходах.

<a id="py-password-hash"></a>

<a id="py-password-hash-fast-digests-used-for-password-storage"></a>

## PY-PASSWORD-HASH. Быстрый digest вместо хранения пароля

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'password|hashlib|sha256|md5|pbkdf2' .
~~~

Найти регистрацию и login; сравнить salt, work factor, формат хранимой записи и ветвь миграции.

**Уязвимый вариант:**

sha256(password) без адаптивной стоимости позволяет быстро проверять догадки по утёкшей БД.

**Исправление:** Поддержанный password hasher фреймворка/Argon2id или подходящий KDF; соль и параметры в записи, обновление после успешного входа.

**Проверка:** Старый пользователь входит и мигрирует; неверный пароль не перезаписывает hash, длинный ввод ограничен.

<a id="py-zip-limits"></a>

<a id="py-zip-limits-archive-traversal-symlinks-and-expanded-volume"></a>

## PY-ZIP-LIMITS. Архив: traversal, symlink и распаковочный объём

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'zipfile|tarfile|extractall|extract\(' .
~~~

Помимо PY-ARCHIVE проверить список entries, фактический объём и filesystem boundary; фильтр путей не ограничивает объём.

**Уязвимый вариант:**

Архив пишет вне root либо исчерпывает диск при допустимом размере сжатого файла.

**Исправление:** Отдельный каталог, проверка каждого пути/типа/ссылки, лимиты числа entries и реально распакованных байтов; атомарная публикация результата.

**Проверка:** Обычный архив, абсолютный путь, ссылка наружу, множество entries, ошибка посередине и уборка временных данных.

**Основание:** [первичный материал](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).

<a id="py-json-duplicates"></a>

<a id="py-json-duplicates-parsers-disagree-on-repeated-keys"></a>

## PY-JSON-DUPLICATES. Разные парсеры выбирают разные повторные ключи

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'json.loads|object_pairs_hook|orjson|signature|canonical' .
~~~

Сравнить парсер подписи, API и downstream: first/last duplicate, числа и нормализация ключей.

**Уязвимый вариант:**

Подпись проверяет одну интерпретацию owner, операция использует другую.

**Исправление:** Единый канонический DTO до подписи и после чтения; явная политика дублей/чисел, reject неоднозначных документов.

**Проверка:** Повторный owner, разный порядок, Unicode и большие числа дают одинаковый смысл или явный отказ.

<a id="py-cache-key"></a>

<a id="py-cache-key-authorization-cache-key-collisions"></a>

## PY-CACHE-KEY. Коллизии ключей кэша авторизации

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'cache|memoize|lru_cache' .
~~~

Сравнить полный ключ для двух пользователей и двух аргументов с одинаковым префиксом; найти усечение и инвалидацию.

**Уязвимый вариант:**

**Основание:** hermicache, авторский разбор RuCTF. Общий кэш строил строковый
ключ из функции и аргументов с усечением до 90 символов.

**Искать:** конкатенация без однозначных границ, prefix/slice ключа, отсутствие
user/tenant/версии прав, совместное хранение публичных результатов и auth.

**Исправление:** сериализовать полный типизированный кортеж, включить нужный контекст.
Успех проверки пароля не кэшировать общим ключом. Сохранить необходимый для SLA
вычислительный кэш. Пример принципа:

~~~python
# before: cache[(function + str(arguments))[:90]]
# after: no truncation, no ambiguous concatenation
key = json.dumps([function, tenant_id, user_id, arguments],
                 separators=(",", ":"), ensure_ascii=False)
~~~

**Проверка:** две разные пары аргументов с одинаковым префиксом; разные пользователи;
смена прав/пароля; штатные повторные вычисления.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/hermicache/README.md).

**Основание:** [первичный материал](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/hermicache/README.md).

<a id="py-jwt-dependency"></a>

<a id="py-jwt-dependency-vulnerable-jwt-verification-dependencies"></a>

## PY-JWT-DEPENDENCY. Уязвимая зависимость проверки JWT

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'python-jwt|PyJWT|jwt|requirements|lock' .
~~~

Сопоставить distribution, lock, vendored-копию и реально загружаемую версию; python-jwt и PyJWT различаются.

**Уязвимый вариант:**

**Основание:** deutsches-flugzeug, авторский обзор saarCTF; advisory python-jwt
CVE-2022-39227. Ошибка находилась в зависимости, даже если вызов выглядел штатно.
**Искать:** точное имя distribution, lock/version, реально импортируемый модуль
и vendored-копии, несовпадение lock с образом.

**Исправление:** исправленная совместимая версия с заранее подготовленными локальными
пакетами/образом; один lockfile не меняет уже запущенный контейнер.

**Проверка:** подпись, все claims, срок, неверный ключ, обычная сессия и подтверждённый
регрессионный случай. Порог исправления именно этого CVE — 3.3.4 у python-jwt;
это не PyJWT и не рекомендация закрепить старую версию навсегда.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/saarsec/saarctf-2024/blob/3a06d18974ca177c6dd251a11bdf9b4b334f382a/deutsches-flugzeug/overview.md).

**Основание:** [первичный материал](https://github.com/saarsec/saarctf-2024/blob/3a06d18974ca177c6dd251a11bdf9b4b334f382a/deutsches-flugzeug/overview.md).

<a id="py-challenge-state"></a>

<a id="py-challenge-state-challenge-disclosure-before-commitment"></a>

## PY-CHALLENGE-STATE. Challenge раскрывается до фиксации commitment

**Поиск:** вручную; отдельного правила сканера нет.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'chall|comm|resp|init_get|finish_get' .
~~~

Построить init/finish state machine; повторный init не должен менять commitment при уже известном challenge.

**Уязвимый вариант:**

**ECSC / fonograph, автор.** Шаги протокола использовали неправильно обновляемый
challenge.

**Исправление:** свежий challenge после commitment, привязка к сессии/объекту,
атомарное однократное потребление.

**Проверка:** повторный init, перестановка
и повтор finish, параллельные сессии, штатный обмен.

**Вариант A/D:** Основание и версия: [исходник/разбор 1](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/fonograph/README.md); [исходник/разбор 2](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/fonograph/backend/db.py); [исходник/разбор 3](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/fonograph/backend/handlers.py).

**Основание:** [первичный материал](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/fonograph/README.md).

<a id="py-ssl-context"></a>

<a id="py-ssl-context-tls-context-verification-disabled"></a>

## PY-SSL-CONTEXT. Отключённая проверка TLS-контекста

**Поиск:** скрипт, правило PY-SSL-CONTEXT. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-SSL-CONTEXT. AST: ssl._create_unverified_context(), присваивания verify_mode=ssl.CERT_NONE и check_hostname=False; aliases импортов поддержаны. Тип объекта присваивания не устанавливается.

**Уязвимый вариант:** В клиентском TLS-контексте `CERT_NONE`, отключённая
проверка hostname или непроверяющий контекст могут позволить принять чужой сервер.

~~~python
import ssl
context = ssl._create_unverified_context()
~~~

**Исправление:** Для клиента создать проверяющий контекст; для внутреннего CA
передать доверенный CA и проверять ожидаемое имя сервера.

~~~python
import ssl
context = ssl.create_default_context(cafile=trusted_ca_file)
~~~

**Проверка:** Доверенный сервер доступен; сертификат чужого имени, просроченный и неизвестного CA отвергаются.

У сервера без mTLS `CERT_NONE` означает, что сертификат клиента не запрашивается:
это штатная конфигурация, если контракт не требует клиентских сертификатов.
`check_hostname` также относится к проверке удалённого сервера клиентом.
Сканер роль и фактический тип объекта не различает, поэтому такой сигнал требует
просмотра; не включать обязательный mTLS только ради его устранения.
[Python ssl.CERT_NONE](https://docs.python.org/3/library/ssl.html#ssl.CERT_NONE).

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'PROTOCOL_TLS_CLIENT|PROTOCOL_TLS_SERVER|create_default_context|CERT_NONE|check_hostname|server_side|server_hostname' .
~~~

После совпадения связать создание контекста с местом его использования,
проверить роль `server_side`, назначение `create_default_context` и требование
сертификата клиента. При исправлении серверной конфигурации проверить прежних
клиентов и согласованный механизм аутентификации.

<a id="py-csrf-exempt"></a>

<a id="py-csrf-exempt-django-view-excluded-from-csrf"></a>

## PY-CSRF-EXEMPT. Исключение Django view из CSRF

**Поиск:** скрипт, правило PY-CSRF-EXEMPT. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-CSRF-EXEMPT. AST: декоратор или вызов django.views.decorators.csrf.csrf_exempt, включая import alias. Наличие исключения ещё не доказывает дефект bearer-only endpoint.

**Уязвимый вариант:** Cookie-аутентифицированная операция изменения состояния без CSRF-проверки принимает чужой браузерный запрос.

~~~python
from django.views.decorators.csrf import csrf_exempt
@csrf_exempt
def update(request):
    return change_profile(request)
~~~

**Исправление:** Для cookie flow вернуть CSRF middleware/decorator и токен в клиенте. Для webhook или bearer API отдельно проверить подпись/auth и отсутствие cookie fallback.

~~~python
from django.views.decorators.csrf import csrf_protect
@csrf_protect
def update(request):
    return change_profile(request)
~~~

**Проверка:** Штатный запрос с токеном проходит; POST без/с чужим CSRF-токеном отклонён; разрешённый webhook продолжает работать.

Первичная документация: [документация 1](https://docs.djangoproject.com/en/5.2/ref/csrf/).

<a id="py-jwt-algorithms"></a>

<a id="py-jwt-algorithms-jwt-algorithms-taken-from-an-expression"></a>

## PY-JWT-ALGORITHMS. Алгоритм JWT берётся из выражения

**Поиск:** скрипт, правило PY-JWT-ALGORITHMS. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-JWT-ALGORITHMS. AST: algorithms вне inline списка/кортежа строк; у точного jose.jwt.decode строковый литерал или известный scalar string также не сигналит. Только jose.jwt.decode и jwt.decode_complete используют третий позиционный аргумент; generic jwt.decode — лишь keyword. Явный None даёт review; отсутствие аргумента, *args, mutable config, версия и происхождение allowlist проверяются вручную. Явные positional/keyword дубликаты algorithms/options не анализируются как исполнимый JWT-вызов.

**Уязвимый вариант:** Недоверенный alg не должен выбирать допустимый криптографический алгоритм проверки.

~~~python
import jwt
claims = jwt.decode(token, key, algorithms=[header['alg']])
~~~

**Исправление:** Связать разрешённый алгоритм с доверенной конфигурацией ключа; не смешивать HMAC и RSA для одного материала ключа.

~~~python
import jwt
claims = jwt.decode(token, key, algorithms=['RS256'], audience='notes', issuer='auth')
~~~

**Проверка:** Правильный токен принимается, другой alg/key type и подпись отвергаются; проверить issuer/audience/срок.

Первичная документация: [документация 1](https://pyjwt.readthedocs.io/en/stable/api.html).

В известном python-jose 3.5.0 фиксированная строка `algorithms='HS256'`
допустима и не получает сигнал; список `['HS256']` тоже подходит. Это не
разрешение выбирать алгоритм из заголовка токена. Явный `algorithms=None`
остаётся поводом для просмотра: его смысл зависит от библиотеки и типа ключа,
а отсутствие аргумента сканер не считает проверкой допустимого списка.
[python-jose 3.5.0](https://github.com/mpdavis/python-jose/blob/3.5.0/jose/jwt.py),
[PyJWT 2.10.1: algorithms и PyJWK](https://pyjwt.readthedocs.io/en/2.10.1/api.html).

Доверенная переменная со списком алгоритмов может сохранить PY-JWT-ALGORITHMS;
проследить её до конфигурации ключа. Для позиционных вызовов сначала сверить
импорт и версию по методике [PY-JWT](#py-jwt). Отсутствие сигнала не проверяет
криптографическую пригодность ключа, его происхождение и разделение назначений.

<a id="py-jwt-claims"></a>

<a id="py-jwt-claims-jwt-expiry-or-recipient-checks-disabled"></a>

## PY-JWT-CLAIMS. Проверки срока и адресата JWT отключены

**Поиск:** скрипт, правило PY-JWT-CLAIMS. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-JWT-CLAIMS. AST: inline options с verify_exp/verify_nbf/verify_aud/verify_iss=False, включая scalar bool и inline dict spreads. Только jose.jwt.decode и jwt.decode_complete учитывают четвёртый позиционный options. Только у jose.jwt.decode require_X=True снимает сигнал для соответствующего verify_X=False; другие claims и подпись не подавляются. Внешние dict, *args, явные дубликаты аргументов, настройки экземпляра, версии и обязательность claims проверить вручную.

**Уязвимый вариант:** Верная подпись не делает просроченный токен или токен другого приложения допустимым.

~~~python
import jwt
claims = jwt.decode(token, key, algorithms=['HS256'], options={'verify_exp': False})
~~~

**Исправление:** Проверять срок, issuer, audience и обязательные claims согласно
контракту. В PyJWT 2.x `require` — список присутствующих полей; он не включает
обратно отключённый `verify_exp`/`verify_aud`/другую проверку значения.
Пример для PyJWT 2.x с обычными включёнными проверками:

~~~python
import jwt
claims = jwt.decode(token, key, algorithms=['HS256'], audience='notes', issuer='auth', options={'require': ['exp', 'sub', 'iss', 'aud']})
~~~

**Проверка:** Истёкший, преждевременный, без обязательных полей и для другого приложения токены отклоняются; штатные сессии работают с выбранной библиотекой и форматом возвращаемого результата.

Первичная документация: [PyJWT 2.10.1: require и verify](https://pyjwt.readthedocs.io/en/2.10.1/api.html).

У python-jose 3.5.0 применяются отдельные `require_*`:

~~~python
from jose import jwt
claims = jwt.decode(
    token, key, algorithms=['HS256'], audience='notes', issuer='auth',
    options={'require_exp': True, 'require_sub': True,
             'require_aud': True, 'require_iss': True},
)
~~~

В этой библиотеке `require_exp=True` требует поле и восстанавливает
соответствующий `verify_exp`. Поэтому известное сочетание
`verify_exp=False, require_exp=True` не получает PY-JWT-CLAIMS; требование
другого поля не подавляет отключённую проверку. Эта семантика не переносится
на PyJWT `require=[...]`. `require_signature` не восстанавливает проверку
подписи: она происходит раньше проверки claims.
[python-jose 3.5.0: проверка claims](https://github.com/mpdavis/python-jose/blob/3.5.0/jose/jwt.py).

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'verify_exp|verify_nbf|verify_aud|verify_iss|require_|require["\x27]|PyJWT[(]|options|decode_complete' .
~~~

Просмотреть настройки экземпляра, сборку options, overrides и версию API;
словари-переменные и обязательность отсутствующих claims автоматикой не
доказываются. Сверить `iss`/`aud` с принимающим сервисом, затем проверить старые
легитимные токены и новые отрицательные случаи. Добавление обязательного поля
может нарушить старые сессии: согласовать выдачу/миграцию до ужесточения приёма.

<a id="py-regex-dynamic"></a>

<a id="py-regex-dynamic-dynamic-regular-expression-pattern"></a>

## PY-REGEX-DYNAMIC. Динамический шаблон регулярного выражения

**Поиск:** скрипт, правило PY-REGEX-DYNAMIC. Запуск: python3 -I -S scripts/defense_scan.py /path/to/service --patches; подробности — --explain PY-REGEX-DYNAMIC. AST: re.compile/match/search/fullmatch/findall/finditer/split/sub/subn с нелитеральным первым аргументом. Не измеряет сложность regex; безопасный re.escape остаётся сигналом.

**Уязвимый вариант:** Пользовательский regex меняет семантику поиска и может вызвать чрезмерный backtracking.

~~~python
import re
found = re.search(request_pattern, text)
~~~

**Исправление:** Для буквального поиска использовать escape или строковую операцию; для regex-функции ограничить грамматику, длины и бюджет исполнения подходящим движком.

~~~python
import re
found = re.search(re.escape(search_text), bounded_text)
~~~

**Проверка:** Метасимволы в буквальном запросе трактуются буквально; длинный почти совпавший текст не блокирует обработчик.

Сигнал может остаться после правильного патча: правило не доказывает соблюдение указанного инварианта.

Первичная документация: [документация 1](https://docs.python.org/3/library/re.html#re.escape).

<a id="py-auth-decorator"></a>

<a id="py-auth-decorator-flask-route-registers-before-login-protection"></a>

## PY-AUTH-DECORATOR. Маршрут Flask регистрируется до защиты login_required

**Поиск:** правило сканера PY-AUTH-DECORATOR. Подробности: `--explain PY-AUTH-DECORATOR`. AST: импортированный flask_login.login_required выше route/get/post/put/patch/delete у известного Flask/Blueprint. Учитываются aliases и последовательные переприсваивания. Пользовательские декораторы, фабрики, динамические маршруты и другие способы регистрации требуют ручной проверки. Проверяйте зарегистрированный HTTP endpoint, а не только прямой вызов функции.

**Уязвимый вариант:**

~~~python
from flask import Flask
from flask_login import login_required
app = Flask(__name__)
@login_required
@app.route('/private')
def private():
    return 'private'
~~~

**Исправление:** Поместите известный декоратор маршрута Flask снаружи login_required; проверяйте авторизацию через зарегистрированный endpoint, а не только прямым вызовом функции.

~~~python
from flask import Flask
from flask_login import login_required
app = Flask(__name__)
@app.route('/private')
@login_required
def private():
    return 'private'
~~~

**Проверка:** Анонимный запрос через реальный маршрут должен отклоняться; аутентифицированные запросы и поведение checker должны сохраниться.

[Первичный источник 1](https://flask.palletsprojects.com/en/stable/patterns/viewdecorators/)

<a id="py-log-credentials"></a>

<a id="py-log-credentials-credential-like-value-passed-directly-to-logging"></a>

## PY-LOG-CREDENTIALS. Значение, похожее на credential, напрямую передаётся в logging

**Поиск:** правило сканера PY-LOG-CREDENTIALS. Подробности: `--explain PY-LOG-CREDENTIALS`. AST: известные logging/getLogger или Flask app.logger с прямыми чувствительными именами, атрибутами, индексами, значениями dict/list или простым форматированием. Имена: password/passwd/secret/token/access_token/refresh_token/api_key/authorization. Helper calls, logging kwargs, wrappers и другие имена не отслеживаются; отсутствие сигнала на redact() не подтверждает очистку.

**Уязвимый вариант:**

~~~python
import logging
logging.warning('authentication failed: %s', password)
~~~

**Исправление:** Записывайте стабильные категории событий и согласованные идентификаторы; не записывайте значения credentials и заголовки Authorization. Проверяйте неудачный вход и обработку исключений.

~~~python
import logging
logging.warning('authentication failed')
~~~

**Проверка:** Тестовые canary-credentials не должны появляться в stdout, логах, evidence или трансляции; полезная диагностика ошибок должна сохраниться.

[Первичный источник 1](https://docs.python.org/3/library/logging.html)
