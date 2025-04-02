Перечень сервисов:
1. nuclear - C
2. medok - Python

---

## [0x01] Scores and Status codes

Sploits:
- 101 OK: The host is vulnerable
- 102 NO: The host is not vulnerable 
- 110 SPLOIT ERROR: Internal error in sploit

Checkers:
- 101 OK: The service works correctly
- 104 DOWN: The service doesn't work
- 110 CHECKER ERROR: Internal error in checker

---

## [0x02] Service 1: nuclear

Система SCADA `nuclear` предназначена для взаимодействия с ядерным реактором в городе X-State, разработана компанией Atech SCADA. Она предназначена для автоматизации контроля и управления технологическими процессами на сложных промышленных объектах, включая ядерные реакторы. У властей города после проведения очередной комиссии по безопасности возникли сомнения по части информационной безопасности системы, начиная с документов до наличия некоторых уязвимостей. Для хакеров нет ничего невозможного. Кто-то из членов комиссии слил информацию об уязвимостях...

### Vuln 1: Overflow

`gets` - в функции `authenticate_user` - при вводе пароля используется уязвимая функция `gets()`.

### Patch for Vuln 1

Задача патча - используя IDA PRO (или любой другой инструмент для патча бинарей) изменить эту функцию на `fgets`.

---

### Vuln 2: Adjust Control Rods

`scanf` - в функции `adjust_control_rods` используется следующая конструкция:

```C
int position;

scanf("%lf", &position);
```

### Patch for Vuln 2

Для патча необходимо изменить `%lf` на `%d`

---

### Vuln 3: Wrong Admin Validation

В функции `main` при вводе команде `add_user` в условии присутствует лишнее `false`, в следствие чего проверка на роль `admin` работает некорректно

```C
if (!check_permissions(&current_user, "admin") && false) continue;
```

### Patch for Vuln 3

Для патча необходимо из условия убрать `false`.

---

## [0x03] Service 2: medok

**МедОК** — это инновационный медицинский сервис, который делает обращение за медицинской помощью быстрым, удобным и доступным. Мы стремимся упростить процесс взаимодействия с врачами,чтобы вы могли сосредоточиться на самом главном — своём здоровье. У очередной госкомиссии возник вопрос: "А стремятся ли они обеспечить безопасность?"

### Vuln 1: SSTI in registration

Сервис **medok** наделен уязвимостью SSTI (Server-Side Template Injection) в функции регистрации (**main.route('/register)**) файла **routes.py**, которая позволяет реализовать удаленное исполнение кода (RCE):

```python
message = """Пользователь %s успешно зарегистрирован.
<meta http-equiv="refresh" content="0;url={{ url_for('main.profile') }}"> """
return render_template_string(message % name)
```

Уязвимость обеспечивает функция render_template_string(), в которую производится передача данных без фильтрации. Таким образом при отправке следующего payload в функцию можно выполнить произвольный код:

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

![ScreenShot](screenshots/medok-1.png)

![ScreenShot](screenshots/medok-2.png)

### Patch for Vuln 1

Для закрытия уязвимости можно использовать функцию redirect(), не выводя сообщение об успешной регистрации пользователя:

```python
# Безопасный редирект в профиль

return redirect(url_for('main.profile'))
```

Таким образом, в шаблон функция не передает ничего, а информация о пользователе подтягивается автоматически. В итоге, профиль доступен, а уязвимость закрыта:

![ScreenShot](screenshots/medok-3.png)

---

### Vuln 2: SQLi in doctors' search

Данная уязвимость происходит в скрипте **utils.py**, функции **get_doctors_from_db()** при составлении запроса к БД. Как видно из кода, пользовательский ввод передается в зарос напрямую, без фильтрации:

```python
query = f"""
    SELECT * FROM doctors
    WHERE LOWER(full_name) LIKE '%{search_query.lower()}%'
"""
cursor.execute(query)
```

Уязвимый участок кода может быть использован для выгрузки информации из других таблиц, в частности таблицы users:

```SQL
%' UNION SELECT 1, 2, username, 3, email, password from users -- -
```

![ScreenShot](screenshots/medok-4.png)

### Patch for Vuln 2

Для закрытия уязвимости необходимо обеспечить достаточный уровень фильтрации пользовательского ввода. Сделать это можно следующим способом:

```python
if search_query:
    # Безопасная передача переменной в SQL-запрос
    query = f"""
        SELECT * FROM doctors
        WHERE LOWER(full_name) LIKE %s
    """
    cursor.execute(query, (f"%{search_query.lower()}%",))
```

В таком случае запрос к БД не вернет ничего:

![ScreenShot](screenshots/medok-5.png)

---

### Vuln 3: RCE in services ticket creation

Уязвимость происходит в функции **create_ticket()** файла **utils.py**. Для записи в файл используется функция **os.system()** с применением утилиты **echo**, что является небезопасным и одназчно приводит к удаленному исполнению кода: 

```python
os.system(f'echo "Заявка №{ticket_number}\n\nВаше имя: {name}\n\nВаш номер телефона: {phone}\n\nОставленное сообщение: {message}" > {ticket_filename}')
```

Пример экспулатации уязвимости:

![ScreenShot](screenshots/medok-6.png)

![ScreenShot](screenshots/medok-7.png)

```bash
$(cat /etc/passwd)
```

### Patch for Vuln 3

Уязвимость можно закрыть стандартными методами python3, а именно записью в файл с помощью функции **open(*filename*, 'w')**, что не будет интерпретировано непосредственно самой оболочкой, а обеспечит безопасную запись в файл:

```python
# Отказ от os.system() в пользу open() для предотвращения RCE
ticket_content = (
    f"Заявка №{ticket_number}\n\n"
    f"Ваше имя: {name}\n\n"
    f"Ваш номер телефона: {phone}\n\n"
    f"Оставленное сообщение: {message}"
)

with open(ticket_filename, 'w', encoding='utf-8') as ticket_file:
    ticket_file.write(ticket_content)
```

Таким образом попытка выполнить вредоносный код на стороне сервера будет предотвращена, а в файл запишется отправленный текст:

![ScreenShot](screenshots/medok-8.png)

---

### Vuln 4: IDOR in appointments

У пользователя **admin** уже имеется запись к врачу:

![ScreenShot](screenshots/medok-9.png)

Для реализации уязвимости можно создать другого пользователя (**test**):

![ScreenShot](screenshots/medok-10.png)

В таком случае можно реализовать уязвимость **IDOR** с помощью перебора интуитивно предсказуемых значений в роуте **@main.route('/view_appointment/<int:user_id>/<int:appointment_id>')**:

```python
@main.route('/view_appointment/<int:user_id>/<int:appointment_id>')
def view_appointment(user_id, appointment_id):
    appointment = get_appointment_details(user_id, appointment_id)
    return render_template('view_appointment.html', appointment=appointment)
```

При выборе значений **user_id=1** и **appointment_id=1** мы получим доступ к той самой записи на прием пользователя **admin**:

![ScreenShot](screenshots/medok-11.png)

### Patch for Vuln 4

Чтобы избежать этой уязвимости, необходимо лишь обеспечить проверку подлинности (проверять, действительно ли пользователь имеет доступ к запрашиваемой информации). Для этого можно использовать сохраненный в **session** параметр **user_id** при регистрации, а также при входе. Безопасная функция в таком случае будет иметь следующий вид:

```python
@main.route('/view_appointment/<int:user_id>/<int:appointment_id>')
def view_appointment(user_id, appointment_id):
    appointment = get_appointment_details(user_id, appointment_id)

    # Проверка user_id сессии; отсутствие вывода, если user_id не совпал
    if session.get('user_id') != user_id: appointment = None
    return render_template('view_appointment.html', appointment=appointment)
```

И теперь, при попытке несанкционированного доступа к чужой записи на прием, не будет выводиться никакой информации:

![ScreenShot](screenshots/medok-12.png)

---
