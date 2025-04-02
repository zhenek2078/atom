# Если HTTPS - Wireshark:

Сначала нужно найти приватный ключ сервера (пример, где может быть):

**Апачи и Nginx - искать в конфигах путь до ключей:**

```
/etc/apache2/sites-available/*.conf

/etc/nginx/sites-available/*.conf
```

**Flask - смотрим в app.py - в main при запуске Flask, передается путь до ключа**

**В докере:**

```
docker exec -it <container_id> ls -l /etc/ssl/private/
```

**Нашли ключ - добавляем в Wireshark:**

```
Edit → Preferences → Protocols → TLS, добавить ключ в раздел RSA Keys List
```

# Если HTTP - Packmate:

```
git clone https://gitlab.com/packmate/starter.git packmate-starter && cd packmate-starter
```

**Изменить настройки в файле .env:**

```
# Локальный IP сервера, на который приходит игровой трафик
PACKMATE_LOCAL_IP=10.20.1.1

# Имя пользователя для web-авторизации
PACKMATE_WEB_LOGIN=SomeUser

# Пароль для web-авторизации
PACKMATE_WEB_PASSWORD=SomeSecurePassword

# Интерфейс, на который поступает трафик
PACKMATE_INTERFACE=ens19
```

**Запускаем:**

```
sudo docker compose up -d
```

**Переходим в браузере: localhost:65000, выбираем порт, на котором крутится сервис**

# Фикс уязв на Python:

## SSTI:

**Библиотеки:**

```
from jinja2 import Environment, select_autoescape
env = Environment(autoescape=select_autoescape(['html', 'xml']))
template = env.from_string("Hello, {{ user }}!")
output = template.render(user="SafeUser")
```

**Без библиотек:**

```
from flask import Flask, render_template_string
app = Flask(__name__)
@app.route('/unsafe')
def unsafe():
    user_input = "Hello {{ 7*7 }}"  # Ввод от пользователя
    return render_template_string(user_input)  # Уязвимость!
@app.route('/safe')
def safe():
    user_input = "Hello User"
    return render_template_string("{{ user }}", user=user_input)  # Безопасно
```

## SQL:

**Библиотеки:**

```
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
@app.route('/user/<name>')
def get_user(name):
    user = User.query.filter_by(username=name).first()  # Безопасно
    return f"User: {user.username}" if user else "Not found"
```

**Без библиотек:**

```
import sqlite3
conn = sqlite3.connect('database.db')
cursor = conn.cursor()
@app.route('/user/<name>')
def get_user_safe(name):
    cursor.execute("SELECT * FROM users WHERE username = ?", (name,))
    user = cursor.fetchone()
    return f"User: {user}" if user else "Not found"
```

## XSS:

**Библиотеки:**

```
from flask import render_template
@app.route('/safe')
def safe():
    user_input = "<script>alert('XSS')</script>"
    return render_template("index.html", user=user_input)  # Jinja2 экранирует ввод
```

**Без библиотек:**

```
import html
@app.route('/manual_escape')
def manual_escape():
    user_input = "<script>alert('XSS')</script>"
    safe_input = html.escape(user_input)  # Преобразует в безопасную строку
    return f"User input: {safe_input}"
```

## CSRF:

**Библиотеки:**

```
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
```

**Без библиотек:**

```
import secrets
from flask import request, session
@app.route('/form', methods=['GET', 'POST'])
def form():
    if request.method == 'POST':
        token = request.form.get('csrf_token')
        if token != session.get('csrf_token'):
            return "CSRF detected!", 403

    session['csrf_token'] = secrets.token_hex(16)
    return f'''
        <form method="post">
            <input type="hidden" name="csrf_token" value="{session['csrf_token']}">
            <input type="submit">
        </form>
    '''
```

## Open redirect:

**Библиотеки:**

```
from werkzeug.urls import url_parse
from flask import request, redirect, url_for
@app.route('/redirect')
def safe_redirect():
    next_url = request.args.get('next')
    if not next_url or url_parse(next_url).netloc != "":
        return redirect(url_for('index'))  # Перенаправляем только внутри сайта
    return redirect(next_url)
```

**Без библиотек:**

```
@app.route('/redirect')
def safe_redirect_manual():
    next_url = request.args.get('next')
    allowed_urls = ["/home", "/profile"]
    if next_url not in allowed_urls:
        return redirect("/home")
    return redirect(next_url)
```

## Path travel:

**Библиотеки:**

```
from werkzeug.security import safe_join
import os
@app.route('/file/<filename>')
def safe_file(filename):
    safe_path = safe_join('/safe_directory', filename)
    if not os.path.exists(safe_path):
        return "File not found", 404
    with open(safe_path, 'r') as file:
        return file.read()
```

**Без библиотек:**

```
@app.route('/file/<path:filename>')
def safe_file_manual(filename):
    if ".." in filename or filename.startswith("/"):
        return "Invalid filename", 400
    safe_path = f"/safe_directory/{filename}"
    return open(safe_path, 'r').read() if os.path.exists(safe_path) else "File not found"
```

## Headre injection:

**Библиотеки:**

```
from flask_talisman import Talisman
Talisman(app, content_security_policy=None)  # Запрещает вредоносные заголовки
```

**Без библиотек:**

```
@app.route('/set_header')
def set_header():
    user_input = request.args.get('header', '')
    if '\n' in user_input or '\r' in user_input:
        return "Invalid header", 400
    response = flask.Response("Header Set")
    response.headers['Custom-Header'] = user_input
    return response
```

## XXE:

**Библиотеки:**

```
from defusedxml.lxml import parse
@app.route('/xml', methods=['POST'])
def parse_xml():
    xml_data = request.data
    tree = parse(xml_data)  # Безопасный парсер
    return "Parsed successfully"
```

**Без библиотек:**

```
from lxml import etree
parser = etree.XMLParser(resolve_entities=False)  # Отключаем внешние сущности
```
