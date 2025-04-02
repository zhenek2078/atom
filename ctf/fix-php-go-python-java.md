# Python

## 1. Server-Side Template Injection (SSTI)

```
from flask import Flask, render_template_string, request

app = Flask(__name__)

@app.route("/safe")
def safe():
    user_input = request.args.get("name", "")
    return render_template_string("Hello, {{ name }}", name=user_input)  # Safe
```

✅ Используем параметризированные данные, без eval в шаблонах.

## 2. SQL Injection (SQLi)

```
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # Safe
    result = cur.fetchall()
    conn.close()
    return str(result)
```

✅ Используем подготовленные запросы.

## 3. Cross-Site Scripting (XSS)

```
import html
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/safe-xss")
def safe_xss():
    user_input = html.escape(request.args.get("input", ""))
    return render_template_string("Hello, {{ name }}", name=user_input)  # Safe
```

✅ Экранируем ввод с html.escape().

## 4. CSRF

```
from flask_wtf.csrf import CSRFProtect
from flask import Flask

app = Flask(__name__)
app.config["SECRET_KEY"] = "supersecretkey"
csrf = CSRFProtect(app)

@app.route("/form", methods=["POST"])
def submit_form():
    return "Form submitted safely!"
```

✅ Используем Flask-WTF для защиты.

## 5. Open Redirect

```
from flask import Flask, request, redirect

app = Flask(__name__)

@app.route("/redirect")
def safe_redirect():
    target = request.args.get("url", "")
    if target.startswith("https://trusted.com"):
        return redirect(target)
    return "Invalid redirect URL", 400
```

✅ Проверяем URL перед редиректом.

## 6. Path Traversal

```
import os
from flask import Flask, request

app = Flask(__name__)

@app.route("/file")
def get_file():
    filename = os.path.basename(request.args.get("file", ""))
    safe_path = os.path.join("/safe_directory", filename)
    with open(safe_path, "r") as f:
        return f.read()
```

✅ Используем os.path.basename().

## 7. Header Injection

```
from flask import Flask, request, Response

app = Flask(__name__)

@app.route("/safe-header")
def safe_header():
    value = request.args.get("input", "")
    safe_value = value.replace("\n", "").replace("\r", "")  # Remove newlines
    response = Response("Safe Header")
    response.headers["X-Custom-Header"] = safe_value
    return response
```

✅ Удаляем переводы строк.

## 8. XML External Entity (XXE)

```
from lxml import etree

parser = etree.XMLParser(resolve_entities=False)
xml_data = "<root></root>"
etree.fromstring(xml_data, parser=parser)
```

✅ Запрещаем обработку внешних сущностей.

# PHP

## 1. SSTI

PHP-шаблоны (Twig, Blade) не выполняют код по умолчанию, поэтому SSTI неактуальна.

## 2. SQLi

```
$conn = new PDO("mysql:host=localhost;dbname=test", "user", "pass");
$stmt = $conn->prepare("SELECT * FROM users WHERE id = :id");
$stmt->bindParam(":id", $_GET["id"], PDO::PARAM_INT);
$stmt->execute();
$result = $stmt->fetchAll();
```

✅ Используем подготовленные запросы.

## 3. XSS

```
echo htmlspecialchars($_GET["name"], ENT_QUOTES, "UTF-8");
```

✅ Экранируем ввод.

## 4. CSRF

```
session_start();
$token = bin2hex(random_bytes(32));
$_SESSION["csrf_token"] = $token;

if ($_POST["csrf_token"] !== $_SESSION["csrf_token"]) {
    die("CSRF detected!");
}
```

✅ Используем CSRF-токены.

## 5. Open Redirect

```
$allowed_hosts = ["trusted.com"];
$url = parse_url($_GET["url"]);
if (in_array($url["host"], $allowed_hosts)) {
    header("Location: " . $_GET["url"]);
} else {
    die("Invalid URL");
}
```

✅ Фильтруем host.

## 6. Path Traversal

```
$filename = basename($_GET["file"]);
$safe_path = "/safe_directory/" . $filename;
$content = file_get_contents($safe_path);
echo $content;
```

✅ Используем basename().

## 7. Header Injection

```
$input = str_replace(["\r", "\n"], "", $_GET["input"]);
header("X-Safe-Header: " . $input);
```

✅ Фильтруем переводы строк.

## 8. XXE

```
$xml = new DOMDocument();
$xml->loadXML($data, LIBXML_NOENT | LIBXML_DTDLOAD);
```

✅ Отключаем LIBXML_NOENT.

# Go

## 1. SQLi

```
db.QueryRow("SELECT * FROM users WHERE id = ?", userID)
```

✅ Используем ?.

## 2. XSS

```
import "html"
html.EscapeString(input)
```

✅ Экранируем ввод.

## 3. CSRF

Используем библиотеку gorilla/csrf.

## 4. Open Redirect

```
if !strings.HasPrefix(url, "https://trusted.com") {
    return errors.New("invalid redirect")
}
```

✅ Проверяем URL.

## 5. Path Traversal

```
import "path/filepath"
safePath := filepath.Clean(userPath)
```

✅ Используем filepath.Clean().

# Java

## 1. SQLi

```
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userID);
stmt.executeQuery();
```

✅ Используем PreparedStatement.

## 2. XSS

```
import org.apache.commons.text.StringEscapeUtils;
StringEscapeUtils.escapeHtml4(input);
```

✅ Экранируем ввод.

## 3. CSRF

Используем Spring Security CSRF protection.

## 4. Open Redirect

```
if (!url.startsWith("https://trusted.com")) {
    throw new IllegalArgumentException("Invalid URL");
}
```

✅ Проверяем URL.

## 5. Path Traversal

```
import java.nio.file.Paths;
Paths.get("/safe_dir", filename).normalize();
```

✅ Используем normalize().
