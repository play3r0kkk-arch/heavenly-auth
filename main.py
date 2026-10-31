from fastapi import FastAPI, HTTPException, Header

from fastapi.middleware.cors import CORSMiddleware

from fastapi.responses import HTMLResponse, Response, FileResponse

from pydantic import BaseModel

from datetime import datetime, timedelta

import secrets

import os

import database



app = FastAPI(

    title="Heavenly Client Auth API",

    description="Облачная система авторизации, привязки HWID и подписок для лоадера Heavenly 1.21.11",

    version="1.0.0"

)



app.add_middleware(

    CORSMiddleware,

    allow_origins=["*"],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],

)



# Инициализируем базу данных

database.init_db()



# Активные сессии в памяти: token -> user_dict

sessions = {}



# Модели запросов

class LoginRequest(BaseModel):

    username: str

    password: str

    hwid: str = ""



class RegisterRequest(BaseModel):

    username: str

    password: str

    key: str

    hwid: str = ""



class ActivateRequest(BaseModel):

    username: str

    key: str



class CreateKeyRequest(BaseModel):

    days: int

    prefix: str = "HV"



class ResetHwidRequest(BaseModel):

    username: str



class BanUserRequest(BaseModel):

    username: str

    banned: bool



class DeleteUserRequest(BaseModel):

    username: str



class ChangePasswordRequest(BaseModel):

    username: str

    new_password: str



class SetSubRequest(BaseModel):

    username: str

    days: int



class DeleteKeyRequest(BaseModel):

    key: str



class SetUidRequest(BaseModel):

    username: str

    new_uid: int



class SetClientUrlRequest(BaseModel):

    download_url: str



@app.get("/api/client/download")
def download_client():
    jar_file = os.path.join(os.path.dirname(__file__), "HeavenlyClient.jar")
    if os.path.exists(jar_file):
        return FileResponse(jar_file, media_type="application/java-archive", filename="HeavenlyClient.jar")
    return Response(content="Client binary not found", status_code=404)

@app.get("/api/client/config")

def get_client_config():

    url = database.get_setting("client_download_url", "")

    version = database.get_setting("client_version", "1.0.0")

    return {

        "status": "ok",

        "download_url": url,

        "version": version

    }



@app.get("/api/client/manifest")

def get_client_manifest():

    manifest_file = os.path.join(os.path.dirname(__file__), "version_manifest.json")

    if os.path.exists(manifest_file):

        with open(manifest_file, "r", encoding="utf-8") as f:

            return Response(content=f.read(), media_type="application/json")

    return {"status": "error", "message": "Manifest template not found"}



@app.post("/api/admin/set_client_url")

def set_client_url(req: SetClientUrlRequest):

    url = req.download_url.strip()

    if "drive.google.com" in url:

        m = re.search(r'/d/([a-zA-Z0-9_-]+)', url)

        if m:

            url = f"https://drive.google.com/uc?export=download&id={m.group(1)}"

        else:

            m = re.search(r'[?&]id=([a-zA-Z0-9_-]+)', url)

            if m:

                url = f"https://drive.google.com/uc?export=download&id={m.group(1)}"

    elif "dropbox.com" in url:

        url = url.replace("?dl=0", "?dl=1")

        if "?dl=" not in url:

            url += "?dl=1"

    database.set_setting("client_download_url", url)

    return {"status": "ok", "message": "Ссылка на клиент успешно сохранена!", "download_url": url}



@app.get("/")

def root():

    return {

        "status": "online",

        "service": "Heavenly Client Auth System",

        "version": "1.21.11",

        "docs": "/docs"

    }



@app.post("/api/login")

def login(req: LoginRequest):

    username = req.username.strip()

    password = req.password

    hwid = req.hwid.strip()



    if not username or not password:

        return {"status": "error", "message": "Заполните логин и пароль"}



    conn = database.get_db()

    cursor = conn.cursor()



    cursor.execute("SELECT id, username, password_hash, hwid, sub_until, role, is_banned FROM users WHERE LOWER(username) = LOWER(?)", (username,))

    user = cursor.fetchone()



    if not user:

        conn.close()

        return {"status": "error", "message": "Пользователь не найден"}



    if user["is_banned"] == 1:

        conn.close()

        return {"status": "error", "message": "Ваш аккаунт заблокирован создателем!"}



    # Проверка пароля

    expected_hash = database.hash_password(password)

    if user["password_hash"] != expected_hash:

        conn.close()

        return {"status": "error", "message": "Неверный пароль"}



    # Проверка и привязка HWID

    user_hwid = user["hwid"]

    if not user_hwid and hwid:

        # Первая авторизация — привязываем HWID

        cursor.execute("UPDATE users SET hwid = ? WHERE id = ?", (hwid, user["id"]))

        conn.commit()

    elif user_hwid and hwid and user_hwid != hwid:

        if user["role"] == "Owner":

            # Владелец (Owner) может входить с любого устройства — HWID обновляется автоматически

            cursor.execute("UPDATE users SET hwid = ? WHERE id = ?", (hwid, user["id"]))

            conn.commit()

        else:

            conn.close()

            return {"status": "error", "message": "HWID не совпадает! Обратитесь к создателю для сброса"}



    # Проверка подписки

    sub_until = user["sub_until"]

    sub_active = False

    days_left = 0



    if sub_until == "LIFETIME":

        sub_active = True

        days_left = 9999

    elif sub_until:

        try:

            exp_date = datetime.strptime(sub_until, "%Y-%m-%d")

            now = datetime.now()

            if exp_date >= now:

                sub_active = True

                days_left = (exp_date - now).days + 1

        except Exception:

            pass



    if not sub_active:

        conn.close()

        return {"status": "error", "message": "Ваша подписка истекла!"}



    conn.close()



    # Генерация токена сессии

    token = secrets.token_hex(24)

    sessions[token] = {

        "uid": user["id"],

        "username": user["username"],

        "role": user["role"]

    }



    return {

        "status": "success",

        "message": "Успешная авторизация",

        "uid": user["id"],

        "username": user["username"],

        "role": user["role"],

        "sub_active": True,

        "sub_until": sub_until,

        "sub_days_left": days_left,

        "token": token

    }



@app.post("/api/register")

def register(req: RegisterRequest):

    username = req.username.strip()

    password = req.password

    key_str = req.key.strip()

    hwid = req.hwid.strip()



    if not username or not password or not key_str:

        return {"status": "error", "message": "Заполните логин, пароль и ключ регистрации"}



    conn = database.get_db()

    cursor = conn.cursor()



    # Проверка занятости логина

    cursor.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", (username,))

    if cursor.fetchone():

        conn.close()

        return {"status": "error", "message": "Пользователь с таким логином уже существует"}



    # Проверка ключа

    cursor.execute("SELECT days, is_used FROM activation_keys WHERE key = ?", (key_str,))

    key_row = cursor.fetchone()

    if not key_row:

        conn.close()

        return {"status": "error", "message": "Неверный ключ активации"}

    if key_row["is_used"] == 1:

        conn.close()

        return {"status": "error", "message": "Этот ключ уже был использован"}



    days = key_row["days"]

    if days >= 9999:

        sub_until = "LIFETIME"

    else:

        exp = datetime.now() + timedelta(days=days)

        sub_until = exp.strftime("%Y-%m-%d")



    cursor.execute("""

    INSERT INTO users (username, password_hash, hwid, sub_until, role)

    VALUES (?, ?, ?, ?, 'User')

    """, (username, database.hash_password(password), hwid, sub_until))



    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))

    u_row = cursor.fetchone()

    new_uid = u_row["id"] if u_row else (cursor.lastrowid or 1)

    cursor.execute("UPDATE activation_keys SET is_used = 1, used_by = ? WHERE key = ?", (username, key_str))

    conn.commit()

    conn.close()



    return {

        "status": "success",

        "message": "Пользователь успешно зарегистрирован",

        "uid": new_uid,

        "username": username,

        "sub_until": sub_until

    }



@app.post("/api/activate")

def activate_key(req: ActivateRequest):

    username = req.username.strip()

    key_str = req.key.strip()



    conn = database.get_db()

    cursor = conn.cursor()



    cursor.execute("SELECT id, sub_until FROM users WHERE LOWER(username) = LOWER(?)", (username,))

    user = cursor.fetchone()

    if not user:

        conn.close()

        return {"status": "error", "message": "Пользователь не найден"}



    cursor.execute("SELECT days, is_used FROM activation_keys WHERE key = ?", (key_str,))

    key_row = cursor.fetchone()

    if not key_row or key_row["is_used"] == 1:

        conn.close()

        return {"status": "error", "message": "Недействительный или уже использованный ключ"}



    days = key_row["days"]

    current_sub = user["sub_until"]



    if days >= 9999 or current_sub == "LIFETIME":

        new_sub = "LIFETIME"

    else:

        try:

            curr_date = datetime.strptime(current_sub, "%Y-%m-%d")

            base = max(datetime.now(), curr_date)

        except Exception:

            base = datetime.now()

        new_sub = (base + timedelta(days=days)).strftime("%Y-%m-%d")



    cursor.execute("UPDATE users SET sub_until = ? WHERE id = ?", (new_sub, user["id"]))

    cursor.execute("UPDATE activation_keys SET is_used = 1, used_by = ? WHERE key = ?", (username, key_str))

    conn.commit()

    conn.close()



    return {

        "status": "success",

        "message": "Подписка успешно продлена",

        "sub_until": new_sub

    }



@app.post("/api/admin/create_key")

def create_key(req: CreateKeyRequest):

    key_rand = secrets.token_hex(4).upper()

    key_rand2 = secrets.token_hex(4).upper()

    new_key = f"{req.prefix}-{key_rand}-{key_rand2}"



    conn = database.get_db()

    cursor = conn.cursor()

    cursor.execute("INSERT INTO activation_keys (key, days) VALUES (?, ?)", (new_key, req.days))

    conn.commit()

    conn.close()



    return {"status": "success", "key": new_key, "days": req.days}



@app.post("/api/admin/reset_hwid")

def reset_hwid(req: ResetHwidRequest):

    conn = database.get_db()

    cursor = conn.cursor()

    cursor.execute("UPDATE users SET hwid = '' WHERE LOWER(username) = LOWER(?)", (req.username.strip(),))

    rows = cursor.rowcount

    conn.commit()

    conn.close()



    if rows > 0:

        return {"status": "success", "message": f"HWID для пользователя {req.username} успешно сброшен"}

    return {"status": "error", "message": "Пользователь не найден"}



@app.post("/api/admin/ban_user")

def ban_user(req: BanUserRequest):

    username = req.username.strip()

    if username.lower() == "heavenlyowner":

        return {"status": "error", "message": "Нельзя заблокировать аккаунт Создателя!"}



    conn = database.get_db()

    cursor = conn.cursor()

    cursor.execute("UPDATE users SET is_banned = ? WHERE LOWER(username) = LOWER(?)", (1 if req.banned else 0, username))

    rows = cursor.rowcount

    conn.commit()

    conn.close()



    if rows > 0:

        act = "заблокирован" if req.banned else "разблокирован"

        return {"status": "success", "message": f"Пользователь {username} успешно {act}"}

    return {"status": "error", "message": "Пользователь не найден"}



@app.post("/api/admin/delete_user")

def delete_user(req: DeleteUserRequest):

    username = req.username.strip()

    if username.lower() == "heavenlyowner":

        return {"status": "error", "message": "Нельзя удалить аккаунт Создателя!"}



    conn = database.get_db()

    cursor = conn.cursor()

    cursor.execute("DELETE FROM users WHERE LOWER(username) = LOWER(?)", (username,))

    rows = cursor.rowcount

    conn.commit()

    conn.close()



    if rows > 0:

        return {"status": "success", "message": f"Пользователь {username} навсегда удален из базы"}

    return {"status": "error", "message": "Пользователь не найден"}



@app.post("/api/admin/change_password")

def change_password(req: ChangePasswordRequest):

    username = req.username.strip()

    new_pass = req.new_password.strip()

    if not new_pass:

        return {"status": "error", "message": "Пароль не может быть пустым"}



    conn = database.get_db()

    cursor = conn.cursor()

    cursor.execute("UPDATE users SET password_hash = ? WHERE LOWER(username) = LOWER(?)", (database.hash_password(new_pass), username))

    rows = cursor.rowcount

    conn.commit()

    conn.close()



    if rows > 0:

        return {"status": "success", "message": f"Пароль для {username} успешно изменен"}

    return {"status": "error", "message": "Пользователь не найден"}



@app.post("/api/admin/set_sub")

def set_sub(req: SetSubRequest):

    username = req.username.strip()

    conn = database.get_db()

    cursor = conn.cursor()



    cursor.execute("SELECT id, sub_until FROM users WHERE LOWER(username) = LOWER(?)", (username,))

    user = cursor.fetchone()

    if not user:

        conn.close()

        return {"status": "error", "message": "Пользователь не найден"}



    if req.days >= 9999:

        new_sub = "LIFETIME"

    else:

        current_sub = user["sub_until"]

        try:

            curr_date = datetime.strptime(current_sub, "%Y-%m-%d")

            base = max(datetime.now(), curr_date)

        except Exception:

            base = datetime.now()

        new_sub = (base + timedelta(days=req.days)).strftime("%Y-%m-%d")



    cursor.execute("UPDATE users SET sub_until = ? WHERE id = ?", (new_sub, user["id"]))

    conn.commit()

    conn.close()



    return {"status": "success", "message": f"Подписка для {username} обновлена до: {new_sub}", "sub_until": new_sub}



@app.get("/api/admin/users")

def get_users():

    conn = database.get_db()

    cursor = conn.cursor()

    cursor.execute("SELECT id, username, hwid, sub_until, role, is_banned, created_at FROM users ORDER BY id ASC")

    rows = cursor.fetchall()

    conn.close()

    return [dict(r) for r in rows]



@app.get("/api/admin/keys")

def get_keys():

    conn = database.get_db()

    cursor = conn.cursor()

    cursor.execute("SELECT key, days, is_used, used_by, created_at FROM activation_keys ORDER BY created_at DESC")

    rows = cursor.fetchall()

    conn.close()

    return [dict(r) for r in rows]



@app.post("/api/admin/delete_key")

def delete_key(req: DeleteKeyRequest):

    key_str = req.key.strip()

    conn = database.get_db()

    cursor = conn.cursor()

    cursor.execute("DELETE FROM activation_keys WHERE key = ?", (key_str,))

    rows = cursor.rowcount

    conn.commit()

    conn.close()



    if rows > 0:

        return {"status": "success", "message": f"Ключ {key_str} успешно удален"}

    return {"status": "error", "message": "Ключ не найден"}



@app.post("/api/admin/set_uid")

def set_uid(req: SetUidRequest):

    username = req.username.strip()

    if username.lower() != "heavenlyowner":

        return {"status": "error", "message": "Кастомный UID разрешен ТОЛЬКО для HeavenlyOwner!"}



    new_uid = req.new_uid

    if new_uid < 0:

        return {"status": "error", "message": "UID не может быть отрицательным числом!"}



    conn = database.get_db()

    cursor = conn.cursor()



    cursor.execute("SELECT username FROM users WHERE id = ? AND LOWER(username) != 'heavenlyowner'", (new_uid,))

    conflict = cursor.fetchone()

    if conflict:

        conn.close()

        return {"status": "error", "message": f"UID #{new_uid} уже занят пользователем {conflict['username']}!"}



    cursor.execute("UPDATE users SET id = ? WHERE LOWER(username) = 'heavenlyowner'", (new_uid,))

    conn.commit()

    conn.close()



    return {"status": "success", "message": f"Кастомный UID #{new_uid} успешно установлен для HeavenlyOwner!", "uid": new_uid}



@app.get("/admin", response_class=HTMLResponse)

@app.get("/", response_class=HTMLResponse)

def admin_page():

    return """<!DOCTYPE html>

<html lang="ru">

<head>

    <meta charset="UTF-8">

    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Heavenly • Панель Управления</title>

    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">

    <style>

        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', -apple-system, sans-serif; }

        body { background: #0e0e12; color: #f5f5fa; min-height: 100vh; padding: 28px 20px; }

        .container { max-width: 1100px; margin: 0 auto; }

        header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 28px; padding-bottom: 20px; border-bottom: 1px solid #23232d; }

        .brand { display: flex; align-items: center; gap: 14px; }

        .logo { width: 44px; height: 44px; background: linear-gradient(135deg, #8a4bff, #6225e6); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 22px; color: #fff; box-shadow: 0 4px 16px rgba(138, 75, 255, 0.4); }

        .title h1 { font-size: 20px; font-weight: 700; letter-spacing: 0.5px; }

        .title p { font-size: 13px; color: #88889c; }

        .status-badge { display: inline-flex; align-items: center; gap: 8px; background: #172a1e; border: 1px solid #2b593a; color: #52e185; padding: 6px 14px; border-radius: 20px; font-size: 13px; font-weight: 600; }

        .dot { width: 8px; height: 8px; background: #52e185; border-radius: 50%; box-shadow: 0 0 8px #52e185; }

        

        .grid-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 26px; }

        .stat-card { background: #16161c; border: 1px solid #272733; border-radius: 14px; padding: 18px 20px; }

        .stat-card .label { font-size: 13px; color: #88889c; margin-bottom: 8px; font-weight: 500; }

        .stat-card .value { font-size: 26px; font-weight: 700; color: #ffffff; }



        .card { background: #16161c; border: 1px solid #272733; border-radius: 14px; padding: 22px; margin-bottom: 26px; }

        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; }

        .card-title { font-size: 16px; font-weight: 700; color: #f5f5fa; display: flex; align-items: center; gap: 8px; }

        

        /* Generator */

        .gen-form { display: flex; gap: 12px; flex-wrap: wrap; }

        select, input { background: #1e1e26; border: 1px solid #363647; color: #fff; padding: 10px 14px; border-radius: 10px; font-size: 14px; outline: none; }

        select:focus, input:focus { border-color: #8a4bff; }

        .btn { background: linear-gradient(135deg, #8a4bff, #6225e6); color: #fff; border: none; padding: 10px 20px; border-radius: 10px; font-weight: 600; cursor: pointer; transition: all 0.2s; font-size: 14px; }

        .btn:hover { filter: brightness(1.15); transform: translateY(-1px); }

        .btn-sm { padding: 6px 12px; font-size: 12px; border-radius: 8px; }

        .btn-danger { background: #e03b3b; color: #fff; border: none; }

        .btn-danger:hover { background: #ff4747; }

        .btn-copy { background: #272736; border: 1px solid #3e3e52; color: #a4a4c2; }

        .btn-copy:hover { color: #fff; border-color: #8a4bff; }



        /* Tables */

        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }

        th { color: #88889c; font-weight: 600; font-size: 12px; text-transform: uppercase; padding: 12px 14px; border-bottom: 1px solid #272733; letter-spacing: 0.5px; }

        td { padding: 14px; border-bottom: 1px solid #1f1f2a; color: #e1e1ec; }

        tr:hover td { background: #1a1a22; }

        .tag { display: inline-block; padding: 4px 10px; border-radius: 8px; font-size: 12px; font-weight: 600; }

        .tag-owner { background: rgba(138, 75, 255, 0.2); color: #ab7eff; border: 1px solid rgba(138, 75, 255, 0.4); }

        .tag-user { background: rgba(100, 110, 140, 0.2); color: #a0a8be; border: 1px solid rgba(100, 110, 140, 0.3); }

        .tag-free { background: rgba(82, 225, 133, 0.15); color: #52e185; border: 1px solid rgba(82, 225, 133, 0.3); }

        .tag-used { background: rgba(220, 60, 60, 0.15); color: #ff6e6e; border: 1px solid rgba(220, 60, 60, 0.3); }

        .key-text { font-family: monospace; font-size: 13.5px; color: #c4b5fd; font-weight: 600; background: #20202c; padding: 4px 8px; border-radius: 6px; }

        

        .alert-box { margin-top: 14px; padding: 12px 16px; border-radius: 10px; background: rgba(138, 75, 255, 0.15); border: 1px solid #8a4bff; display: none; align-items: center; justify-content: space-between; }

        .actions-wrap { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }

        .btn-action { background: #22222d; border: 1px solid #36364a; color: #cfcfe2; padding: 5px 9px; font-size: 12px; border-radius: 7px; cursor: pointer; transition: 0.15s; }

        .btn-action:hover { border-color: #8a4bff; color: #fff; background: #2c2c3b; }

        .btn-ban { background: rgba(220, 50, 50, 0.15); border: 1px solid rgba(220, 50, 50, 0.4); color: #ff6e6e; padding: 5px 9px; font-size: 12px; border-radius: 7px; cursor: pointer; transition: 0.15s; }

        .btn-ban:hover { background: #dc3232; color: #fff; }

        .btn-unban { background: rgba(82, 225, 133, 0.15); border: 1px solid rgba(82, 225, 133, 0.4); color: #52e185; padding: 5px 9px; font-size: 12px; border-radius: 7px; cursor: pointer; transition: 0.15s; }

        .btn-unban:hover { background: #52e185; color: #000; }

        .btn-del { background: rgba(180, 30, 30, 0.15); border: 1px solid rgba(180, 30, 30, 0.35); color: #ff7777; padding: 5px 8px; font-size: 12px; border-radius: 7px; cursor: pointer; transition: 0.15s; }

        .btn-del:hover { background: #e02424; color: #fff; }

    </style>

</head>

<body>

    <div class="container">

        <header>

            <div class="brand">

                <div class="logo">H</div>

                <div class="title">

                    <h1>Heavenly • Панель Управления</h1>

                    <p>База данных клиентов, генератор подписок и HWID</p>

                </div>

            </div>

            <div class="status-badge">

                <span class="dot"></span> Сервер работает (API Online)

            </div>

        </header>



        <div class="grid-stats">

            <div class="stat-card">

                <div class="label">Всего пользователей (UID)</div>

                <div class="value" id="statUsers">-</div>

            </div>

            <div class="stat-card">

                <div class="label">Всего лицензионных ключей</div>

                <div class="value" id="statKeys">-</div>

            </div>

            <div class="stat-card">

                <div class="label">Свободных ключей</div>

                <div class="value" id="statFreeKeys" style="color:#52e185;">-</div>

            </div>

        </div>



        <!-- Генератор ключей -->

        <div class="card">

            <div class="card-header">

                <div class="card-title">⚡ Генератор новых ключей подписки</div>

            </div>

            <div class="gen-form">

                <select id="keyDays">

                    <option value="7">7 Дней (Trial)</option>

                    <option value="30" selected>30 Дней (Стандарт 1 месяц)</option>

                    <option value="90">90 Дней (Сезон 3 месяца)</option>

                    <option value="9999">Навсегда (LIFETIME)</option>

                </select>

                <input type="text" id="keyPrefix" value="HV" placeholder="Префикс (HV)" style="width: 110px;">

                <button class="btn" onclick="generateKey()">+ Сгенерировать ключ</button>

            </div>

            <div class="alert-box" id="newKeyAlert">

                <div>Новый ключ создан: <span class="key-text" id="newKeyText"></span></div>

                <button class="btn btn-sm btn-copy" onclick="copyNewKey()">Скопировать</button>

            </div>

        </div>



        <!-- Облачное автоскачивание клиента -->

        <div class="card">

            <div class="card-header">

                <div class="card-title">📦 Облачное автоскачивание клиента (Option A)</div>

            </div>

            <div style="font-size: 13px; color: #8e8ea0; margin-bottom: 12px; line-height: 1.5;">

                Укажи прямую ссылку на скачивание <code>HeavenlyClient.jar</code> (например, GitHub Release, Catbox, Google Диск или другой хостинг). Когда другой игрок нажимает <b>«ЗАПУСТИТЬ КЛИЕНТ»</b>, лоадер сам скачает и установит чит!

            </div>

            <div class="gen-form">

                <input type="text" id="clientDownloadUrl" placeholder="https://github.com/.../releases/download/.../HeavenlyClient.jar" style="flex: 1;">

                <button class="btn" onclick="saveClientDownloadUrl()">💾 Сохранить ссылку</button>

            </div>

            <div id="clientUrlStatus" style="font-size: 13px; margin-top: 10px; color: #52e185; display: none;"></div>

        </div>



        <!-- Таблица пользователей -->

        <div class="card">

            <div class="card-header">

                <div class="card-title">👥 Зарегистрированные пользователи</div>

                <button class="btn btn-sm btn-copy" onclick="loadAll()">↻ Обновить</button>

            </div>

            <table>

                <thead>

                    <tr>

                        <th>UID</th>

                        <th>Логин</th>

                        <th>Роль</th>

                        <th>Подписка</th>

                        <th>Привязка HWID</th>

                        <th>Действие</th>

                    </tr>

                </thead>

                <tbody id="usersTable">

                    <tr><td colspan="6" style="text-align:center; color:#888;">Загрузка...</td></tr>

                </tbody>

            </table>

        </div>



        <!-- Таблица ключей -->

        <div class="card">

            <div class="card-header">

                <div class="card-title">🔑 Ключи активации</div>

            </div>

            <table>

                <thead>

                    <tr>

                        <th>Лицензионный ключ</th>

                        <th>Срок</th>

                        <th>Статус</th>

                        <th>Кем активирован</th>

                        <th>Создан</th>

                        <th>Действие</th>

                    </tr>

                </thead>

                <tbody id="keysTable">

                    <tr><td colspan="6" style="text-align:center; color:#888;">Загрузка...</td></tr>

                </tbody>

            </table>

        </div>

    </div>



    <script>

        async function loadAll() {

            try {

                const [resUsers, resKeys] = await Promise.all([

                    fetch('/api/admin/users').then(r => r.json()),

                    fetch('/api/admin/keys').then(r => r.json())

                ]);



                // Статистика

                document.getElementById('statUsers').innerText = resUsers.length;

                document.getElementById('statKeys').innerText = resKeys.length;

                const freeCount = resKeys.filter(k => k.is_used === 0).length;

                document.getElementById('statFreeKeys').innerText = freeCount;



                // Загружаем текущую ссылку на клиент

                try {

                    const cfg = await fetch('/api/client/config').then(r => r.json());

                    if (cfg && cfg.download_url) {

                        document.getElementById('clientDownloadUrl').value = cfg.download_url;

                    }

                } catch (e) {}



                // Пользователи

                const uTbody = document.getElementById('usersTable');

                if (resUsers.length === 0) {

                    uTbody.innerHTML = '<tr><td colspan="6" style="text-align:center;">Пользователей нет</td></tr>';

                } else {

                    uTbody.innerHTML = resUsers.map(u => {

                        const isOwner = u.role === 'Owner';

                        const isBanned = u.is_banned === 1;

                        let roleTag = isOwner ? '<span class="tag tag-owner">Owner</span>' : '<span class="tag tag-user">User</span>';

                        if (isBanned) {

                            roleTag += ' <span class="tag tag-used" style="margin-left:4px;">⛔ ЗАБЛОКИРОВАН</span>';

                        }

                        const hwidDisplay = u.hwid ? '<span style="color:#a4a4c2; font-family:monospace; font-size:12px;">' + u.hwid.substring(0, 12) + '...</span>' : '<span style="color:#666;">Не привязан</span>';

                        const subDisplay = u.sub_until === 'LIFETIME' ? '<span style="color:#52e185; font-weight:700;">LIFETIME</span>' : u.sub_until;

                        

                        let actionButtons = `

                            <button class="btn-action" title="Сменить пароль" onclick="changeUserPassword('${u.username}')">🔑 Пароль</button>

                            <button class="btn-action" title="Добавить подписку" onclick="addSubscription('${u.username}')">⏳ +Подписка</button>

                            <button class="btn-action" title="Сбросить привязку ПК" onclick="resetUserHwid('${u.username}')">🔄 HWID</button>

                        `;



                        if (isOwner) {

                            actionButtons += `<button class="btn-action" style="border-color:#8a4bff; color:#ab7eff;" title="Установить кастомный UID" onclick="changeOwnerUid()">⭐ Кастомный UID</button>`;

                        } else {

                            if (isBanned) {

                                actionButtons += `<button class="btn-unban" onclick="toggleBan('${u.username}', false)">✅ Разбанить</button>`;

                            } else {

                                actionButtons += `<button class="btn-ban" onclick="toggleBan('${u.username}', true)">⛔ Бан</button>`;

                            }

                            actionButtons += `<button class="btn-del" title="Навсегда удалить" onclick="deleteUser('${u.username}')">🗑️</button>`;

                        }



                        const rowStyle = isBanned ? 'style="background: rgba(220, 50, 50, 0.08);"' : '';

                        const uidDisplay = isOwner ? `<b>#${u.id}</b> <button class="btn-action" style="padding:1px 5px; font-size:10px; margin-left:3px;" title="Сменить UID Создателя" onclick="changeOwnerUid()">✏️</button>` : `<b>#${u.id}</b>`;



                        return `<tr ${rowStyle}>

                            <td>${uidDisplay}</td>

                            <td><b>${u.username}</b></td>

                            <td>${roleTag}</td>

                            <td>${subDisplay}</td>

                            <td>${hwidDisplay}</td>

                            <td>

                                <div class="actions-wrap">

                                    ${actionButtons}

                                </div>

                            </td>

                        </tr>`;

                    }).join('');

                }



                // Ключи

                const kTbody = document.getElementById('keysTable');

                if (resKeys.length === 0) {

                    kTbody.innerHTML = '<tr><td colspan="6" style="text-align:center;">Ключей нет</td></tr>';

                } else {

                    kTbody.innerHTML = resKeys.map(k => {

                        const isUsed = k.is_used === 1;

                        const statusTag = isUsed ? '<span class="tag tag-used">Использован</span>' : '<span class="tag tag-free">Свободен</span>';

                        const daysText = k.days >= 9999 ? 'Навсегда' : k.days + ' дн.';

                        const usedBy = k.used_by ? '<b>' + k.used_by + '</b>' : '<span style="color:#666;">—</span>';

                        return `<tr>

                            <td><span class="key-text">${k.key}</span> <button class="btn btn-sm btn-copy" style="margin-left:6px;" onclick="navigator.clipboard.writeText('${k.key}'); alert('Ключ скопирован: ${k.key}');">📋</button></td>

                            <td>${daysText}</td>

                            <td>${statusTag}</td>

                            <td>${usedBy}</td>

                            <td style="color:#888; font-size:12px;">${k.created_at || '—'}</td>

                            <td><button class="btn-del" title="Удалить ключ" onclick="deleteActivationKey('${k.key}')">🗑️ Удалить</button></td>

                        </tr>`;

                    }).join('');

                }



            } catch (e) {

                console.error(e);

            }

        }



        async function generateKey() {

            const days = parseInt(document.getElementById('keyDays').value);

            const prefix = document.getElementById('keyPrefix').value.trim() || 'HV';

            const res = await fetch('/api/admin/create_key', {

                method: 'POST',

                headers: { 'Content-Type': 'application/json' },

                body: JSON.stringify({ days: days, prefix: prefix })

            }).then(r => r.json());



            if (res.status === 'success') {

                document.getElementById('newKeyText').innerText = res.key;

                document.getElementById('newKeyAlert').style.display = 'flex';

                loadAll();

            }

        }



        function copyNewKey() {

            const key = document.getElementById('newKeyText').innerText;

            navigator.clipboard.writeText(key);

            alert('Ключ скопирован в буфер: ' + key);

        }



        async function resetUserHwid(username) {

            if (!confirm('Сбросить привязку HWID для пользователя ' + username + '?')) return;

            const res = await fetch('/api/admin/reset_hwid', {

                method: 'POST',

                headers: { 'Content-Type': 'application/json' },

                body: JSON.stringify({ username: username })

            }).then(r => r.json());

            alert(res.message);

            loadAll();

        }



        async function changeUserPassword(username) {

            const newPass = prompt('Введите новый пароль для ' + username + ':');

            if (!newPass || !newPass.trim()) return;

            const res = await fetch('/api/admin/change_password', {

                method: 'POST',

                headers: { 'Content-Type': 'application/json' },

                body: JSON.stringify({ username: username, new_password: newPass.trim() })

            }).then(r => r.json());

            alert(res.message);

            loadAll();

        }



        async function addSubscription(username) {

            const val = prompt('Сколько дней подписки выдать для ' + username + ' (30, 90 или 9999 для навсегда):', '30');

            if (!val) return;

            const days = parseInt(val);

            if (isNaN(days) || days <= 0) {

                alert('Введите корректное число дней!');

                return;

            }

            const res = await fetch('/api/admin/set_sub', {

                method: 'POST',

                headers: { 'Content-Type': 'application/json' },

                body: JSON.stringify({ username: username, days: days })

            }).then(r => r.json());

            alert(res.message);

            loadAll();

        }



        async function toggleBan(username, banned) {

            const act = banned ? 'ЗАБЛОКИРОВАТЬ' : 'РАЗБЛОКИРОВАТЬ';

            if (!confirm('Вы точно хотите ' + act + ' пользователя ' + username + '?')) return;

            const res = await fetch('/api/admin/ban_user', {

                method: 'POST',

                headers: { 'Content-Type': 'application/json' },

                body: JSON.stringify({ username: username, banned: banned })

            }).then(r => r.json());

            alert(res.message);

            loadAll();

        }



        async function deleteUser(username) {

            if (!confirm('ВНИМАНИЕ! Вы точно хотите НАВСЕГДА удалить пользователя ' + username + '? Все данные будут стерты.')) return;

            const res = await fetch('/api/admin/delete_user', {

                method: 'POST',

                headers: { 'Content-Type': 'application/json' },

                body: JSON.stringify({ username: username })

            }).then(r => r.json());

            alert(res.message);

            loadAll();

        }



        async function changeOwnerUid() {

            const current = prompt('Введите новый кастомный UID для HeavenlyOwner (например: 0, 77, 777, 1337):', '1');

            if (current === null) return;

            const num = parseInt(current);

            if (isNaN(num) || num < 0) {

                alert('Введите корректное число >= 0!');

                return;

            }

            const res = await fetch('/api/admin/set_uid', {

                method: 'POST',

                headers: { 'Content-Type': 'application/json' },

                body: JSON.stringify({ username: 'HeavenlyOwner', new_uid: num })

            }).then(r => r.json());

            alert(res.message);

            loadAll();

        }



        async function saveClientDownloadUrl() {

            const url = document.getElementById('clientDownloadUrl').value.trim();

            const res = await fetch('/api/admin/set_client_url', {

                method: 'POST',

                headers: { 'Content-Type': 'application/json' },

                body: JSON.stringify({ download_url: url })

            }).then(r => r.json());

            const st = document.getElementById('clientUrlStatus');

            st.style.display = 'block';

            st.innerText = res.message || 'Ссылка успешно сохранена!';

            setTimeout(() => { st.style.display = 'none'; }, 4000);

        }



        async function deleteActivationKey(key) {

            if (!confirm('Вы точно хотите удалить ключ ' + key + '?')) return;

            const res = await fetch('/api/admin/delete_key', {

                method: 'POST',

                headers: { 'Content-Type': 'application/json' },

                body: JSON.stringify({ key: key })

            }).then(r => r.json());

            alert(res.message);

            loadAll();

        }



        loadAll();

    </script>

</body>

</html>

"""



if __name__ == "__main__":

    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

