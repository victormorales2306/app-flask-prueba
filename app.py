from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import csv
import io
import os

app = Flask(_name_)
app.secret_key = os.environ.get("SECRET_KEY")

BASE_DIR = os.path.dirname(os.path.abspath(_file_))
DB_PATH = os.path.join(BASE_DIR, "Ubicaciones.db")

MAX_INTENTOS = 3
TIEMPO_BLOQUEO_MIN = 15

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "usuario" not in session:
            return redirect(url_for("login"))
        if session.get("rol") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def init_db():
    conn = get_db()
    cur = conn.cursor()

    # Tabla para control de intentos
    cur.execute("""
        CREATE TABLE IF NOT EXISTS intentos_login (
            ip TEXT PRIMARY KEY,
            intentos INTEGER DEFAULT 0,
            bloqueado_hasta TEXT
        )
    """)

    # Añadir columnas estado y rol si no existen en usuarios_sistema (solo si tienes esta tabla)
    try:
        cur.execute("ALTER TABLE usuarios_sistema ADD COLUMN estado TEXT DEFAULT 'activo'")
    except sqlite3.OperationalError:
        pass

    try:
        cur.execute("ALTER TABLE usuarios_sistema ADD COLUMN rol TEXT DEFAULT 'usuario'")
    except sqlite3.OperationalError:
        pass

    # Convertir contraseñas a hash si es necesario (solo si tienes usuarios_sistema)
    try:
        cur.execute("SELECT Usuario, contraseña FROM usuarios_sistema")
        usuarios = cur.fetchall()
        updated = False
        for u in usuarios:
            pw = u["contraseña"]
            if not pw.startswith("pbkdf2:") and not pw.startswith("scrypt:"):
                hash_pw = generate_password_hash(pw)
                cur.execute("UPDATE usuarios_sistema SET contraseña = ? WHERE Usuario = ?", (hash_pw, u["Usuario"]))
                updated = True
        if updated:
            print("Contraseñas convertidas a hash.")
    except sqlite3.OperationalError:
        # Tabla usuarios_sistema no existe, no hacemos nada
        pass

    conn.commit()
    conn.close()

@app.route("/")
def index():
    # Página principal (mapa)
    if "usuario" not in session:
        return redirect(url_for("login"))

    # Usuarios admin van al dashboard
    if session.get("rol") == "admin":
        return redirect(url_for("dashboard"))
    else:
        # Usuarios normales van directo al mapa
        return render_template("mapa.html", usuario=session["usuario"])

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form["usuario"]
        password = request.form["password"]
        ip = get_ip()

        conn = get_db()
        cur = conn.cursor()

        # Verificar bloqueo IP
        cur.execute("SELECT * FROM intentos_login WHERE ip = ?", (ip,))
        intento = cur.fetchone()
        if intento and intento["bloqueado_hasta"]:
            bloqueado_hasta = datetime.fromisoformat(intento["bloqueado_hasta"])
            if datetime.now() < bloqueado_hasta:
                flash("IP bloqueada por múltiples intentos fallidos. Contacta a mantenimiento.")
                return redirect(url_for("login"))

        # Buscar usuario
        try:
            cur.execute("SELECT * FROM usuarios_sistema WHERE Usuario = ?", (usuario,))
            user = cur.fetchone()
        except sqlite3.OperationalError:
            flash("Error: Tabla de usuarios no configurada.")
            conn.close()
            return redirect(url_for("login"))

        if not user:
            registrar_intento(ip, conn)
            flash("Usuario o contraseña incorrectos")
            conn.close()
            return redirect(url_for("login"))

        if user["estado"] == "bloqueado":
            flash("Tu cuenta está bloqueada. Contacta a mantenimiento.")
            conn.close()
            return redirect(url_for("login"))

        if not check_password_hash(user["contraseña"], password):
            registrar_intento(ip, conn)
            flash("Usuario o contraseña incorrectos")
            conn.close()
            return redirect(url_for("login"))

        limpiar_intentos(ip, conn)
        session["usuario"] = user["Usuario"]
        session["rol"] = user["rol"]
        conn.close()

        # Redireccionar según rol
        if user["rol"] == "admin":
            return redirect(url_for("dashboard"))
        else:
            return redirect(url_for("index"))

    return render_template("login.html")

@app.route("/dashboard")
@admin_required
def dashboard():
    return render_template("dashboard.html", usuario=session["usuario"], rol=session["rol"])

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

def registrar_intento(ip, conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM intentos_login WHERE ip = ?", (ip,))
    data = cur.fetchone()

    if data:
        intentos = data["intentos"] + 1
        if intentos >= MAX_INTENTOS:
            bloqueado_hasta = datetime.now() + timedelta(minutes=TIEMPO_BLOQUEO_MIN)
            cur.execute("""
                UPDATE intentos_login
                SET intentos = ?, bloqueado_hasta = ?
                WHERE ip = ?
            """, (intentos, bloqueado_hasta.isoformat(), ip))
        else:
            cur.execute("UPDATE intentos_login SET intentos = ? WHERE ip = ?", (intentos, ip))
    else:
        cur.execute("INSERT INTO intentos_login (ip, intentos) VALUES (?, 1)", (ip,))

    conn.commit()

def limpiar_intentos(ip, conn):
    cur = conn.cursor()
    cur.execute("DELETE FROM intentos_login WHERE ip = ?", (ip,))
    conn.commit()

# --- Admin usuarios ---

@app.route("/admin/usuarios")
@admin_required
def admin_usuarios():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT Usuario, nombre, correo, estado, rol FROM usuarios_sistema ORDER BY Usuario")
    usuarios = cur.fetchall()
    conn.close()
    return render_template("admin_usuarios.html", usuarios=usuarios)

@app.route("/admin/usuario/<usuario>/bloquear")
@admin_required
def bloquear_usuario(usuario):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE usuarios_sistema SET estado = 'bloqueado' WHERE Usuario = ?", (usuario,))
    conn.commit()
    conn.close()
    flash(f"Usuario {usuario} bloqueado.")
    return redirect(url_for("admin_usuarios"))

@app.route("/admin/usuario/<usuario>/desbloquear")
@admin_required
def desbloquear_usuario(usuario):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE usuarios_sistema SET estado = 'activo' WHERE Usuario = ?", (usuario,))
    conn.commit()
    conn.close()
    flash(f"Usuario {usuario} desbloqueado.")
    return redirect(url_for("admin_usuarios"))

@app.route("/admin/usuario/<usuario>/cambiar_password", methods=["GET", "POST"])
@admin_required
def cambiar_password(usuario):
    if request.method == "POST":
        nueva_pw = request.form["nueva_password"]
        hash_pw = generate_password_hash(nueva_pw)
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            UPDATE usuarios_sistema
            SET contraseña = ?, estado = 'activo'
            WHERE Usuario = ?
        """, (hash_pw, usuario))
        conn.commit()
        conn.close()
        flash(f"Contraseña cambiada para {usuario}.")
        return redirect(url_for("admin_usuarios"))

    return render_template("cambiar_password.html", usuario=usuario)

@app.route("/admin/usuario/nuevo", methods=["GET", "POST"])
@admin_required
def nuevo_usuario():
    if request.method == "POST":
        usuario = request.form["usuario"].strip()
        nombre = request.form["nombre"].strip()
        password = request.form["password"]
        correo = request.form["correo"].strip()
        estado = request.form.get("estado", "activo")
        rol = request.form.get("rol", "usuario")

        if not usuario or not nombre or not password or not correo:
            flash("Todos los campos son obligatorios")
            return redirect(url_for("nuevo_usuario"))

        hash_pw = generate_password_hash(password)

        conn = get_db()
        cur = conn.cursor()

        cur.execute("SELECT Usuario FROM usuarios_sistema WHERE Usuario = ?", (usuario,))
        if cur.fetchone():
            flash("El usuario ya existe")
            conn.close()
            return redirect(url_for("nuevo_usuario"))

        cur.execute("""
            INSERT INTO usuarios_sistema (Usuario, nombre, contraseña, correo, estado, rol)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (usuario, nombre, hash_pw, correo, estado, rol))

        conn.commit()
        conn.close()

        flash(f"Usuario {usuario} creado correctamente")
        return redirect(url_for("admin_usuarios"))

    return render_template("nuevo_usuario.html")

# --- Endpoint clientes para mapa ---

@app.route("/api/clientes")
def api_clientes():
    serial = request.args.get("serial")

    conn = get_db()
    cur = conn.cursor()

    if serial:
        cur.execute("""
            SELECT SERIALNUMBER, LATITUDE, LONGITUDE
            FROM Suscriptores_Noviembre_2025
            WHERE SERIALNUMBER = ?
        """, (serial,))
    else:
        cur.execute("""
            SELECT SERIALNUMBER, LATITUDE, LONGITUDE
            FROM Suscriptores_Noviembre_2025
            LIMIT 200
        """)

    rows = cur.fetchall()
    conn.close()

    data = [dict(row) for row in rows]
    return jsonify(data)

# --- NUEVO: Cargar archivo CSV/TXT para recargar tabla Suscriptores_Noviembre_2025 ---

@app.route("/admin/cargar_suscriptores", methods=["GET", "POST"])
@admin_required
def cargar_suscriptores():
    if request.method == "POST":
        if "archivo" not in request.files:
            flash("No se seleccionó ningún archivo")
            return redirect(url_for("cargar_suscriptores"))
        archivo = request.files["archivo"]
        if archivo.filename == "":
            flash("No se seleccionó ningún archivo")
            return redirect(url_for("cargar_suscriptores"))

        # Solo aceptamos CSV o TXT
        if not (archivo.filename.endswith(".csv") or archivo.filename.endswith(".txt")):
            flash("Solo se permiten archivos CSV o TXT")
            return redirect(url_for("cargar_suscriptores"))

        try:
            contenido = archivo.read().decode("utf-8")
            reader = csv.DictReader(io.StringIO(contenido))
        except Exception as e:
            flash(f"Error leyendo archivo: {e}")
            return redirect(url_for("cargar_suscriptores"))

        # Insertar en BD (borrando primero)
        conn = get_db()
        cur = conn.cursor()

        try:
            cur.execute("DELETE FROM Suscriptores_Noviembre_2025")
            for row in reader:
                # Ajusta las columnas según tu CSV/TXT
                cur.execute("""
                    INSERT INTO Suscriptores_Noviembre_2025 (SERIALNUMBER, LATITUDE, LONGITUDE)
                    VALUES (?, ?, ?)
                """, (row.get("SERIALNUMBER"), row.get("LATITUDE"), row.get("LONGITUDE")))
            conn.commit()
            flash("Tabla Suscriptores_Noviembre_2025 recargada correctamente")
        except Exception as e:
            conn.rollback()
            flash(f"Error al insertar datos: {e}")
        finally:
            conn.close()

        return redirect(url_for("cargar_suscriptores"))

    return render_template("cargar_suscriptores.html")


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
