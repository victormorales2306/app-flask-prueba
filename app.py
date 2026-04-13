from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify
import psycopg2
import psycopg2.extras
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import csv
import io
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_key")

DATABASE_URL = os.environ.get("DATABASE_URL")
print("DATABASE_URL =", DATABASE_URL)

MAX_INTENTOS = 3
TIEMPO_BLOQUEO_MIN = 15

# ---------------- DB ----------------

def get_db():
    return psycopg2.connect(
        DATABASE_URL,
        sslmode="require",
        cursor_factory=psycopg2.extras.RealDictCursor
    )

# ---------------- HELPERS ----------------

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

# ---------------- INDEX ----------------

@app.route("/")
def index():
    if "usuario" not in session:
        return redirect(url_for("login"))

    if session.get("rol") == "admin":
        return redirect(url_for("dashboard"))

    return render_template("mapa.html", usuario=session["usuario"])

# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form["usuario"]
        password = request.form["password"]
        ip = get_ip()

        conn = get_db()
        cur = conn.cursor()

        try:
            cur.execute("SELECT * FROM intentos_login WHERE ip = %s", (ip,))
            intento = cur.fetchone()

            if intento and intento["bloqueado_hasta"]:
                if datetime.now() < intento["bloqueado_hasta"]:
                    flash("IP bloqueada")
                    return redirect(url_for("login"))

            cur.execute("SELECT * FROM usuarios_sistema WHERE usuario = %s", (usuario,))
            user = cur.fetchone()

            if not user:
                registrar_intento(ip, conn)
                flash("Usuario o contraseña incorrectos")
                return redirect(url_for("login"))

            if user["estado"] == "bloqueado":
                flash("Usuario bloqueado")
                return redirect(url_for("login"))

            if not check_password_hash(user["contrasena"], password):
                registrar_intento(ip, conn)
                flash("Usuario o contraseña incorrectos")
                return redirect(url_for("login"))

            limpiar_intentos(ip, conn)

            session["usuario"] = user["usuario"]
            session["rol"] = user["rol"]

            return redirect(url_for("index"))

        finally:
            conn.close()

    return render_template("login.html")

@app.route("/dashboard")
@admin_required
def dashboard():
    return render_template("dashboard.html", usuario=session["usuario"], rol=session["rol"])


# ---------------- LOGOUT ----------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))
#--------------ver_reportes------------------------
@app.route("/ver_reportes")
def ver_reportes():
    if "usuario" not in session:
        return redirect(url_for("login"))
    return render_template("ver_reportes.html")
# ---------------- ADMIN USUARIOS ----------------

@app.route("/admin/usuarios")
@admin_required
def admin_usuarios():
    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("SELECT usuario, nombre, correo, estado, rol FROM usuarios_sistema ORDER BY usuario")
        usuarios = cur.fetchall()
        return render_template("admin_usuarios.html", usuarios=usuarios)
    finally:
        conn.close()

@app.route("/admin/usuario/<usuario>/bloquear")
@admin_required
def bloquear_usuario(usuario):
    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("UPDATE usuarios_sistema SET estado = 'bloqueado' WHERE usuario = %s", (usuario,))
        conn.commit()
        flash(f"Usuario {usuario} bloqueado.")
    finally:
        conn.close()

    return redirect(url_for("admin_usuarios"))

@app.route("/admin/usuario/<usuario>/desbloquear")
@admin_required
def desbloquear_usuario(usuario):
    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("UPDATE usuarios_sistema SET estado = 'activo' WHERE usuario = %s", (usuario,))
        conn.commit()
        flash(f"Usuario {usuario} desbloqueado.")
    finally:
        conn.close()

    return redirect(url_for("admin_usuarios"))

@app.route("/admin/usuario/nuevo", methods=["GET", "POST"])
@admin_required
def nuevo_usuario():
    if request.method == "POST":
        usuario = request.form["usuario"]
        nombre = request.form["nombre"]
        password = request.form["password"]
        correo = request.form["correo"]
        rol = request.form.get("rol", "usuario")

        hash_pw = generate_password_hash(password)

        conn = get_db()
        cur = conn.cursor()

        try:
            cur.execute("SELECT usuario FROM usuarios_sistema WHERE usuario = %s", (usuario,))
            if cur.fetchone():
                flash("Usuario ya existe")
                return redirect(url_for("nuevo_usuario"))

            cur.execute("""
                INSERT INTO usuarios_sistema (usuario, nombre, contrasena, correo, estado, rol)
                VALUES (%s, %s, %s, %s, 'activo', %s)
            """, (usuario, nombre, hash_pw, correo, rol))

            conn.commit()
            flash("Usuario creado")

        finally:
            conn.close()

        return redirect(url_for("admin_usuarios"))

    return render_template("nuevo_usuario.html")

# ---------------- CLIENTES ----------------

@app.route("/api/clientes")
def api_clientes():
    serial = request.args.get("serial")

    conn = get_db()
    cur = conn.cursor()

    try:
        if serial:
            cur.execute("""
                SELECT serialnumber, latitude, longitude
                FROM suscriptores_noviembre_2025
                WHERE serialnumber = %s
            """, (serial,))
        else:
            cur.execute("""
                SELECT serialnumber, latitude, longitude
                FROM suscriptores_noviembre_2025
                LIMIT 200
            """)

        return jsonify(cur.fetchall())

    finally:
        conn.close()

# ---------------- REPORTES ----------------

@app.route("/api/reportes", methods=["GET"])
def obtener_reportes():
    if "usuario" not in session:
        return jsonify({"error": "No autorizado"}), 401

    fecha_inicio = request.args.get("inicio")
    fecha_fin = request.args.get("fin")

    conn = get_db()
    cur = conn.cursor()

    try:
        query = """
            SELECT aparato, mru, referencia, comentario, latitud, longitud, usuario, fecha
            FROM reportes_medidores
            WHERE 1=1
        """

        params = []

        if fecha_inicio:
            query += " AND fecha::date >= %s"
            params.append(fecha_inicio)

        if fecha_fin:
            query += " AND fecha::date <= %s"
            params.append(fecha_fin)

        query += " ORDER BY fecha DESC LIMIT 200"

        cur.execute(query, tuple(params))
        return jsonify(cur.fetchall())

    finally:
        conn.close()

@app.route("/api/reportes", methods=["POST"])
def api_reportes():
    if "usuario" not in session:
        return jsonify({"error": "No autorizado"}), 401

    data = request.get_json()

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("""
            INSERT INTO reportes_medidores 
            (aparato, mru, referencia, comentario, latitud, longitud, usuario, fecha)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            data.get("aparato"),
            data.get("mru"),
            data.get("referencia"),
            data.get("comentario"),
            data.get("latitud"),
            data.get("longitud"),
            session["usuario"],
            data.get("fecha")
        ))

        conn.commit()
        return jsonify({"status": "ok"})

    finally:
        conn.close()
#--------------------------------- cambiar contraseña --------------------------------------

@app.route('/cambiar_password/<usuario>', methods=['GET', 'POST'])
@admin_required
def cambiar_password(usuario):
    if request.method == 'POST':
        nueva_password = request.form.get('password')

        conn = get_db()
        cur = conn.cursor()

        try:
            hash_pw = generate_password_hash(nueva_password)

            cur.execute("""
                UPDATE usuarios_sistema
                SET contrasena = %s
                WHERE usuario = %s
            """, (hash_pw, usuario))

            conn.commit()
            flash('Contraseña actualizada correctamente')

        finally:
            conn.close()

        return redirect(url_for('admin_usuarios'))

    return render_template('cambiar_password.html', usuario=usuario)


# ---------------- EXPORT ----------------

@app.route("/admin/exportar_reportes")
@admin_required
def exportar_reportes():
    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT aparato, mru, referencia, comentario, latitud, longitud, usuario, fecha
            FROM reportes_medidores
            ORDER BY fecha DESC
        """)

        rows = cur.fetchall()

        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["APARATO","MRU","REFERENCIA","COMENTARIO","LAT","LON","USUARIO","FECHA"])

        for r in rows:
            writer.writerow([
                r["aparato"], r["mru"], r["referencia"],
                r["comentario"], r["latitud"], r["longitud"],
                r["usuario"], r["fecha"]
            ])

        output.seek(0)

        return app.response_class(
            output,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=reportes.csv"}
        )

    finally:
        conn.close()

# ---------------- CSV CARGA ----------------

@app.route("/admin/cargar_suscriptores", methods=["GET", "POST"])
@admin_required
def cargar_suscriptores():
    if request.method == "POST":
        archivo = request.files["archivo"]
        contenido = archivo.read().decode("utf-8")
        reader = csv.DictReader(io.StringIO(contenido))

        conn = get_db()
        cur = conn.cursor()

        try:
            cur.execute("DELETE FROM suscriptores_noviembre_2025")

            for row in reader:
                cur.execute("""
                    INSERT INTO suscriptores_noviembre_2025 (serialnumber, latitude, longitude)
                    VALUES (%s, %s, %s)
                """, (
                    row.get("serialnumber"),
                    row.get("latitude"),
                    row.get("longitude")
                ))

            conn.commit()
            flash("Datos cargados correctamente")

        finally:
            conn.close()

        return redirect(url_for("cargar_suscriptores"))

    return render_template("cargar_suscriptores.html")

# ---------------- INTENTOS ----------------

def registrar_intento(ip, conn):
    cur = conn.cursor()

    cur.execute("SELECT * FROM intentos_login WHERE ip = %s", (ip,))
    data = cur.fetchone()

    if data:
        intentos = data["intentos"] + 1
        if intentos >= MAX_INTENTOS:
            bloqueo = datetime.now() + timedelta(minutes=TIEMPO_BLOQUEO_MIN)
            cur.execute("""
                UPDATE intentos_login 
                SET intentos=%s, bloqueado_hasta=%s 
                WHERE ip=%s
            """, (intentos, bloqueo, ip))
        else:
            cur.execute("UPDATE intentos_login SET intentos=%s WHERE ip=%s", (intentos, ip))
    else:
        cur.execute("INSERT INTO intentos_login (ip, intentos) VALUES (%s, 1)", (ip,))

    conn.commit()

def limpiar_intentos(ip, conn):
    cur = conn.cursor()
    cur.execute("DELETE FROM intentos_login WHERE ip = %s", (ip,))
    conn.commit()

# ---------------- RUN ----------------

if __name__ == "__main__":
    app.run(debug=True)