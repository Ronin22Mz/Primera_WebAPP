from flask import Flask, render_template, request, url_for
from flask_socketio import SocketIO
import sqlite3
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'tu_clave_secreta'
app.config['UPLOAD_FOLDER'] = 'static/uploads'

socketio = SocketIO(app)

# ---------- DB ----------
def init_db():
    with sqlite3.connect("chat.db") as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mensajes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT,
                contenido TEXT,
                tipo TEXT
            )
        """)

init_db()

# ---------- ROUTES ----------
@app.route('/')
def index():
    with sqlite3.connect("chat.db") as conn:
        mensajes = conn.execute(
            "SELECT nombre, contenido, tipo FROM mensajes"
        ).fetchall()
    return render_template('realtime.html', mensajes=mensajes)

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    if file:
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(path)
        return {
            'url': url_for('static', filename=f'uploads/{file.filename}')
        }

# ---------- SOCKET ----------
@socketio.on('mensaje')
def manejar_mensaje(data):
    nombre = data['nombre']
    contenido = data['contenido']
    tipo = data['tipo']  # text | image | file

    with sqlite3.connect("chat.db") as conn:
        conn.execute(
            "INSERT INTO mensajes (nombre, contenido, tipo) VALUES (?, ?, ?)",
            (nombre, contenido, tipo)
        )

    socketio.emit('actualizar_mensajes', data)

if __name__ == '__main__':
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
