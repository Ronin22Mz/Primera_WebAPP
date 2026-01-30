from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'tu_clave_secreta_aqui_chat_elegante_2024'
socketio = SocketIO(app, cors_allowed_origins="*")

# Configuración de base de datos
def init_db():
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    
    # Tabla de usuarios
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  role TEXT DEFAULT 'user',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Tabla de mensajes
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  sender TEXT NOT NULL,
                  receiver TEXT NOT NULL,
                  message TEXT NOT NULL,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  is_read INTEGER DEFAULT 0)''')
    
    # Insertar admin si no existe
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        hashed_pw = generate_password_hash('admin123')
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  ('admin', hashed_pw, 'admin'))
    
    conn.commit()
    conn.close()

# Inicializar base de datos antes del primer request
init_db()

# Rutas principales
@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('chat.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['username'] = user[1]
            session['role'] = user[3]
            return redirect(url_for('chat'))
        else:
            return render_template('login.html', error='Credenciales incorrectas')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if len(username) < 3 or len(password) < 6:
            return render_template('register.html', error='Usuario o contraseña muy cortos')
        
        hashed_pw = generate_password_hash(password)
        
        try:
            conn = sqlite3.connect('chat.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                      (username, hashed_pw))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Usuario ya existe')
    
    return render_template('register.html')

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    role = session.get('role', 'user')
    
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    
    # Obtener todos los usuarios excepto el actual
    c.execute("SELECT username, role FROM users WHERE username != ? ORDER BY role DESC, username", 
              (username,))
    users = [{'username': row[0], 'role': row[1]} for row in c.fetchall()]
    
    # Obtener mensajes no leídos
    c.execute("""SELECT sender, COUNT(*) as unread_count 
                 FROM messages 
                 WHERE receiver=? AND is_read=0 
                 GROUP BY sender""", 
              (username,))
    
    unread_counts = {row[0]: row[1] for row in c.fetchall()}
    total_unread = sum(unread_counts.values())
    
    conn.close()
    
    return render_template('chat.html', 
                         username=username,
                         role=role,
                         users=users,
                         unread_counts=unread_counts,
                         total_unread=total_unread)

@app.route('/admin')
def admin():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('chat'))
    
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute("SELECT id, username, role, created_at FROM users ORDER BY role DESC, username")
    users = c.fetchall()
    conn.close()
    
    return render_template('admin.html', 
                         users=users, 
                         username=session['username'],
                         role=session['role'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# API para mensajes
@app.route('/get_messages/<contact>')
def get_messages(contact):
    if 'username' not in session:
        return jsonify({'error': 'No autenticado'}), 401
    
    username = session['username']
    
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    
    # Obtener mensajes entre dos usuarios
    c.execute("""SELECT sender, receiver, message, timestamp, is_read 
                 FROM messages 
                 WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
                 ORDER BY timestamp""",
              (username, contact, contact, username))
    
    messages = []
    for row in c.fetchall():
        # Formatear la fecha
        timestamp = row[3]
        if isinstance(timestamp, str):
            try:
                time_obj = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                time_str = time_obj.strftime('%H:%M')
            except:
                time_str = timestamp
        else:
            time_str = timestamp
        
        messages.append({
            'sender': row[0],
            'receiver': row[1],
            'message': row[2],
            'time': time_str,
            'is_read': row[4],
            'is_me': row[0] == username
        })
    
    # Marcar como leídos
    c.execute("""UPDATE messages SET is_read=1 
                 WHERE receiver=? AND sender=? AND is_read=0""",
              (username, contact))
    
    conn.commit()
    conn.close()
    
    return jsonify(messages)

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'username' not in session:
        return jsonify({'error': 'No autenticado'}), 401
    
    data = request.get_json()
    receiver = data.get('receiver')
    message = data.get('message')
    
    if not receiver or not message:
        return jsonify({'error': 'Faltan datos'}), 400
    
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute("INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)",
              (session['username'], receiver, message.strip()))
    conn.commit()
    conn.close()
    
    # Emitir evento de socket para actualización en tiempo real
    socketio.emit('new_message', {
        'sender': session['username'],
        'receiver': receiver,
        'message': message.strip(),
        'time': datetime.now().strftime('%H:%M')
    }, room=receiver)
    
    # También emitir al sender para confirmación
    socketio.emit('message_sent', {
        'receiver': receiver,
        'message': message.strip(),
        'time': datetime.now().strftime('%H:%M')
    }, room=session['username'])
    
    return jsonify({'success': True, 'time': datetime.now().strftime('%H:%M')})

@app.route('/get_unread_count')
def get_unread_count():
    if 'username' not in session:
        return jsonify({'error': 'No autenticado'}), 401
    
    username = session['username']
    
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute("""SELECT sender, COUNT(*) as count 
                 FROM messages 
                 WHERE receiver=? AND is_read=0 
                 GROUP BY sender""", 
              (username,))
    
    result = {row[0]: row[1] for row in c.fetchall()}
    total = sum(result.values())
    
    conn.close()
    
    return jsonify({'total': total, 'by_user': result})

@app.route('/mark_as_read/<sender>', methods=['POST'])
def mark_as_read(sender):
    if 'username' not in session:
        return jsonify({'error': 'No autenticado'}), 401
    
    username = session['username']
    
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute("""UPDATE messages SET is_read=1 
                 WHERE receiver=? AND sender=? AND is_read=0""",
              (username, sender))
    conn.commit()
    conn.close()
    
    # Emitir actualización para reducir contador
    socketio.emit('messages_read', {
        'sender': sender,
        'receiver': username
    })
    
    return jsonify({'success': True})

@app.route('/get_unread_by_sender/<sender>')
def get_unread_by_sender(sender):
    if 'username' not in session:
        return jsonify({'error': 'No autenticado'}), 401
    
    username = session['username']
    
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute("""SELECT COUNT(*) as count 
                 FROM messages 
                 WHERE receiver=? AND sender=? AND is_read=0""", 
              (username, sender))
    
    count = c.fetchone()[0]
    conn.close()
    
    return jsonify({'count': count})

# Rutas de administración
@app.route('/admin/toggle_role/<int:user_id>', methods=['POST'])
def toggle_role(user_id):
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'No autorizado'}), 403
    
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    
    # Obtener usuario actual
    c.execute("SELECT username, role FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    
    if not user:
        conn.close()
        return jsonify({'error': 'Usuario no encontrado'}), 404
    
    if user[0] == 'admin':
        conn.close()
        return jsonify({'error': 'No se puede modificar al administrador principal'}), 400
    
    # Cambiar rol
    new_role = 'user' if user[1] == 'admin' else 'admin'
    c.execute("UPDATE users SET role=? WHERE id=?", (new_role, user_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'new_role': new_role})

@app.route('/admin/delete_user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'No autorizado'}), 403
    
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    
    # Obtener usuario
    c.execute("SELECT username FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    
    if not user:
        conn.close()
        return jsonify({'error': 'Usuario no encontrado'}), 404
    
    if user[0] == 'admin' or user[0] == session['username']:
        conn.close()
        return jsonify({'error': 'No se puede eliminar este usuario'}), 400
    
    # Eliminar usuario y sus mensajes
    c.execute("DELETE FROM users WHERE id=?", (user_id,))
    c.execute("DELETE FROM messages WHERE sender=? OR receiver=?", (user[0], user[0]))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

# Eventos de Socket.IO
@socketio.on('connect')
def handle_connect():
    if 'username' in session:
        username = session['username']
        join_room(username)
        print(f'Usuario {username} conectado')
        # Notificar a todos que este usuario está online
        emit('user_status', {'username': username, 'status': 'online'}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if 'username' in session:
        username = session['username']
        print(f'Usuario {username} desconectado')
        # Notificar a todos que este usuario está offline
        emit('user_status', {'username': username, 'status': 'offline'}, broadcast=True)

@socketio.on('typing')
def handle_typing(data):
    if 'username' in session:
        emit('user_typing', {
            'username': session['username'],
            'receiver': data.get('receiver'),
            'is_typing': data.get('is_typing')
        }, room=data.get('receiver'))

@socketio.on('user_online')
def handle_user_online(data):
    if 'username' in session:
        username = session['username']
        emit('user_status', {'username': username, 'status': 'online'}, broadcast=True)

if __name__ == '__main__':
    print("Iniciando Chat Elegante...")
    print("Accede a: http://localhost:5000")
    socketio.run(app, 
                 debug=True, 
                 host='0.0.0.0', 
                 port=5000, 
                 allow_unsafe_werkzeug=True)