import sqlite3
from datetime import datetime

def migrate_database():
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    
    try:
        # Añadir columna last_seen si no existe
        c.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in c.fetchall()]
        
        if 'last_seen' not in columns:
            c.execute("ALTER TABLE users ADD COLUMN last_seen TIMESTAMP")
            print("✓ Columna 'last_seen' añadida a users")
        
        # Añadir columna read_at si no existe
        c.execute("PRAGMA table_info(messages)")
        columns = [column[1] for column in c.fetchall()]
        
        if 'read_at' not in columns:
            c.execute("ALTER TABLE messages ADD COLUMN read_at TIMESTAMP")
            print("✓ Columna 'read_at' añadida a messages")
        
        # Actualizar todos los usuarios con un last_seen por defecto
        c.execute("UPDATE users SET last_seen=? WHERE last_seen IS NULL", 
                 (datetime.now(),))
        
        conn.commit()
        print("✓ Base de datos migrada exitosamente")
        
    except sqlite3.Error as e:
        print(f"✗ Error durante la migración: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == '__main__':
    migrate_database()