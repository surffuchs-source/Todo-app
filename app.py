from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-change-in-production')
DB_PATH = os.environ.get('DB_PATH', 'todos.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        db.execute('''CREATE TABLE IF NOT EXISTS todos (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, title TEXT NOT NULL, done INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id))''')
        db.commit()

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/')
@login_required
def index():
    with get_db() as db:
        todos = db.execute('SELECT * FROM todos WHERE user_id = ? ORDER BY done ASC, created_at DESC', (session['user_id'],)).fetchall()
    return render_template('index.html', todos=todos, username=session['username'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        with get_db() as db:
            user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('index'))
        error = 'Invalid username or password.'
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if len(username) < 3:
            error = 'Username must be at least 3 characters.'
        elif len(password) < 6:
            error = 'Password must be at least 6 characters.'
        else:
            try:
                with get_db() as db:
                    db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, generate_password_hash(password)))
                    db.commit()
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                error = 'Username already taken.'
    return render_template('register.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/todos/add', methods=['POST'])
@login_required
def add_todo():
    title = request.form.get('title', '').strip()
    if title:
        with get_db() as db:
            db.execute('INSERT INTO todos (user_id, title) VALUES (?, ?)', (session['user_id'], title))
            db.commit()
    return redirect(url_for('index'))

@app.route('/todos/<int:todo_id>/toggle', methods=['POST'])
@login_required
def toggle_todo(todo_id):
    with get_db() as db:
        todo = db.execute('SELECT * FROM todos WHERE id = ? AND user_id = ?', (todo_id, session['user_id'])).fetchone()
        if todo:
            db.execute('UPDATE todos SET done = ? WHERE id = ?', (0 if todo['done'] else 1, todo_id))
            db.commit()
    return redirect(url_for('index'))

@app.route('/todos/<int:todo_id>/delete', methods=['POST'])
@login_required
def delete_todo(todo_id):
    with get_db() as db:
        db.execute('DELETE FROM todos WHERE id = ? AND user_id = ?', (todo_id, session['user_id']))
        db.commit()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))

# Initialize DB on startup
with app.app_context():
    init_db()
