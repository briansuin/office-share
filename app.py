import sqlite3

# the following is added only for windows
import os
from dotenv import load_dotenv

load_dotenv()
# the above is added only for windows

import os
import functools
import io
import openpyxl
from urllib.parse import quote
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, g, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
#app.config['SECRET_KEY'] = os.urandom(24)
#app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
# the following is added only for windows
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
# the above is added only for windows

app.config['UPLOAD_FOLDER'] = 'static/uploads'

def get_db():
    """Creates and returns a new database connection. If a connection already exists in the request context, it is reused."""
    if 'db' not in g:
        g.db = sqlite3.connect('share.db')
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    """Closes the database connection at the end of the request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('signin'))
        return view(**kwargs)
    return wrapped_view

def admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None or not g.user['is_admin']:
            flash('您无权访问此页面。')
            return redirect(url_for('index'))
        return view(**kwargs)
    return wrapped_view

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        db = get_db()
        g.user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

def validate_form(form_data):
    """Validates form data based on a set of rules."""
    for field, rules in form_data.items():
        value = request.form.get(field)
        for rule in rules:
            if rule == 'required' and not value:
                return f"“{field.replace('_', ' ').title()}”是必填项。"
            if value:
                if rule.startswith('max_length:'):
                    max_length = int(rule.split(':')[1])
                    if len(value) > max_length:
                        return f"“{field.replace('_', ' ').title()}”不能超过{max_length}个字符。"
    return None

@app.route('/')
def index():
    """Fetches items from the database and displays them."""
    db = get_db()
    items = db.execute('SELECT * FROM items ORDER BY RANDOM()').fetchall()
    sharing_methods = db.execute('SELECT * FROM sharing_methods').fetchall()
    return render_template('index.html', items=items, sharing_methods=sharing_methods)

@app.route('/add', methods=('GET', 'POST'))
@login_required
def add():
    db = get_db()
    sharing_methods = db.execute('SELECT * FROM sharing_methods').fetchall()
    if request.method == 'POST':
        error = validate_form({
            'name': ['required', 'max_length:20'],
            'method': ['required'],
            'location': ['max_length:30'],
            'contact': ['max_length:30'],
            'details': ['max_length:100']
        })

        if error is None:
            thumbnail_filename = None
            if 'thumbnail' in request.files:
                file = request.files['thumbnail']
                if file.filename != '':
                    ext = os.path.splitext(file.filename)[1]
                    thumbnail_filename = os.urandom(16).hex() + ext
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], thumbnail_filename))

            db = get_db()
            db.execute(
                'INSERT INTO items (name, method, owner, thumbnail, location, contact, details) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (request.form['name'], request.form['method'], g.user['username'], thumbnail_filename, request.form['location'], request.form['contact'], request.form['details'])
            )
            db.commit()
            return redirect(url_for('index'))

        flash(error, 'error')

    return render_template('add.html', sharing_methods=sharing_methods)

@app.route('/signup', methods=('GET', 'POST'))
def signup():
    if request.method == 'POST':
        error = validate_form({
            'username': ['required', 'max_length:20'],
            'password': ['required']
        })

        if error is None:
            db = get_db()
            username = request.form['username']
            password = request.form['password']
            if db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone() is not None:
                error = f"用户“{username}”已注册。"
            else:
                registration_approval_setting = db.execute("SELECT value FROM settings WHERE key = 'registration_approval'").fetchone()
                registration_approval = registration_approval_setting['value'] == 'true' if registration_approval_setting else False

                is_approved = not registration_approval

                cursor = db.cursor()
                cursor.execute(
                    'INSERT INTO users (username, password, is_approved) VALUES (?, ?, ?)',
                    (username, generate_password_hash(password), is_approved)
                )
                db.commit()

                if not is_approved:
                    flash('您的注册正在等待管理员批准。')
                    return redirect(url_for('signin'))

                new_user_id = cursor.lastrowid
                session.clear()
                session['user_id'] = new_user_id
                return redirect(url_for('index'))

        flash(error, 'error')

    return render_template('signup.html')

@app.route('/signin', methods=('GET', 'POST'))
def signin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        error = None

        if not username:
            error = '用户名为必填项。'
        elif len(username) > 20:
            error = '用户名不能超过20个字符。'
        elif not password:
            error = '密码为必填项。'

        if error is None:
            db = get_db()
            user = db.execute(
                'SELECT * FROM users WHERE username = ?', (username,)
            ).fetchone()

            if user is None or not check_password_hash(user['password'], password):
                error = '用户名或密码不正确。'
            elif not user['is_approved']:
                error = '您的帐户尚未获得管理员批准。'
            
            if error is None:
                session.clear()
                session['user_id'] = user['id']
                return redirect(url_for('index'))

        flash(error, 'error')

    return render_template('signin.html')

@app.route('/signout')
def signout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/edit/<int:item_id>', methods=('GET', 'POST'))
@login_required
def edit(item_id):
    db = get_db()
    item = db.execute('SELECT * FROM items WHERE id = ?', (item_id,)).fetchone()
    sharing_methods = db.execute('SELECT * FROM sharing_methods').fetchall()

    if item is None:
        flash('未找到项目。', 'error')
        return redirect(url_for('index'))

    if not g.user['is_admin'] and item['owner'] != g.user['username']:
        flash('您无权编辑此项目。', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        error = validate_form({
            'name': ['required', 'max_length:20'],
            'method': ['required'],
            'location': ['max_length:30'],
            'contact': ['max_length:30'],
            'details': ['max_length:100']
        })

        if error is None:
            name = request.form['name']
            method = request.form['method']
            location = request.form['location']
            contact = request.form['contact']
            details = request.form['details']
            thumbnail = item['thumbnail']

            if 'thumbnail' in request.files:
                file = request.files['thumbnail']
                if file.filename != '':
                    if item['thumbnail']:
                        old_thumbnail_path = os.path.join(app.config['UPLOAD_FOLDER'], item['thumbnail'])
                        if os.path.exists(old_thumbnail_path):
                            os.remove(old_thumbnail_path)
                    
                    ext = os.path.splitext(file.filename)[1]
                    thumbnail = os.urandom(16).hex() + ext
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], thumbnail))

            db.execute(
                'UPDATE items SET name = ?, method = ?, thumbnail = ?, location = ?, contact = ?, details = ? WHERE id = ?',
                (name, method, thumbnail, location, contact, details, item_id)
            )
            db.commit()
            return redirect(url_for('index'))

        flash(error, 'error')

    return render_template('edit.html', item=item, sharing_methods=sharing_methods)

@app.route('/delete/<int:item_id>', methods=('POST',))
@login_required
def delete(item_id):
    db = get_db()
    item = db.execute('SELECT thumbnail, owner FROM items WHERE id = ?', (item_id,)).fetchone()

    if item is None:
        flash('未找到项目。', 'error')
        return redirect(url_for('index'))

    if not g.user['is_admin'] and item['owner'] != g.user['username']:
        flash('您无权删除此项目。', 'error')
        return redirect(url_for('index'))

    if item['thumbnail']:
        thumbnail_path = os.path.join(app.config['UPLOAD_FOLDER'], item['thumbnail'])
        if os.path.exists(thumbnail_path):
            os.remove(thumbnail_path)

    db.execute('DELETE FROM items WHERE id = ?', (item_id,))
    db.commit()
    flash('项目已成功删除。')

    if request.form.get('next') == 'admin_dashboard':
        return redirect(url_for('admin_dashboard'))

    return redirect(url_for('index'))

@app.route('/change_password', methods=('GET', 'POST'))
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        error = None

        if not check_password_hash(g.user['password'], old_password):
            error = '旧密码不正确。'
        elif new_password != confirm_password:
            error = '新密码不匹配。'

        if error is None:
            db = get_db()
            db.execute(
                'UPDATE users SET password = ? WHERE id = ?',
                (generate_password_hash(new_password), g.user['id'])
            )
            db.commit()
            flash('密码已成功更新。')
            return redirect(url_for('index'))

        flash(error, 'error')

    return render_template('change_password.html')

@app.route('/delete_account', methods=('GET', 'POST'))
@login_required
def delete_account():
    if request.method == 'POST':
        password = request.form['password']
        if not check_password_hash(g.user['password'], password):
            flash('密码不正确。', 'error')
        else:
            db = get_db()
            items = db.execute('SELECT thumbnail FROM items WHERE owner = ?', (g.user['username'],)).fetchall()
            for item in items:
                if item['thumbnail']:
                    thumbnail_path = os.path.join(app.config['UPLOAD_FOLDER'], item['thumbnail'])
                    if os.path.exists(thumbnail_path):
                        os.remove(thumbnail_path)
            
            db.execute('DELETE FROM items WHERE owner = ?', (g.user['username'],))
            db.execute('DELETE FROM users WHERE id = ?', (g.user['id'],))
            db.commit()
            session.clear()
            flash('您的帐户已成功删除。')
            return redirect(url_for('index'))

    return render_template('delete_account.html')

@app.route('/update_method/<int:item_id>', methods=['POST'])
@login_required
def update_method(item_id):
    """Updates the method for a given item."""
    db = get_db()
    method = request.json['method']
    db.execute('UPDATE items SET method = ? WHERE id = ?', (method, item_id))
    db.commit()
    return jsonify({'success': True})

@app.route('/admin/settings/toggle_registration_approval', methods=['POST'])
@admin_required
def toggle_registration_approval():
    db = get_db()
    current_setting = db.execute("SELECT value FROM settings WHERE key = 'registration_approval'").fetchone()
    new_value = 'true' if current_setting and current_setting['value'] == 'false' else 'false'
    db.execute("UPDATE settings SET value = ? WHERE key = ?", (new_value, 'registration_approval'))
    db.commit()
    flash(f"注册审批已{'启用' if new_value == 'true' else '禁用'}。")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/users/approve/<int:user_id>', methods=['POST'])
@admin_required
def approve_user(user_id):
    db = get_db()
    db.execute("UPDATE users SET is_approved = 1 WHERE id = ?", (user_id,))
    db.commit()
    flash("用户已成功批准。")
    return redirect(url_for('admin_dashboard'))

# Admin routes
@app.route('/admin', methods=('GET', 'POST'))
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()

        if user is None or not user['is_admin']:
            error = '用户名不正确或不是管理员。'
        elif not check_password_hash(user['password'], password):
            error = '密码不正确。'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('admin_dashboard'))

        flash(error, 'error')

    return render_template('admin_login.html')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    db = get_db()
    users = db.execute('SELECT id, username, is_admin, is_approved FROM users').fetchall()
    items = db.execute('SELECT id, name, owner, method FROM items').fetchall()
    sharing_methods = db.execute('SELECT * FROM sharing_methods').fetchall()
    registration_approval_setting = db.execute("SELECT value FROM settings WHERE key = 'registration_approval'").fetchone()
    registration_approval = registration_approval_setting['value'] == 'true' if registration_approval_setting else False
    
    unapproved_users = [user for user in users if not user['is_approved']]

    return render_template('admin_dashboard.html', users=users, items=items, sharing_methods=sharing_methods, registration_approval=registration_approval, unapproved_users=unapproved_users)

@app.route('/admin/sharing_methods/add', methods=['POST'])
@admin_required
def add_sharing_method():
    name = request.form.get('name')
    if name:
        db = get_db()
        db.execute('INSERT INTO sharing_methods (name) VALUES (?)', (name,))
        db.commit()
        flash('分享方式已成功添加。')
    else:
        flash('名称为必填项。')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/sharing_methods/edit/<int:method_id>', methods=['POST'])
@admin_required
def edit_sharing_method(method_id):
    name = request.form.get('name')
    if name:
        db = get_db()
        old_method = db.execute('SELECT name FROM sharing_methods WHERE id = ?', (method_id,)).fetchone()
        if old_method:
            old_name = old_method['name']
            db.execute('UPDATE sharing_methods SET name = ? WHERE id = ?', (name, method_id))
            db.execute('UPDATE items SET method = ? WHERE method = ?', (name, old_name))
            db.commit()
            flash('分享方式已成功更新。')
    else:
        flash('名称为必填项。')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/sharing_methods/delete/<int:method_id>', methods=['POST'])
@admin_required
def delete_sharing_method(method_id):
    db = get_db()
    method = db.execute('SELECT name FROM sharing_methods WHERE id = ?', (method_id,)).fetchone()
    if not method:
        flash('未找到方式。')
        return redirect(url_for('admin_dashboard'))

    items_in_use = db.execute('SELECT COUNT(*) FROM items WHERE method = ?', (method['name'],)).fetchone()[0]
    if items_in_use > 0:
        flash(f'无法删除“{method["name"]}”，因为它正在被{items_in_use}个项目使用。', 'error')
    else:
        db.execute('DELETE FROM sharing_methods WHERE id = ?', (method_id,))
        db.commit()
        flash('分享方式已成功删除。')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reset_password/<int:user_id>', methods=('GET', 'POST'))
@admin_required
def admin_reset_password(user_id):
    db = get_db()
    user = db.execute('SELECT id, username FROM users WHERE id = ?', (user_id,)).fetchone()

    if user is None:
        flash('未找到用户。', 'error')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        error = None

        if new_password != confirm_password:
            error = '新密码不匹配。'

        if error is None:
            db.execute(
                'UPDATE users SET password = ? WHERE id = ?',
                (generate_password_hash(new_password), user_id)
            )
            db.commit()
            flash(f"用户“{user['username']}”的密码已成功更新。")
            return redirect(url_for('admin_dashboard'))

        flash(error, 'error')

    return render_template('admin_reset_password.html', user=user)

@app.route('/admin/delete_user/<int:user_id>', methods=('POST',))
@admin_required
def admin_delete_user(user_id):
    db = get_db()
    user = db.execute('SELECT username, is_admin FROM users WHERE id = ?', (user_id,)).fetchone()

    if user is None:
        flash('未找到用户。', 'error')
        return redirect(url_for('admin_dashboard'))

    if user['is_admin']:
        flash('无法删除管理员帐户。', 'error')
        return redirect(url_for('admin_dashboard'))

    items = db.execute('SELECT thumbnail FROM items WHERE owner = ?', (user['username'],)).fetchall()
    for item in items:
        if item['thumbnail']:
            thumbnail_path = os.path.join(app.config['UPLOAD_FOLDER'], item['thumbnail'])
            if os.path.exists(thumbnail_path):
                os.remove(thumbnail_path)
    
    db.execute('DELETE FROM items WHERE owner = ?', (user['username'],))
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    flash(f"用户“{user['username']}”已成功删除。")
    return redirect(url_for('admin_dashboard'))

@app.route('/download_excel')
def download_excel():
    """Fetches all items and returns them as an Excel file."""
    db = get_db()
    items = db.execute('SELECT * FROM items').fetchall()

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "分享清单"

    headers = ['名称', '所有者', '照片', '方式', '位置', '联系方式', '详情']
    ws.append(headers)

    for item in items:
        photo_exists = 'Yes' if item['thumbnail'] else 'No'
        ws.append([
            item['name'],
            item['owner'],
            photo_exists,
            item['method'],
            item['location'],
            item['contact'],
            item['details']
        ])

    excel_stream = io.BytesIO()
    wb.save(excel_stream)
    excel_stream.seek(0)

    filename = "分享清单.xlsx"

    return Response(
        excel_stream,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={'Content-Disposition': "attachment; filename*=UTF-8''{}".format(quote(filename))}
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
