from flask import Flask, render_template, request, redirect, url_for, flash, session
from models import Requested, db, User, Book, Section, Issue
from app import app
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date


def auth_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' in session:
            return func(*args, **kwargs)
        else:
            flash('Please login to continue')
            return redirect(url_for('login'))
    return inner

def admin_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to continue')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user.is_admin:
            flash('You are not authorized to access this page')
            return redirect(url_for('index'))
        return func(*args, **kwargs)
    return inner

@app.route('/')
@auth_required
def index():
    user = User.query.get(session['user_id'])
    if user.is_admin:
        return redirect(url_for('admin'))
    
    sections = Section.query.all()

    sname = request.args.get('sname') or ''
    bname = request.args.get('bname') or ''

    if sname:
        sections = Section.query.filter(Section.name.ilike(f'%{sname}%')).all()

    return render_template('index.html', sections=sections, sname=sname, bname=bname)

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        flash('Please fill out all fields')
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=username).first()
    
    if not user:
        flash('Username does not exist')
        return redirect(url_for('login'))
    
    if not user.check_password(password):
        flash('Incorrect password')
        return redirect(url_for('login'))

    session['user_id'] = user.u_id
    return redirect(url_for('index'))

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register_post():
    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    name = request.form.get('name')

    if not username or not password or not confirm_password:
        flash('Please fill out all fields')
        return redirect(url_for('register'))
    
    if password != confirm_password:
        flash('Passwords do not match')
        return redirect(url_for('register'))
    
    user = User.query.filter_by(username=username).first()

    if user:
        flash('Username already exists')
        return redirect(url_for('register'))
    
    
    new_user = User(username=username, password=password, name=name)
    
    db.session.add(new_user)
    db.session.commit()
    flash('User Created')
    return redirect(url_for('login'))

@app.route('/profile')
@auth_required
def profile():
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

@app.route('/profile', methods=['POST'])
@auth_required
def profile_post():
    username = request.form.get('username')
    cpassword = request.form.get('cpassword')
    password = request.form.get('password')
    name = request.form.get('name')

    if not username or not cpassword or not password:
        flash('Please fill out all the required fields')
        return redirect(url_for('profile'))
    
    user = User.query.get(session['user_id'])
    if not check_password_hash(user.passhash, cpassword):
        flash('Incorrect password')
        return redirect(url_for('profile'))
    
    if username != user.username:
        new_username = User.query.filter_by(username=username).first()
        if new_username:
            flash('Username already exists')
            return redirect(url_for('profile'))
    
    new_password_hash = generate_password_hash(password)
    user.username = username
    user.passhash = new_password_hash
    user.name = name
    db.session.commit()
    flash('Profile updated successfully')
    return redirect(url_for('profile'))

@app.route('/admin')
@admin_required
def admin():
    s_count = Section.query.count()
    b_count = Book.query.count()
    u_count = User.query.count()-1
    r_count = Requested.query.count()
    i_count = Issue.query.count()
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        flash('You are not allowed to view this page')
        return redirect(url_for('index'))
    else:
        return render_template('admin.html', user = user, 
                               sections = Section.query.all(), 
                               section_count = s_count,
                               book_count = b_count,
                               user_count = u_count,
                               request_count = r_count,
                               issue_count = i_count)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/section/add')
@admin_required
def add_section():
    return render_template('/Sections/add.html') 

@app.route('/section/add', methods=['POST'])
@admin_required
def add_section_post():
    name = request.form.get('name')
    description = request.form.get('description')
    date = request.form.get('date')

    if not name:
        flash('Please fill out all fields')
        return redirect(url_for('add_section'))
    
    if len(description) > 256:
        flash('Please add description within 256 characters')
        return redirect(url_for('add_section'))
    
    section = Section(name=name, description = description, create_date = datetime.now())
    db.session.add(section)
    db.session.commit()

    flash('Section added successfully')
    return redirect(url_for('admin'))

@app.route('/section/<int:id>/show')
@admin_required
def show_section(id):
    return render_template('Sections/manage.html', user = User.query.get(session['user_id']),section=Section.query.get(id))

@app.route('/section/<int:id>/edit')
@admin_required
def edit_section(id):
    section = Section.query.get(id)
    if not section:
        flash('Section does not exist')
        return redirect(url_for('admin'))
    return render_template('Sections/edit.html', user = User.query.get(session['user_id']),section=Section.query.get(id))

@app.route('/section/<int:id>/edit', methods=['POST'])
@admin_required
def edit_section_post(id):
    section = Section.query.get(id)
    if not section:
        flash('Category does not exist')
        return redirect(url_for('admin'))
    name = request.form.get('name')
    description = request.form.get('description')
    if not name:
        flash('Please fill out all fields')
        return redirect(url_for('edit_section', id=id))
    section.name = name
    section.description = description
    db.session.commit()
    flash('Category updated successfully')
    return redirect(url_for('admin'))

@app.route('/section/<int:id>/delete')
@admin_required
def delete_section(id):
    section = Section.query.get(id)
    if not section:
        flash('Section does not exist')
        return redirect(url_for('admin'))
    return render_template('Sections/delete.html', user = User.query.get(session['user_id']),section=Section.query.get(id))

@app.route('/section/<int:id>/delete', methods=['POST'])
@admin_required
def delete_section_post(id):
    section = Section.query.get(id)
    if not section:
        flash('Section does not exist')
        return redirect(url_for('admin'))
    db.session.delete(section)
    db.session.commit()

    flash('Section deleted successfully')
    return redirect(url_for('admin'))

@app.route('/Sections/manage')
@admin_required
def manage_section():
    return render_template('Sections/manage.html', sections = Section.query.all())

@app.route('/Books/manage')
@admin_required
def manage_book():
    return render_template('Books/manage.html', books = Book.query.all())

@app.route('/manage-requests')
@admin_required
def manage_requests():
    return render_template('manage_request.html', requests = Requested.query.all())

@app.route('/manage-issues')
@admin_required
def manage_issues():
    return render_template('manage_issue.html', issues = Issue.query.all())

@app.route('/books/add')
@admin_required
def add_book():
    return render_template('/Books/add.html') 

@app.route('/books/add', methods=['POST'])
@admin_required
def add_section_book():
    name = request.form.get('name')
    content = request.form.get('content')
    author = request.form.get('author')
    section = request.form.get('section')

    if not name:
        flash('Please fill out all fields')
        return redirect(url_for('add_book'))
    
    if len(content) > 256:
        flash('Please add content within 256 characters')
        return redirect(url_for('add_book'))
    
    
    book = Book(name=name, author = author, content = content, create_date = date.today(), status = "In Stock", section_id = section)
    db.session.add(book)
    db.session.commit()

    flash('Book added successfully')
    return redirect(url_for('admin'))

@app.route('/books/<int:id>/edit')
@admin_required
def edit_book(id):
    book = Book.query.get(id)
    if not book:
        flash('Book does not exist')
        return redirect(url_for('admin'))
    return render_template('Books/edit.html', user = User.query.get(session['user_id']),book=Book.query.get(id))

@app.route('/books/<int:id>/edit', methods=['POST'])
@admin_required
def edit_book_post(id):
    book = Book.query.get(id)
    if not book:
        flash('Books does not exist')
        return redirect(url_for('admin'))
    name = request.form.get('name')
    content = request.form.get('content')
    author = request.form.get('author')
    section = request.form.get('section')
    if not name:
        flash('Please fill out all fields')
        return redirect(url_for('edit_book', id=id))
    book.name = name
    book.content = content
    book.author = author
    book.section_id = section
    db.session.commit()
    flash('Book updated successfully')
    return redirect(url_for('admin'))

@app.route('/books/<int:id>/delete')
@admin_required
def delete_book(id):
    book = Book.query.get(id)
    if not book:
        flash('Book does not exist')
        return redirect(url_for('admin'))
    return render_template('Books/delete.html', user = User.query.get(session['user_id']),book=Book.query.get(id))

@app.route('/books/<int:id>/delete', methods=['POST'])
@admin_required
def delete_book_post(id):
    book = Book.query.get(id)
    if not book:
        flash('Book does not exist')
        return redirect(url_for('admin'))
    db.session.delete(book)
    db.session.commit()

    flash('Book deleted successfully')
    return redirect(url_for('admin'))

@app.route('/<int:id>/request')
@auth_required
def request_book(id):
    book = Book.query.get(id)
    if not book:
        flash('Book does not exist')
        return redirect(url_for('index'))
    return render_template('user_request.html', user = User.query.get(session['user_id']),book=Book.query.get(id))

@app.route('/<int:id>/request', methods=['POST'])
@auth_required
def request_book_post(id):
    book = Book.query.get(id)
    user = User.query.get(session['user_id'])

    request_count = Requested.query.filter_by(user_id = session['user_id']).count()

    if request_count >= 5:
        flash('You cannot request more than 5 books')
        return redirect(url_for('index'))

    if not book:
        flash('Book does not exist')
        return redirect(url_for('index'))
    
    
    book.status = "Requested"
    request = Requested(user_id = user.u_id, user_name = user.username, book_id = book.book_id, book_name = book.name, request_date = datetime.now())
    db.session.add(request)
    db.session.commit()
    flash('Book requested successfully')
    return redirect(url_for('index'))

@app.route('/<int:id>/issue')
@admin_required
def issue(id):
    request = Requested.query.get(id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('index'))
    return render_template('issue.html', user = User.query.get(session['user_id']),request=Requested.query.get(id))

@app.route('/<int:id>/issue', methods=['POST'])
@admin_required
def issue_post(id):
    request = Requested.query.get(id)
    book = Book.query.get(request.book_id)
    if not request:
        flash('Book does not exist')
        return redirect(url_for('index'))
    
    issue = Issue(user_id = request.user_id, user_name = request.user_name, book_id = request.book_id, book_name = request.book_name, issue_date = datetime.now())
    db.session.add(issue)
    book.status = 'Issued'
    db.session.delete(request)
    db.session.commit()
    flash('Book issued successfully')
    return redirect(url_for('index'))

@app.route('/<int:id>/decline')
@admin_required
def decline(id):
    request = Requested.query.get(id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('admin'))
    return render_template('decline.html', user = User.query.get(session['user_id']),request=Requested.query.get(id))

@app.route('/<int:id>/decline', methods=['POST'])
@admin_required
def decline_post(id):
    request = Requested.query.get(id)
    book = Book.query.get(request.book_id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('admin'))
    db.session.delete(request)
    book.status = 'In Stock'
    db.session.commit()

    flash('Request declined successfully')
    return redirect(url_for('admin'))

@app.route('/<int:id>/revoke')
@admin_required
def revoke(id):
    issue = Issue.query.get(id)
    if not issue:
        flash('Issue does not exist')
        return redirect(url_for('admin'))
    return render_template('revoke.html', user = User.query.get(session['user_id']),issue=Issue.query.get(id))

@app.route('/<int:id>/revoke', methods=['POST'])
@admin_required
def revoke_post(id):
    issue = Issue.query.get(id)
    book = Book.query.get(issue.book_id)
    if not issue:
        flash('Issue does not exist')
        return redirect(url_for('admin'))
    db.session.delete(issue)
    book.status = 'In Stock'
    db.session.commit()

    flash('Issue Revoked successfully')
    return redirect(url_for('admin'))

@app.route('/my-books')
@auth_required
def my_books():
    issues = Issue.query.filter_by(user_id = session['user_id']).all()
    requests = Requested.query.filter_by(user_id = session['user_id']).all()
    return(render_template('my_books.html',issues = issues, requests = requests))

@app.route('/<int:id>/return')
@auth_required
def return_book(id):
    issue = Issue.query.get(id)
    if not issue:
        flash('Issue does not exist')
        return redirect(url_for('index'))
    return render_template('return.html', user = User.query.get(session['user_id']),issue=Issue.query.get(id))

@app.route('/<int:id>/return', methods=['POST'])
@auth_required
def return_book_post(id):
    issue = Issue.query.get(id)
    book = Book.query.get(issue.book_id)
    if not issue:
        flash('Issue does not exist')
        return redirect(url_for('index'))
    db.session.delete(issue)
    book.status = 'In Stock'
    db.session.commit()

    flash('Book returned successfully')
    return redirect(url_for('index'))

@app.route('/<int:id>/cancel')
@auth_required
def cancel_book(id):
    requested = Requested.query.get(id)
    if not requested:
        flash('Request does not exist')
        return redirect(url_for('index'))
    return render_template('cancel.html', user = User.query.get(session['user_id']),requested=Requested.query.get(id))

@app.route('/<int:id>/cancel', methods=['POST'])
@auth_required
def cancel_book_post(id):
    requested = Requested.query.get(id)
    book = Book.query.get(requested.book_id)
    if not requested:
        flash('Request does not exist')
        return redirect(url_for('index'))
    db.session.delete(requested)
    book.status = 'In Stock'
    db.session.commit()

    flash('Request cancelled successfully')
    return redirect(url_for('index'))

@app.route('/read')
@auth_required
def read():
    return 'book content'