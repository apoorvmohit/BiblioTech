from flask_sqlalchemy import SQLAlchemy
from app import app
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy(app)

#models

class User(db.Model):
    __tablename__ = 'user'
    u_id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(32), unique = True, nullable = False)
    passhash = db.Column(db.String(512), nullable = False)
    name = db.Column(db.String(64), nullable = False)
    is_admin = db.Column(db.Boolean, nullable = False, default = False)

    @property
    def password(self):
        raise AttributeError("Password is not readable")

    @password.setter
    def password(self, password):
        self.passhash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.passhash, password)

class Book(db.Model):
    __tablename__ = 'book'
    book_id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(64), nullable = False)
    content = db.Column(db.String(512), nullable = True)
    author = db.Column(db.String(64), nullable = False)
    create_date = db.Column(db.DateTime, nullable = False)
    status = db.Column(db.String(64), nullable = False)
    section_id = db.Column(db.Integer, db.ForeignKey('section.section_id'), nullable = False)

    #relationship
    issues = db.relationship('Issue', backref = 'book', lazy = True)
    requests = db.relationship('Requested', backref = 'book', lazy = True)

class Section(db.Model):
    __tablename__ = 'section'
    section_id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(64), nullable = False)
    description = db.Column(db.String(512), nullable = True)
    create_date = db.Column(db.Date, nullable = False)

    #relationship
    books = db.relationship('Book', backref = 'section', lazy = True)

class Issue(db.Model):
    __tablename__ = 'issue'
    issue_id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.u_id'), nullable = False)
    user_name = db.Column(db.String(64), nullable = False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.book_id'), nullable = False)
    book_name = db.Column(db.String(64), nullable = False)
    issue_date = db.Column(db.DateTime, nullable = False)

class Requested(db.Model):
    __tablename__ = 'request'
    request_id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.u_id'), nullable = False)
    user_name = db.Column(db.String(64), nullable = False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.book_id'), nullable = False)
    book_name = db.Column(db.String(64), nullable = False)
    request_date = db.Column(db.DateTime, nullable = False)


with app.app_context():
    db.create_all()

    # if admin exists, else create admin
    admin = User.query.filter_by(is_admin=True).first()
    if not admin:
        password_hash = generate_password_hash('admin')
        admin = User(username='admin', passhash=password_hash, name='Admin', is_admin=True)
        db.session.add(admin)
        db.session.commit()