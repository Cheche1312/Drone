from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, TextAreaField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
import os
from datetime import datetime
import uuid

# --- App Setup ---
app = Flask(__name__)
app.secret_key = 'your-secret-key'

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "users.sqlite3")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_BINDS'] = {
    'contacts': f'sqlite:///{os.path.join(basedir, "contacts.sqlite3")}'
}

db = SQLAlchemy(app)

UPLOAD_FOLDER = os.path.join(basedir, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'signin'
login_manager.login_message_category = 'info'

# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

class Card(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    image_filename = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)

class Contact(db.Model):
    __bind_key__ = 'contacts'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20))
    subject = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

# --- Forms ---
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('Username already exists.')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('Email already exists.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone')
    subject = StringField('Subject', validators=[DataRequired()])
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send Message')

class CardForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[DataRequired()])
    image = FileField('Image', validators=[
        FileRequired(),
        FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')
    ])
    submit = SubmitField('Add Card')

# --- User Loader ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- Routes ---
@app.route('/')
def home():
    cards = Card.query.all()
    return render_template('project.html', cards=cards)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            is_admin = User.query.count() == 0
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                phone=form.phone.data,
                password_hash=generate_password_hash(form.password.data),
                is_admin=is_admin
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Registered successfully!', 'success')
            return redirect(url_for('signin'))
        except:
            db.session.rollback()
            flash('Registration failed.', 'danger')
    return render_template('register.html', form=form)

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            flash('Welcome back!', 'success')
            return redirect(url_for('admin_dashboard' if user.is_admin else 'user_page'))
        flash('Invalid login.', 'danger')
    return render_template('signin.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/user')
@login_required
def user_page():
    cards = Card.query.all()
    return render_template('project.html', user=current_user, cards=cards)

@app.route('/contact', methods=['GET', 'POST'])
def contact_us():
    form = ContactForm()
    if form.validate_on_submit():
        new_contact = Contact(
            name=form.name.data,
            email=form.email.data,
            phone=form.phone.data,
            subject=form.subject.data,
            message=form.message.data
        )
        db.session.add(new_contact)
        db.session.commit()
        flash('Message sent successfully!', 'success')
        return redirect(url_for('contact_us'))
    return render_template('contact.html', form=form)

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))
    users = User.query.all()
    cards = Card.query.all()
    contacts = Contact.query.order_by(Contact.created_at.desc()).all()
    return render_template('admin.html', users=users, cards=cards, contacts=contacts)

@app.route('/admin/add_card', methods=['GET', 'POST'])
@login_required
def add_card():
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))
    form = CardForm()
    if form.validate_on_submit():
        file = form.image.data
        filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        new_card = Card(title=form.title.data, image_filename=filename, description=form.description.data)
        db.session.add(new_card)
        db.session.commit()
        flash('Card added!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('add_card.html', form=form)

@app.route('/admin/delete_card/<int:card_id>', methods=['POST'])
@login_required
def delete_card(card_id):
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))
    card = Card.query.get_or_404(card_id)
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], card.image_filename))
    except Exception:
        pass
    db.session.delete(card)
    db.session.commit()
    flash('Card deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/mark_contact_read/<int:contact_id>', methods=['POST'])
@login_required
def mark_contact_read(contact_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))
    contact = Contact.query.get_or_404(contact_id)
    contact.is_read = True
    db.session.commit()
    flash('Marked as read.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_contact/<int:contact_id>', methods=['POST'])
@login_required
def delete_contact(contact_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))
    contact = Contact.query.get_or_404(contact_id)
    db.session.delete(contact)
    db.session.commit()
    flash('Contact deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot delete yourself.', 'danger')
        return redirect(url_for('admin_dashboard'))
    db.session.delete(user)
    db.session.commit()
    flash('User deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/make_admin/<int:user_id>', methods=['POST'])
@login_required
def make_admin(user_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))
    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()
    flash('User promoted to admin.', 'success')
    return redirect(url_for('admin_dashboard'))

# --- Init ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Databases created.")
    app.run(debug=True)

