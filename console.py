from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime

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

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'signin'
login_manager.login_message_category = 'info'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

class Card(db.Model):
    id = db.Column(db.Integer, primary_key=True)
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

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def home():
    cards = Card.query.all()
    return render_template('project.html', cards=cards)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '')

        if not all([username, email, phone, password]):
            flash('All fields are required', 'danger')
        elif len(username) < 3:
            flash('Username must be at least 3 characters', 'danger')
        elif len(password) < 6:
            flash('Password must be at least 6 characters', 'danger')
        elif User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
        else:
            try:
                is_admin = User.query.count() == 0
                new_user = User(
                    username=username,
                    email=email,
                    phone=phone,
                    password_hash=generate_password_hash(password),
                    is_admin=is_admin
                )
                db.session.add(new_user)
                db.session.commit()
                flash('Registration successful! You can now log in.', 'success')
                return redirect(url_for('signin'))
            except:
                db.session.rollback()
                flash('Registration failed. Try again.', 'danger')
    return render_template('register.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('admin_dashboard' if user.is_admin else 'user_page'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('signin.html')

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
    if request.method == 'POST':
        try:
            name = request.form.get('name', '').strip()
            email = request.form.get('email', '').strip()
            phone = request.form.get('phone', '').strip()
            subject = request.form.get('subject', '').strip()
            message = request.form.get('message', '').strip()

            if not all([name, email, subject, message]):
                flash('All required fields must be filled', 'danger')
                return redirect(url_for('contact_us'))

            new_contact = Contact(
                name=name,
                email=email,
                phone=phone if phone else None,
                subject=subject,
                message=message
            )

            db.session.add(new_contact)
            db.session.commit()

            flash('Thank you for your message! We\'ll get back to you within 24 hours.', 'success')
            return redirect(url_for('contact_us'))

        except:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'danger')
            return redirect(url_for('contact_us'))
    return render_template('contact.html')

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied. Admin only.', 'danger')
        return redirect(url_for('home'))

    users = User.query.all()
    cards = Card.query.all()
    contacts = Contact.query.order_by(Contact.created_at.desc()).all()

    return render_template('admin.html', users=users, cards=cards, contacts=contacts)

@app.route('/admin/mark_contact_read/<int:contact_id>', methods=['POST'])
@login_required
def mark_contact_read(contact_id):
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))

    contact = Contact.query.get_or_404(contact_id)
    contact.is_read = True
    db.session.commit()
    flash('Contact marked as read.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_contact/<int:contact_id>', methods=['POST'])
@login_required
def delete_contact(contact_id):
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
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
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))

    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('Cannot delete yourself.', 'danger')
        return redirect(url_for('admin_dashboard'))

    db.session.delete(user)
    db.session.commit()
    flash(f'{user.username} deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/make_admin/<int:user_id>', methods=['POST'])
@login_required
def make_admin(user_id):
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))

    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()
    flash(f'{user.username} is now an admin.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/add_card', methods=['GET', 'POST'])
@login_required
def add_card():
    if not current_user.is_admin:
        flash('Admin access only.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        description = request.form.get('description', '')
        file = request.files.get('image')

        if not file or file.filename == '':
            flash('Image is required.', 'danger')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            new_card = Card(image_filename=filename, description=description)
            db.session.add(new_card)
            db.session.commit()
            flash('Card added successfully!', 'success')
            return redirect(url_for('admin_dashboard'))

    return render_template('add_card.html')

@app.route('/admin/delete_card/<int:card_id>', methods=['POST'])
@login_required
def delete_card(card_id):
    if not current_user.is_admin:
        flash('Admin access only.', 'danger')
        return redirect(url_for('home'))

    card = Card.query.get_or_404(card_id)
    try:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], card.image_filename)
        if os.path.exists(image_path):
            os.remove(image_path)
    except:
        pass

    db.session.delete(card)
    db.session.commit()
    flash('Card deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Database ready.")
    app.run(debug=True)
