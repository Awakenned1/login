from flask import Flask, request, session, flash, redirect, url_for, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize the Flask app and configure the database
app = Flask(__name__)
app.config['SECRET_KEY'] = 'simple'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///studentManDB.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# Define the User model with UserMixin for authentication
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def add_user(username, password):
    # Check if user already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user is None:
        # Create a new user instance
        new_user = User(username=username)
        new_user.set_password(password)  # Set password hash
        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()
        print(f"User {username} added successfully.")
    else:
        print(f"User {username} already exists.")


# Create all tables within application context
with app.app_context():
    db.create_all()
    add_user('nami_d', 'password@01')  # Adding new user record upon


# index routing
@app.route('/')
def index():
    return render_template('login.html')


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user is None:
            # Create a new user instance
            new_user = User(username=username)
            new_user.set_password(password)  # Set password hash
            # Add the new user to the database
            db.session.add(new_user)
            db.session.commit()
            flash('User added successfully.', 'success')
            return redirect(url_for('login'))  # Redirect to login page
        else:
            flash('Username already exists.', 'danger')
    return render_template('signup.html')


# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
