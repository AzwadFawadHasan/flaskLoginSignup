from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_mysqldb import MySQL
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, validators
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.validators import DataRequired

app = Flask(__name__)

app.config['SECRET_KEY'] = 'mysecretkey'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'devuser'
app.config['MYSQL_PASSWORD'] = 'devuser'
app.config['MYSQL_PORT'] = 3306
app.config['MYSQL_DB'] = 'flaskuserauthentication'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class LoginForm(FlaskForm):
    email = StringField('Email', [validators.Email(), validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])
    submit = SubmitField('Login')

class SignupForm(FlaskForm):
    email = StringField('Email', [validators.Email(), validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])
    submit = SubmitField('Signup')

class User(UserMixin):
    def __init__(self, id, email, password):
        self.id = id
        self.email = email
        self.password = password

@login_manager.user_loader
def load_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE idusers = %s", (user_id,))
    user_data = cur.fetchone()
    cur.close()
    return User(id=user_data['idusers'], email=user_data['email'], password=user_data['password'])

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (form.email.data, hashed_password))
        mysql.connection.commit()
        cur.close()
        flash('Signed up successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (form.email.data,))
        user_data = cur.fetchone()
        cur.close()
        if user_data and check_password_hash(user_data['password'], form.password.data):
            user = User(id=user_data['idusers'], email=user_data['email'], password=user_data['password'])
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Login Unsuccessful. Check email and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return f'Hello, {current_user.email}! Welcome to your dashboard.'

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
