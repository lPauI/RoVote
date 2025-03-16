from flask import Flask, render_template, redirect, url_for
from flask_wtf import CSRFProtect, FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, ValidationError
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

from dotenv import load_dotenv
from os import getenv
from bcrypt import hashpw, gensalt, checkpw

import re
import os

from extract_ci import find_cnp_from_ci

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = getenv('FLASK_SECRET_KEY')
csrf = CSRFProtect(app)

mysql_user = getenv('MYSQL_USER')
mysql_password = getenv('MYSQL_PASSWORD')
mysql_host = getenv('MYSQL_HOST')
mysql_database = getenv('MYSQL_DATABASE')

app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{mysql_user}:{mysql_password}@{mysql_host}/{mysql_database}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

def validate_cnp(form, field):
    pattern = re.compile(r'^[1-6]\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(?:(?!999)\d{3}|999)\d{3}$')
    if not pattern.fullmatch(field.data):
        raise ValidationError("CNP invalid.")


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    cnp = db.Column(db.String(13), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)


class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    ci_image = FileField('CI Image', validators=[FileAllowed(['jpg', 'jpeg', 'png'], 'Doar imagini!')])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


@app.route('/')
def home():
    return render_template('index.html')


@app.route("/auth/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error = None
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        
        user = Users.query.filter_by(email=email).first()
        
        if not user:
            error = "Email-ul nu a fost gasit."
            return render_template('auth/login.html', form=form, error=error)
        
        if not checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            error = "Parola este invalida."
            return render_template('auth/login.html', form=form, error=error)
            
        return render_template("index.html")
    return render_template('auth/login.html', form=form, error=error)


@app.route('/auth/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    
    if form.validate_on_submit():
        if form.ci_image.data:
            file = form.ci_image.data
            filename = secure_filename(file.filename)
            upload_folder = os.path.join('static', 'uploads')
            os.makedirs(upload_folder, exist_ok=True)
            temp_path = os.path.join(upload_folder, filename)
            file.save(temp_path)
            
            extracted_cnp = find_cnp_from_ci(temp_path)
            if extracted_cnp == 'CNP was not found':
                form.ci_image.errors.append("CNP-ul nu a putut fi extras din imaginea CI.")
                return render_template('auth/register.html', form=form)
        
        else:
            form.ci_image.errors.append("Imaginea CI este necesară.")
            return render_template('auth/register.html', form=form)
        
        email = form.email.data
        password = form.password.data
        cnp = extracted_cnp
        
        password = hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')

        new_user = Users(email=email, password=password, cnp=cnp)
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('home'))
    
    return render_template('auth/register.html', form=form)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    app.run(host='0.0.0.0', port=5000, debug=True)
