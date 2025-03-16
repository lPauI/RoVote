from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_wtf import CSRFProtect, FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, ValidationError
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from email.message import EmailMessage

from dotenv import load_dotenv
from os import getenv
from bcrypt import hashpw, gensalt, checkpw

import smtplib
import re
import os
import random

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
    

def validate_otp(form, field):
    return ValidationError("OTP invalid.")


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    cnp = db.Column(db.String(13), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    voted_president = db.Column(db.Integer, db.ForeignKey('presidents.id'), nullable=True)


class Presidents(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)


class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    ci_image = FileField('CI Image', validators=[FileAllowed(['jpg', 'jpeg', 'png'], 'Doar imagini!')])
    otp = StringField('OTP Code', validators=[validate_otp])
    send_otp = SubmitField('Send OTP')
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


@app.route('/')
def home():
    presidents = Presidents.query.all()
    is_logged = 'user_id' in session
    
    has_voted = False
    if is_logged:
        user = Users.query.get(session['user_id'])
        has_voted = user.voted_president is not None
    
    return render_template('index.html', presidents=presidents, is_logged=is_logged, has_voted=has_voted)


@app.route("/auth/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        
        # Find user by email
        user = Users.query.filter_by(email=email).first()
        
        # Check if user exists and password is correct
        if user and checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            # Set up session
            session['user_id'] = user.id
            session['email'] = user.email
            
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password. Please try again.', 'error')
    
    return render_template('auth/login.html', form=form)


@app.route('/logout')
def logout():
    # Clear the user session
    session.clear()
    flash('You have been successfully logged out.', 'success')
    return redirect(url_for('home'))


@app.route('/auth/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    
    if form.validate_on_submit():
        email = form.email.data
        
        if form.send_otp.data:
            otp = random.randint(100000, 999999)
            
            subject = "OTP from Code4Gov"
            body = f"Your OTP is {otp}\n\nYou have 15 minutes to use this code."
            
            msg = EmailMessage()
            msg.set_content(body)
            msg["Subject"] = subject
            msg["From"] = getenv("SMTP_EMAIL")
            msg["To"] = email
            
            new_otp = OTP(email=email, otp=otp)
            db.session.add(new_otp)
            db.session.commit()
            
            try:
                with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                    server.login(getenv("SMTP_EMAIL"), getenv("SMTP_PASSWORD"))
                    server.send_message(msg)
                    
            except Exception as e:
                flash(f"Error sending OTP: {str(e)}", "error")
                return render_template('auth/register.html', form=form)
            
            flash("OTP sent successfully!", "success")
            return render_template('auth/register.html', form=form)

        
        if form.submit.data:
            existing_email = Users.query.filter_by(email=email).first()
            if existing_email:
                flash("Există deja un cont asociat cu acest email.", "error")
                return render_template('auth/register.html', form=form)
            
            otp = form.otp.data
            
            otp_obj = OTP.query.filter_by(email=email).order_by(OTP.created_at.desc()).first()
            
            if otp_obj.otp != otp:
                form.otp.errors.append("OTP-ul este invalid.")
                return render_template('auth/register.html', form=form)
            
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
            
            existing_cnp = Users.query.filter_by(cnp=extracted_cnp).first()
            if existing_cnp:
                flash("Există deja un cont asociat cu acest CNP.", "error")
                return render_template('auth/register.html', form=form)
            
            password = form.password.data
            cnp = extracted_cnp
            
            password = hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')

            new_user = Users(email=email, password=password, cnp=cnp)
            db.session.add(new_user)
            db.session.commit()
            
            flash("Contul a fost creat cu succes! Acum vă puteți autentifica.", "success")
            return redirect(url_for('login'))
    
    return render_template('auth/register.html', form=form)


@app.route('/vote/<int:president_id>', methods=['GET', 'POST'])
def vote(president_id):
    if 'user_id' not in session:
        flash('Trebuie să fiți autentificat pentru a vota.', 'error')
        return redirect(url_for('login'))
    
    president = Presidents.query.get_or_404(president_id)
    
    user = Users.query.get(session['user_id'])
    
    if user.voted_president is not None:
        flash('Ați ales deja un președinte.', 'error')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        user.voted_president = president_id
        db.session.commit()
        
        flash(f'Ați votat cu succes pentru {president.name}!', 'success')
        return redirect(url_for('home'))
    
    return render_template('vote.html', president=president)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    app.run(host='0.0.0.0', port=5000, debug=True)
