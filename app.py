from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, jsonify
from flask_mysqldb import MySQL
from flask_wtf.file import DataRequired
from wtforms import Form, StringField, PasswordField, validators, SubmitField, SelectField
from wtforms.fields import EmailField, DateTimeLocalField  
from passlib.hash import pbkdf2_sha256
from keras.preprocessing import image as i1
from keras import models
from functools import wraps           
from flask_mail import Mail
from secrets import token_hex
import os, string, random, cv2, pdfkit, smtplib, uuid, time, hmac
from PIL import Image
import numpy as np
import logging
from logging.handlers import RotatingFileHandler
from collections import defaultdict

app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'malariadb'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['INITIAL_FILE_UPLOADS'] = os.path.join('static', 'img', 'uploads')
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT']= 587  
app.config['MAIL_USE_TLS']= True
app.config['MAIL_USERNAME']= os.environ.get('EMAIL_USER') 
app.config['MAIL_PASSWORD']= os.environ.get('EMAIL_PASS')

mail = Mail(app)
model = models.load_model('./model.h5')
mysql = MySQL(app)


# Configure logging
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/malaria.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Malaria detection startup')

# Rate limiting setup
login_attempts = defaultdict(list)
MAX_ATTEMPTS = 5
ATTEMPT_WINDOW = 300  # 5 minutes in seconds

def is_rate_limited(username):
    now = time.time()
    attempts = login_attempts[username]
    # Remove old attempts
    attempts = [attempt for attempt in attempts if now - attempt < ATTEMPT_WINDOW]
    login_attempts[username] = attempts
    return len(attempts) >= MAX_ATTEMPTS

def add_login_attempt(username):
    login_attempts[username].append(time.time())

# Session timeout middleware
@app.before_request
def check_session_timeout():
    if 'logged_in' in session:
        now = int(time.time())
        last_active = session.get('last_activity', now)
        timeout = 30 * 60  # 30 minutes timeout
        
        if now - last_active > timeout:
            session.clear()
            flash('Session expired. Please login again.', 'danger')
            return redirect(url_for('login'))
            
        session['last_activity'] = now

def validate_image_file(file):
    if not file:
        return False, "No file uploaded"
    
    # Check if file has an allowed extension
    if not allowed_file(file.filename):
        return False, "Only .png, .jpg, .jpeg file extensions allowed"
    
    try:
        # Check file size (max 5MB)
        file_content = file.read()
        if len(file_content) > 5 * 1024 * 1024:  # 5MB in bytes
            return False, "File size too large. Maximum size is 5MB"
        
        # Reset file pointer after reading
        file.seek(0)
        
        # Try to open the image to verify it's valid
        img = Image.open(file)
        img.verify()
        
        return True, None
    except Exception as e:
        return False, f"Invalid image file: {str(e)}"

@app.route("/")
def index():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

def allowed_file(filename):
 return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def predict_label(img_path):
    # Load and preprocess the image
    i = cv2.imread(img_path)
    resized = cv2.resize(i, (224, 224))  # Match model input
    i = i1.img_to_array(resized) / 255.0
    i = i.reshape(1, 224, 224, 3)

    # Predict
    result = model.predict(i)
    prob = float(result[0][0]) * 100  # Single sigmoid output
    
    app.logger.info(f'Prediction raw: {result}, Probability: {prob:.2f}%')

    threshold = 10
    if prob > threshold:
        classes = ['Uninfected', 'Infected']
        pred = classes[1] if prob >= 50 else classes[0]
        return pred, round(prob, 2)
    else:
        return 'Invalid Image', 0



# User Registration Form Class
class RegisterForm(Form):
    name = StringField('Full Name', [
        validators.Length(min=3, max=50),
        validators.DataRequired()
    ])
    speciality = StringField('Speciality', [validators.DataRequired()])
    cnic = StringField('CNIC', [
        validators.Length(min=5, max=20),
        validators.DataRequired()
    ])
    username = StringField('Username', [
        validators.Length(min=4, max=25),
        validators.DataRequired()
    ])
    email = EmailField('Email Address', [
        validators.Length(min=6, max=50),
        validators.DataRequired(),
        validators.Email()
    ])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.Length(min=8, message="Password must be at least 8 characters long"),
        validators.Regexp(r'.*[A-Z].*', message="Password must contain at least one uppercase letter"),
        validators.Regexp(r'.*[a-z].*', message="Password must contain at least one lowercase letter"),
        validators.Regexp(r'.*[0-9].*', message="Password must contain at least one number"),
        validators.Regexp(r'.*[!@#$%^&*(),.?":{}|<>].*', message="Password must contain at least one special character"),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

# Forgot Password Form Class
class ForgotForm(Form):
    email = EmailField('Email Address',[validators.DataRequired(),validators.Email()])

class PasswordResetForm(Form):
    password = PasswordField('Password',[validators.DataRequired(),validators.Length(min=6,max=50),
                                        validators.EqualTo('confirm',message='Password do not match')])
    confirm = PasswordField('Confirm Password',[validators.DataRequired()])

# user register
@app.route('/register',methods=['GET','POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data.lower()
        username = form.username.data.lower()
        speciality = form.speciality.data
        cnic = form.cnic.data
        
        # Generate a unique salt for this user
        salt = token_hex(16)
        # Hash password with salt using pbkdf2
        password = pbkdf2_sha256.using(rounds=350000).hash(str(form.password.data))

        cur = mysql.connection.cursor()
        try:
            # Check for existing users
            result1 = cur.execute("SELECT username FROM user WHERE username=%s",[username])
            result2 = cur.execute("SELECT email FROM user WHERE email=%s",[email])
            result3 = cur.execute("SELECT cnic FROM user WHERE cnic=%s",[cnic])

            if result1 > 0:
                flash("Username already exists",'danger')
                return render_template('register.html',form=form)
            elif result2 > 0:
                flash("An account with this email already exists",'danger')
                return render_template('register.html',form=form)
            elif result3 > 0:
                flash("An account with this CNIC already exists",'danger')
                return render_template('register.html',form=form)
            
            # Get pending type_id from user_types
            cur.execute("SELECT type_id FROM user_types WHERE type_name='Pending'")
            pending_type = cur.fetchone()
            if not pending_type:
                flash("Error in user type configuration",'danger')
                return render_template('register.html',form=form)
                
            pending_type_id = pending_type['type_id']
            
            # Store the salt and hashed password
            cur.execute("""
                INSERT INTO user(name,cnic,speciality,email,username,password,salt,user_type) 
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
            """, (name,cnic,speciality,email,username,password,salt,pending_type_id))
            
            mysql.connection.commit()
            flash("Your registration request has been sent",'success')
            return redirect(url_for('login'))

        except Exception as e:
            app.logger.error(f"Registration error: {str(e)}")
            flash("Error during registration",'danger')
            return render_template('register.html',form=form)
        finally:
            cur.close()
                
    return render_template('register.html',form=form)

# User Login
@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].lower()
        password_candidate = request.form['password']
        
        if not username or not password_candidate:
            flash('Please enter both username and password', 'danger')
            return render_template('login.html')
        
        # Check rate limiting
        if is_rate_limited(username):
            flash('Too many login attempts. Please try again later.', 'danger')
            return render_template('login.html')
            
        try:
            cur = mysql.connection.cursor()
            result = cur.execute("""
                SELECT user.*, user_types.type_name 
                FROM user 
                INNER JOIN user_types ON user.user_type = user_types.type_id 
                WHERE LOWER(username) = %s
            """, [username])

            if result > 0:
                data = cur.fetchone()
                stored_password = data['password']
                
                # Verify password using constant-time comparison
                if pbkdf2_sha256.verify(password_candidate, stored_password):
                    # Reset login attempts on successful login
                    login_attempts[username] = []
                    
                    if data['type_name'] == 'Admin':
                        session.clear()
                        session['logged_in'] = True
                        session['username'] = username
                        session['user_type'] = 1
                        session['id'] = data['id']
                        session['last_activity'] = int(time.time())
                        session['csrf_token'] = token_hex(32)
                        app.logger.info(f'Admin login successful: {username}')
                        flash('You are now logged in','success')
                        return redirect(url_for('admin'))
                    elif data['type_name'] == 'Physician':
                        session.clear()
                        session['logged_in'] = True
                        session['username'] = username
                        session['user_type'] = 0
                        session['id'] = data['id']
                        session['last_activity'] = int(time.time())
                        session['csrf_token'] = token_hex(32)
                        app.logger.info(f'Physician login successful: {username}')
                        flash('You are now logged in','success')
                        return redirect(url_for('dashboard'))
                    elif data['type_name'] == 'Pending':
                        flash("Your account is pending approval",'warning')
                        return render_template('login.html')
                else:
                    # Record failed attempt
                    add_login_attempt(username)
                    app.logger.warning(f'Failed login attempt for user: {username}')
                    flash('Invalid credentials', 'danger')
                    return render_template('login.html')
            else:
                # Still record the attempt even if username doesn't exist
                add_login_attempt(username)
                flash('Invalid credentials', 'danger')
                return render_template('login.html')
        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            flash('An error occurred during login', 'danger')
            return render_template('login.html')
        finally:
            cur.close()
            
    return render_template('login.html')

# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args,**kwargs):
        if 'logged_in' in session:
            return f(*args,**kwargs)
        else:
            flash('Unauthorized, Please login','danger')
            return redirect(url_for('login'))
    return wrap

def redirect_url(default='index'):
    return request.args.get('next') or request.referrer or url_for(default)

# Check if user is admin
def is_admin_in(f):
    @wraps(f)
    def wrap(*args,**kwargs):
        if session['user_type'] == 1:
            return f(*args,**kwargs)
        elif session['user_type'] == 0:
            return f(*args,**kwargs)
        else:
            flash('Unauthorized Access','danger')
            return redirect(redirect_url('dashboard'))
    return wrap

def is_physician_in(f):
    @wraps(f)
    def wrap(*args,**kwargs):
        if session['user_type'] == 0:
            return f(*args,**kwargs)
        elif session['user_type'] == 1:
            return f(*args,**kwargs)
        else:
            flash('Unauthorized Access','danger')
            return redirect(redirect_url('admin'))
    return wrap

#Users Route for admin
@app.route('/user')
@is_logged_in
@is_admin_in
def user():
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM user WHERE user_type='0'")
    user = cur.fetchall()

    if result > 0:
        return render_template('users.html', user=user)
    else:
        msg = "No Users Found"
        return render_template('users.html' , msg=msg)
    cur.close()

# User Requests
@app.route('/user_requests')
@is_logged_in
@is_admin_in
def userRequests():
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM user WHERE user_type='3'")
    users = cur.fetchall()

    if result > 0:
        cur.close()
        return render_template('user_requests.html',users=users)
    else:
        cur.close()
        msg = 'No User Requests Found'
        return render_template('user_requests.html',msg=msg)

# Accept User
@app.route('/user_requests/<string:id>',methods=['GET','POST'])
@is_logged_in
@is_admin_in
def acceptUser(id):
    if request.method == 'POST':
        cur = mysql.connection.cursor()
        # Get physician type_id from user_types
        cur.execute("SELECT type_id FROM user_types WHERE type_name='Physician'")
        physician_type = cur.fetchone()
        physician_type_id = physician_type['type_id']
        
        cur.execute("UPDATE user SET user_type=%s WHERE id=%s",[physician_type_id, id])
        mysql.connection.commit()
        cur.close()
        flash('Request Accepted','success')
        return redirect(url_for('userRequests'))

# Delete User
@app.route('/delete_user_request/<string:id>',methods=['POST'])
@is_logged_in
@is_admin_in
def deleteUserRequest(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE from user WHERE id=%s",[id])
    mysql.connection.commit()
    cur.close()
    flash('Request Deleted','success')
    return redirect(url_for('userRequests'))

#Delete User Route
@app.route('/delete_user/<string:id>', methods=['POST'])
@is_logged_in
@is_admin_in
def delete_user(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM user WHERE id= %s", [id])
    mysql.connection.commit()
    cur.close()

    flash('User Deleted','success')
    return redirect(url_for('user'))

#Profile Route
@app.route('/profile')
@is_logged_in
def profile():
    cur = mysql.connection.cursor()
    id = session['id']
    result = cur.execute("SELECT * FROM user WHERE id=%s",[id])
    user = cur.fetchall()

    if result > 0:
        return render_template('profile.html', user=user,id=id)
    else:
        msg = "No User Found"
        return render_template('profile.html' , msg=msg)
    cur.close()

#Admin Dashboard Route
@app.route('/admin')
@is_logged_in
@is_admin_in
def admin():
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT COUNT(id) AS users FROM user WHERE user_type='0'")
    data = cur.fetchone()
    users = data['users']
    result = cur.execute("SELECT COUNT(p_id) AS all_patients FROM patients")
    data = cur.fetchone()
    patients = data['all_patients']
    result = cur.execute("SELECT * FROM user WHERE user_type='0'")
    user_records = cur.fetchall()
    result = cur.execute("SELECT COUNT(disease_id) AS disease_reports FROM disease")
    data = cur.fetchone()
    reports = data['disease_reports']
    result = cur.execute("SELECT *,concat('P21-',lpad(patients.p_id,5,'0')) AS p_id2 FROM patients")
    patient_records = cur.fetchall()
    cur.close()

    return render_template('admin_dashboard.html',patient_records=patient_records,reports=reports,user_records=user_records,patients=patients,users=users)

# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out','success')
    return redirect(url_for('login'))

# Dashboard
@app.route('/dashboard')
@is_logged_in
@is_physician_in
def dashboard():
    cur = mysql.connection.cursor()
    id = session['id']
    result = cur.execute("SELECT *,concat('P21-',lpad(p_id,5,'0')) AS p_id2  FROM patients WHERE user_id=%s",[id])
    patient_records = cur.fetchall()
    result = cur.execute("SELECT COUNT(p_id) AS all_patients FROM patients WHERE user_id=%s",[id])
    data = cur.fetchone()
    patients = data['all_patients']
    result = cur.execute("SELECT COUNT(disease_id) AS all_reports FROM disease WHERE patient_id in (SELECT p_id from patients WHERE user_id=%s)",[id])
    data = cur.fetchone()
    reports = data['all_reports']
    return render_template('dashboard.html',reports=reports,patients=patients,patient_records=patient_records)

# Forgot Password
@app.route('/forgot',methods=['GET','POST'])
def forgot():
    form = ForgotForm(request.form)

    if request.method == 'POST' and form.validate():
        email = form.email.data
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * from user where email=%s",[email])
        data = cur.fetchone()

        if result > 0:
            token = str(uuid.uuid4())
            cur.execute("UPDATE user SET token=%s WHERE email=%s",(token,email))
            mysql.connection.commit()
            TEXT = "We have received a request for password reset.\n\n To reset your password, please click on this link:\n http://127.0.0.1:5000/reset/"+token
            SUBJECT = "Password reset request"
            message = 'Subject: {}\n\n{}'.format(SUBJECT, TEXT)
            server = smtplib.SMTP("smtp.gmail.com",587)
            server.starttls()
            server.login('kushalreddy648@gmail.com','aqjfidjekutmdxpf')
            server.sendmail('email',email,message)
            cur.close()
            msg = "You have received a password reset email"
            return render_template('forgot.html',form=form,msg=msg)
        else:
            cur.close()
            error = "A user account with this email doesn't exist"
            return render_template('forgot.html',form=form,error=error)
    return render_template('forgot.html',form=form)

# reset Password
@app.route('/reset/<string:token>',methods=['GET','POST'])
def resetPassword(token):
    form = PasswordResetForm(request.form)
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * from user WHERE token=%s",[token])
    if result > 0:
        if request.method == 'POST' and form.validate():
            password = pbkdf2_sha256.using(rounds=350000).hash(str(form.password.data))
            cur.execute("UPDATE user SET password=%s, token='' WHERE token=%s",(password,token))
            mysql.connection.commit()
            cur.close()
            flash('Password successfully changed','success')
            return redirect(url_for('login'))
        return render_template('reset_password.html',form=form)
    else:
        flash('Your token is invalid','danger')
        return redirect(url_for('login'))

#Patients Route
@app.route('/patients')
@is_logged_in
@is_admin_in
@is_physician_in
def patients():
    cur = mysql.connection.cursor()
    id = session['id']
    result = cur.execute("SELECT *,concat('P21-',lpad(p_id,5,'0')) as p_id2 FROM patients WHERE user_id=%s",[id])
    patients = cur.fetchall()

    if result > 0:
        return render_template('patients.html', patients=patients)
    else:
        msg = "No Patients Found"
        return render_template('patients.html' , msg=msg)
    cur.close()

# Patient Form Class
class PatientForm(Form):
    user_id = StringField('User ID')
    p_name = StringField('Full Name')
    p_dob = StringField('Date of Birth')
    p_age = StringField('Age')
    p_docname = StringField('Doctor Name')
    p_gender = SelectField(u'Gender',choices = [('Male','Male'),('Female','Female')])

#Add Patient Route
@app.route('/add_patient',methods = ['GET', 'POST'])
@is_logged_in
@is_physician_in
def add_patient():
    form = PatientForm(request.form)
    if request.method == 'POST' and form.validate():
        p_name = form.p_name.data
        p_dob = form.p_dob.data
        p_age = form.p_age.data
        p_docname = form.p_docname.data
        p_gender = form.p_gender.data

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO patients(p_name, user_id, p_dob, p_age,p_docname,p_gender) VALUES(%s,%s,%s,%s,%s,%s)", (p_name, session['id'], p_dob,p_age,p_docname,p_gender))
        mysql.connection.commit()
        cur.close()
        flash('Patient Added','success')
        return redirect(url_for('patients'))
    return render_template('add_patient.html',form=form)

#Edit Patient Route
@app.route('/edit_patient/<string:id>',methods = ['GET', 'POST'])
@is_logged_in
@is_physician_in
def edit_patient(id):
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM patients WHERE p_id=%s", [id])
    patient = cur.fetchone()

    form = PatientForm(request.form)
    form.user_id.data =patient['user_id']
    form.p_name.data = patient['p_name']
    form.p_dob.data = patient['p_dob']
    form.p_age.data = patient['p_age']
    form.p_docname.data = patient['p_docname']
    form.p_gender.data = patient['p_gender']

    if request.method == 'POST' and form.validate():
        p_name = request.form['p_name']
        p_dob = request.form['p_dob']
        p_age = request.form['p_age']
        p_docname = request.form['p_docname']
        p_gender = request.form['p_gender']

        cur = mysql.connection.cursor()
        cur.execute("UPDATE patients SET p_name=%s, p_dob=%s, p_age=%s, p_docname=%s, p_gender=%s WHERE p_id = %s", (p_name,p_dob,p_age,p_docname,p_gender, id))
        mysql.connection.commit()
        cur.close()

        flash('Patient Edited','success')
        return redirect(url_for('patients'))
    return render_template('edit_patient.html',form=form)

#Delete Patient Route
@app.route('/delete_patient/<string:id>', methods=['POST'])
@is_logged_in
@is_physician_in
def delete_patient(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM patients WHERE p_id= %s", [id])
    mysql.connection.commit()
    cur.close()
    flash('Patient Deleted','success')
    return redirect(url_for('patients'))

# Patient Classification History
@app.route('/history/<string:id>')
@is_logged_in
@is_physician_in
def mal_history(id):
    user_id = session['id']
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM patients WHERE p_id=%s AND user_id=%s",(id,user_id))
    data = cur.fetchone()

    if data is None:
        flash("No Such Record Exists",'danger')
        return redirect(url_for('classify'))
    
    result = cur.execute("SELECT * FROM disease WHERE patient_id=%s ORDER BY create_date DESC",[id])
    history = cur.fetchall()

    if result > 0:
        cur.close()
        return render_template('mal_history.html', history=history)
    else:
        cur.close()
        msg = "No History Found"
        return render_template('mal_history.html' , msg=msg)

@app.route('/classify')
@is_logged_in
@is_physician_in
def classify():
    cur = mysql.connection.cursor()
    id = session['id']
    result = cur.execute("SELECT *,concat('P21-',lpad(p_id,5,'0')) as p_id2 FROM patients WHERE user_id=%s",[id])
    patients = cur.fetchall()

    if result > 0:
        return render_template('classify.html', patients=patients)
    else:
        msg = "No Patients Found"
        return render_template('classify.html' , msg=msg)
    cur.close()

# #Classify Image Route
@app.route('/classify_image/<string:id>',methods = ['GET', 'POST'])
@is_logged_in
@is_physician_in
def classify_image(id):
    user_id = session['id']
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM patients WHERE p_id=%s AND user_id=%s",(id,user_id))
    data = cur.fetchone()

    if data is None:
        flash("No Such Record Exists",'danger')
        return redirect(url_for('classify'))

    full_filename = 'img/no_image.PNG'

    if request.method == "GET":
        return render_template("classify_image.html", full_filename = full_filename)

    if request.method == "POST":
        image_upload = request.files['image_upload']
        
        # Validate uploaded file
        is_valid, error_message = validate_image_file(image_upload)
        if not is_valid:
            flash(error_message, 'danger')
            return render_template('classify_image.html', full_filename=full_filename)
            
        try:
            # Generate secure filename
            letters = string.ascii_lowercase
            name = token_hex(16) + '.png'
            full_filename = 'img/uploads/' + name
            
            # Save and process image
            image = Image.open(image_upload)
            image = image.resize((128,128))
            img_path = os.path.join(app.config['INITIAL_FILE_UPLOADS'], name)
            image.save(img_path)
            print("Starting predict")
            pred, prob = predict_label(img_path)
            print("Probabaility ",prob)
            # Store result in database
            cur.execute("INSERT INTO disease(patient_id,disease_name,image) VALUES(%s,%s,%s)", 
                       (id,pred,img_path))
            mysql.connection.commit()
            disease_id = cur.lastrowid
            
            app.logger.info(f'Image classification completed for patient {id}: {pred} ({prob}%)')
            return render_template('classify_image.html', 
                                full_filename=full_filename, 
                                pred=pred, 
                                prob=prob, 
                                disease_id=disease_id)
                                
        except Exception as e:
            app.logger.error(f'Image classification error: {str(e)}')
            flash('Error processing image', 'danger')
            return render_template('classify_image.html', full_filename=full_filename)
        finally:
            cur.close()

@app.route('/mal_pdf/<string:id>')
@is_logged_in
@is_physician_in
def mal_pdf(id):
    user_id = session['id']
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM disease WHERE disease_id=%s",[id])
    data = cur.fetchone()

    if data is None:
        flash("No Such Record Exists",'danger')
        return redirect(url_for('classify'))

    result = cur.execute("SELECT *,concat('22-',lpad(patients.p_id,4,'0')) as p_id2 FROM patients INNER JOIN disease ON patients.p_id=disease.patient_id WHERE disease.disease_id=%s AND patients.user_id=%s",(id,user_id))
    data = cur.fetchone()

    if data is None:
        flash("No Such Record Exists",'danger')
        return redirect(url_for('classify'))

    id = data['p_id2']
    create_date = data['create_date']
    name=data['p_name']
    dob =  data['p_dob']
    age = data['p_age']
    gender = data['p_gender']
    disease_name = data['disease_name']
    cur.close()

    src = os.path.dirname(os.path.abspath(__file__))+'/'+data['image']
    app.logger.info(src)
    rendered = render_template('mal_pdf.html',id=id,full_filename=src,name=name,dob=dob,age=age,gender=gender,time_added=create_date,pred=disease_name)
    options = {
  "enable-local-file-access": None
    }
    config = pdfkit.configuration(wkhtmltopdf="C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe")
    pdf = pdfkit.from_string(rendered,False,options=options,configuration=config)
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'inline; output.pdf'

    return response

class GenerateLabReport(Form):
    patient = SelectField(u'Patient Name',coerce = int)
    report_date = SelectField(u'Report Date',coerce = int)

@app.route('/lab_reports',methods=['GET','POST'])
@is_logged_in
@is_physician_in
def labReports():
    form = GenerateLabReport(request.form)
    doc_id = session['id']
    cur = mysql.connection.cursor()
    patient_result = cur.execute("SELECT p_id,p_name FROM patients WHERE user_id=%s AND p_id in (SELECT patient_id FROM lab_reports)",[doc_id])
    patients = cur.fetchall()
    patientData = []

    for patient in patients:
        patientData.append((patient['p_id'],patient['p_name']))
    form.patient.choices = patientData

    if request.method == 'POST':
        patient = str(form.patient.data)
        report_date = str(request.form['report_date'])
        app.logger.info(report_date)
        return patient + " " + report_date
    return render_template('lab_reports.html',form=form)

@app.route('/process',methods=['GET','POST'])
@is_logged_in
@is_physician_in
def process():
    patient_id = request.form['patient']

    if patient_id:
        cur = mysql.connection.cursor()
        report_dates = cur.execute("SELECT DATE_FORMAT(date,'%%Y-%%m-%%d') as report_date FROM lab_reports WHERE patient_id = %s GROUP BY report_date",[patient_id])
        report_dates = cur.fetchall()
        return jsonify(report_dates)
    return 'error'

#Generate PDF of Lab Report
@app.route('/lab_report_pdf',methods=['GET','POST'])
@is_logged_in
@is_physician_in
def lab_report_pdf():
    physician_id = session['id']
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT name from user WHERE id=%s",[physician_id])

    if result > 0:
        data = cur.fetchone();
        physician_name = data['name']
    else:
        return 'No User Data Found'

    if request.method == 'POST':
        patient_id = request.form['patient'];
        report_date = request.form['report_date'];
        result = cur.execute("SELECT * FROM (((lab_reports INNER JOIN patients ON p_id = patient_id) INNER JOIN tests_under ON lab_reports.test_id = tests_under.id) INNER JOIN lab_tests ON tests_under.test_id = lab_tests.Id) WHERE DATE_FORMAT(lab_reports.date,'%%Y-%%m-%%d')=%s AND lab_reports.patient_id=%s ORDER BY lab_tests.test_name",(report_date,patient_id))
        report_details = cur.fetchall()

        if result > 0:
            cur.close()
            report_data = {}

            for info in report_details:
                report_data[info['lab_tests.test_name']] = {'TEST':[],'RESULT':[],'UNIT':[],'UPPER_LIMIT':[],'LOWER_LIMIT':[]}

            for info in report_details:
                report_data[info['lab_tests.test_name']]['TEST'].append(info['test_name'])
                report_data[info['lab_tests.test_name']]['RESULT'].append(info['test_value'])
                report_data[info['lab_tests.test_name']]['UNIT'].append(info['unit'])
                report_data[info['lab_tests.test_name']]['UPPER_LIMIT'].append(info['upper_limit'])
                report_data[info['lab_tests.test_name']]['LOWER_LIMIT'].append(info['lower_limit'])
                report_data[info['lab_tests.test_name']]['LENGTH'] = len(report_data[info['lab_tests.test_name']]['TEST'])

            rendered = render_template('lab_report_pdf.html',report_details=report_details,report_date=report_date,physician_name=physician_name,report_data=report_data)
            options = {
          "enable-local-file-access": None
            }
            config = pdfkit.configuration(wkhtmltopdf="C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe")
            pdf = pdfkit.from_string(rendered,False,options=options,configuration=config)
            response = make_response(pdf)
            response.headers['Content-Type'] = 'application/pdf'
            response.headers['Content-Disposition'] = 'inline; lab_report.pdf'
            return response
        else:
            msg = "No User Data Found"
            return msg

# Add Test Type Form
class labTest(Form):
    test_name = StringField(label='Test name',validators=[DataRequired(),validators.Length(min=1),validators.Regexp(regex="^[a-zA-Z ]*$",message="Only alphabets and spaces are allowed")])
    code = StringField(label='code',validators=[DataRequired(),validators.Length(min=1),validators.Regexp(regex="^[a-zA-Z ]*$",message="Only alphabets and spaces are allowed")])
    submit = SubmitField(label="Submit")

# View type of Lab Test
class TestUnder(Form):
    test_name = StringField(label='Test name',validators=[DataRequired(),validators.Length(min=1),validators.Regexp(regex="^[a-zA-Z ]*$",message="Only alphabets and spaces are allowed")])
    lower_limit = StringField(label='Lower limit',validators=[DataRequired(),validators.Length(min=1),validators.Regexp(regex="^([0-9]+[.]?[0-9]*)$",message="Only positive numeric or decimal values allowed")])
    upper_limit = StringField(label='Upper limit',validators=[DataRequired(),validators.Length(min=1),validators.Regexp(regex="^([0-9]+[.]?[0-9]*)$",message="Only positive numeric or decimal values allowed")])
    unit = StringField(label='Unit',validators=[DataRequired(),validators.Length(min=1),validators.Regexp(regex="^[a-zA-Z/%]*$",message="Only alphabets and some special characters allowed (/,%)")])
    unit_price = StringField(label='Unit price',validators=[DataRequired(),validators.Length(min=1),validators.Regexp(regex="^([0-9]+[.]?[0-9]*)$",message="Only numeric or decimal values allowed")])
    taxes = StringField(label='Taxes',validators=[DataRequired(),validators.Length(min=1),validators.Regexp(regex="^([0-9]+[.]?[0-9]*)$",message="Only numeric or decimal values allowed")])

# Lab Test Type Sub Category
@app.route('/test_under/<string:id>',methods=['GET','POST'])
@is_logged_in
@is_physician_in
def testUnder(id):
    form = TestUnder(request.form)

    if request.method == 'POST' and form.validate():
        test_name = form.test_name.data
        lower_limit = form.lower_limit.data
        upper_limit = form.upper_limit.data
        unit = form.unit.data
        unit_price = form.unit_price.data
        taxes = form.taxes.data
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO tests_under(test_name,test_id,lower_limit,upper_limit,unit,unit_price,taxes) VALUES(%s, %s, %s, %s, %s, %s, %s)",(test_name,id,lower_limit,upper_limit,unit,unit_price,taxes))
        mysql.connection.commit()
        cur.close()

        flash('Test Under Category Created', 'success')
        return redirect(url_for('testUnder',id=id))

    cur = mysql.connection.cursor()
    result = cur.execute("SELECT test_name from lab_tests WHERE id = %s ",[id])
    data = cur.fetchone()
    lab_test = data['test_name']
    result = cur.execute("SELECT * FROM tests_under WHERE test_id=%s",[id])
    tests = cur.fetchall()

    if result > 0:
        return render_template('test_under.html', tests=tests, form=form,lab_test=lab_test)
    else:
        msg = 'No Tests Under Category Found'
        return render_template('test_under.html',msg=msg,form=form,lab_test=lab_test);
    cur.close()

# Lab Report Fields
class LabReport(Form):
    patient = SelectField(u'Patient',coerce = int)
    test_value = StringField(label='Test Value',validators=[DataRequired(),validators.Length(min=1),validators.Regexp(regex="^([0-9]+[.]?[0-9]*)$",message="Only numeric or decimal values allowed")])

# Add Lab Report Data of a patient
@app.route('/add_lab_report/<string:id>',methods=['GET','POST'])
@is_logged_in
@is_physician_in
def addLabReport(id):
    form = LabReport(request.form)
    doc_id = session['id']
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT p_id,p_name FROM patients WHERE user_id=%s",[doc_id])
    patients = cur.fetchall()
    patientData = []

    for patient in patients:
        patientData.append((patient['p_id'],patient['p_name']))
    form.patient.choices = patientData

    if request.method == 'POST' and form.validate():
        patient_id = form.patient.data
        test_value = form.test_value.data
        result = cur.execute("INSERT INTO lab_reports(test_id,patient_id,test_value) VALUES(%s,%s,%s)",(id,patient_id,test_value))
        mysql.connection.commit()

        flash('Report Added','success')
        return redirect(url_for('addLabReport',id=id))

    result = cur.execute("SELECT lab_tests.test_name as test_type_name,lab_tests.Id as type_id, tests_under.test_name as test_name  FROM lab_tests INNER JOIN tests_under ON lab_tests.Id=tests_under.test_id WHERE tests_under.id=%s",[id])
    data = cur.fetchone()
    test_data = data
    result = cur.execute("SELECT p_id,p_name FROM patients WHERE user_id=%s",[doc_id])

    if result > 0:
        return render_template('add_lab_report.html',test_data=test_data,form=form)
    else:
        msg = "No Patients Found"
        return render_template('add_lab_report.html' , msg=msg,form=form)

# Lab Request Fields
class LabRequest(Form):
    patient = SelectField(u'Patient',coerce = int)
    request_date = DateTimeLocalField('Request Date',format='%Y-%m-%dT%H:%M',validators=[DataRequired()])
    urgency = SelectField(u'Urgency Level',choices = [('Normal','Normal'),('High','High'),('Very High','Very High')])

# Add Lab Request for a patient
@app.route('/add_lab_request/<string:id>',methods=['GET','POST'])
@is_logged_in
@is_physician_in
def addLabRequest(id):
    form = LabRequest(request.form)
    doc_id = session['id']
    cur = mysql.connection.cursor()
    patient_result = cur.execute("SELECT p_id,p_name FROM patients WHERE user_id=%s",[doc_id])
    patients = cur.fetchall()
    patientData = []

    for patient in patients:
        patientData.append((patient['p_id'],patient['p_name']))
    form.patient.choices = patientData

    if request.method == 'POST' and form.validate():
        request_date = form.request_date.data.strftime("%Y-%m-%d %H:%M:00")
        patient_id = form.patient.data
        urgency_level = form.urgency.data
        result = cur.execute("INSERT INTO lab_requests(test_id,patient_id,urgency_level,request_date) VALUES(%s,%s,%s,%s)",(id,patient_id,urgency_level,request_date))
        mysql.connection.commit()

        flash('Request Added','success')
        return redirect(url_for('addLabRequest',id=id))
    result = cur.execute("SELECT lab_tests.test_name as test_type_name,lab_tests.Id as type_id, tests_under.test_name as test_name  FROM lab_tests INNER JOIN tests_under ON lab_tests.Id=tests_under.test_id WHERE tests_under.id=%s",[id])

    data = cur.fetchone()
    test_data = data

    if patient_result > 0:
        return render_template('add_lab_request.html',test_data=test_data,form=form)
    else:
        msg = "No Patients Found"
        return render_template('add_lab_request.html' , msg=msg,form=form)

if __name__ == "__main__":
    app.secret_key='secret123'
    app.run(debug=True)
