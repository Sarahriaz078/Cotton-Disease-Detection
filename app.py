import os,csv
import io
import stripe
from flask import session, request,Response,make_response
from reportlab.lib import colors
from reportlab.lib.utils import simpleSplit,ImageReader
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime,timedelta
from flask_login import UserMixin
from collections import Counter
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from tensorflow.keras.models import load_model
# from tensorflow.keras.applications.resnet50 import preprocess_input
from tensorflow.keras.preprocessing import image
from tensorflow.keras.applications.mobilenet_v2 import MobileNetV2, preprocess_input, decode_predictions
import numpy as np
from flask_wtf.csrf import CSRFProtect
from sqlalchemy.orm import joinedload
from collections import defaultdict
from sqlalchemy import func,and_

MAX_UPLOADS_GUEST = 1

# ------------------- App Config -------------------

app = Flask(__name__)
app.config['SECRET_KEY'] = '12345678'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
basedir = os.path.abspath(os.path.dirname(__file__))
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
stripe.api_key = 'sk_test_51RVeOuH8ePsBIjVa5ww1ZG7EbaXVgARakBFcwgNHH9hPjqlfB12AmOOLSG6b3bcwWySTMFvO5lq6AtVsKfOoaird005tddGWz8'

PRICE_IDS = {
    'premium': 'price_1RWDtXH8ePsBIjVa8ZMH4SWC',  # replace with actual price ID
    'diamond': 'price_1RWDsfH8ePsBIjVacxX87HVa'
}
# In app.py or settings
app.config['WTF_CSRF_HEADERS'] = ['X-CSRFToken']
csrf = CSRFProtect(app)


db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Load the trained model
# model name
MODEL_PATH ='resnet50.h5'
filter_model = MobileNetV2(weights='imagenet')

# load trained model
model = load_model(MODEL_PATH)
def is_plant_image(img_path,confidence_threshold=0.60):
    img = image.load_img(img_path, target_size=(224, 224))
    img_array = image.img_to_array(img)
    img_array = preprocess_input(np.expand_dims(img_array, axis=0))

    preds = filter_model.predict(img_array)
    decoded = decode_predictions(preds, top=10)[0] # Get top 5 predictions
    leaf_keywords = ['leaf', 'plant', 'tree', 'flower', 'vegetable', 'fruit', 'foliage', 'cabbage', 'lettuce', 'corn', 'pineapple', 'banana']

    # Check if any predicted label is plant-related
    for _, label, prob in decoded:
        if any(keyword in label.lower() for keyword in leaf_keywords)and prob > confidence_threshold:
            return True
    return False

def model_predict(img_path, model,confidence_threshold=0.55):
    print('Uploaded image path: ',img_path)
    # First check if image is plant/leaf related

    loaded_image = image.load_img(img_path, target_size=(224, 224))

    # preprocess the image
    loaded_image_in_array = image.img_to_array(loaded_image)

    # normalize
    loaded_image_in_array=loaded_image_in_array/255

    # add additional dim such as to match input dim of the model architecture
    x = np.expand_dims(loaded_image_in_array, axis=0)

    # prediction
    prediction = model.predict(x)
    confidence = np.max(prediction) 
    results_index = np.argmax(prediction, axis=1)[0]

    # map indexes to disease names
    disease_labels = {
        0: "The leaf shows signs of Aphids",
        1: "The leaf shows signs of Army Worm",
        2: "The leaf shows signs of Bacterial Blight",
        3: "The leaf is Healthy",
        4: "The leaf shows signs of Powdery Mildew",
        5: "The leaf shows signs of Target Spot"
    }

    # if confidence < confidence_threshold or not is_plant_image(img_path):
    #     return "Prediction confidence is low. Please upload a clearer or relevant image or The uploaded image does not seem to be a valid plant leaf. Please upload a leaf image."
    # if not is_plant_image(img_path):
    #   return "Prediction confidence is low. Please upload a clearer or relevant image or The uploaded image does not seem to be a valid plant leaf. Please upload a leaf image."
    # Return prediction with confidence percentage
    return f"{disease_labels.get(results_index, 'Unknown disease')} (Confidence: {confidence*100:.2f}%)"

# ------------------- Models -------------------

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    upload_attempts = db.Column(db.Integer, default=0)
    subscribed = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(50), default='user')  # add this
    upload_limit = db.Column(db.Integer, default=3)  # Free plan by default
    subscription_date = db.Column(db.DateTime)
    subscription_plan = db.Column(db.String(100), default="Free")
    reports = db.relationship('Report', backref='user', lazy=True)


    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password,password)


class SignupHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    username = db.Column(db.String(150))
    success = db.Column(db.Boolean)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class SessionHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    username = db.Column(db.String(150))
    action = db.Column(db.String(50))  # login or logout
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(100), nullable=False)
    prediction = db.Column(db.String(100), nullable=False)
    confidence = db.Column(db.Float, nullable=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())


class payment_history(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    username = db.Column(db.String(150))
    plan = db.Column(db.String(50))
    amount = db.Column(db.Float)
    payment_time = db.Column(db.DateTime, default=datetime.utcnow)


@app.route('/download_report/<int:report_id>')
@login_required
def download_report(report_id):
    if current_user.is_admin:
        report = Report.query.filter_by(id=report_id).first()
    else:
        report = Report.query.filter_by(id=report_id, user_id=current_user.id).first()

    if not report:
        flash("Report not found or unauthorized access.", "danger")
        return redirect(url_for('home'))

    image_path = image_path = os.path.join("uploads", report.filename)
    # Format confidence safely
    try:
        confidence_value = float(report.confidence)
        confidence_text = f"{confidence_value:.2f}%"
    except (TypeError, ValueError):
        confidence_text = "N/A"

    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    # Colors
    header_color = colors.HexColor('#1e3a8a')
    box_bg_color = colors.HexColor('#f1f5f9')
    text_color = colors.HexColor('#0f172a')

    # Header
    p.setFillColor(header_color)
    p.rect(0, height - 80, width, 80, fill=True, stroke=False)
    p.setFillColor(colors.white)
    p.setFont("Helvetica-Bold", 20)
    p.drawString(69, height - 50, "Cotton Disease Detection Report")
    
    
  # Logo (draw AFTER header)
    logo_path = os.path.join("static", "assets", "img", "logo.png")
    logo_width = 50
    logo_height = 50
    logo_x = 20  # Align left
    logo_y = height - 70  # Lower than top edge

    if os.path.exists(logo_path):
        try:
           p.drawImage(ImageReader(logo_path), logo_x, logo_y, width=logo_width, height=logo_height, mask='auto')
        except Exception as e:
          print(f"Logo not embedded: {e}")

    # Image
    image_width = 280
    image_height = 200
    image_x = (width - image_width) / 2
    image_y = height - 100 - image_height  # 100 below top

    if os.path.exists(image_path):
        try:
            p.drawImage(ImageReader(image_path), image_x, image_y, width=image_width, height=image_height)

        except Exception as e:
            print(f"Error embedding image: {e}")
            p.setFont("Helvetica", 10)
            p.drawString(image_x, image_y + 70, "Could not embed image.")
    else:
        p.setFont("Helvetica", 10)
        p.drawString(image_x, image_y + 70, "Image not found.")

    # Report Info Box - dynamically below the image
    box_top_y = image_y - 40  # Space below image
    box_height = 250
    x, y = 50, box_top_y - box_height
    box_width = width - 100

    p.setFillColor(box_bg_color)
    p.roundRect(x, y, box_width, box_height, 12, fill=True, stroke=True)

    # Text content
    p.setFont("Helvetica-Bold", 12)
    p.setFillColor(text_color)
    padding = 20
    label_x = x + padding
    value_x = x + 160
    line_height = 30
    start_y = y + box_height - 40

    # Filename
    p.drawString(label_x, start_y, "Filename:")
    p.setFont("Helvetica", 12)
    p.drawString(value_x, start_y, report.filename)

    # Prediction (multi-line)
    p.setFont("Helvetica-Bold", 12)
    p.drawString(label_x, start_y - line_height, "Prediction:")
    prediction_text = report.prediction
    max_text_width = box_width - (2 * padding + 110)
    prediction_lines = simpleSplit(prediction_text, "Helvetica", 12, max_text_width)

    p.setFont("Helvetica", 12)
    for i, line in enumerate(prediction_lines):
        p.drawString(value_x, start_y - line_height - (i * 15), line)

    # Adjust position for next items
    extra_offset = line_height + (len(prediction_lines) * 15)
    current_y = start_y - extra_offset

    # Confidence
    p.setFont("Helvetica-Bold", 12)
    p.drawString(label_x, current_y, "Confidence:")
    p.setFont("Helvetica", 12)
    p.drawString(value_x, current_y, confidence_text)

    # Date
    p.setFont("Helvetica-Bold", 12)
    p.drawString(label_x, current_y - line_height, "Date:")
    p.setFont("Helvetica", 12)
    p.drawString(value_x, current_y - line_height, report.timestamp.strftime('%Y-%m-%d %H:%M:%S'))

    # Footer
    p.setStrokeColor(colors.HexColor("#cccccc"))
    p.line(40, 60, width - 40, 60)
    p.setFont("Helvetica-Oblique", 10)
    p.setFillColor(colors.HexColor("#777777"))
    p.drawString(40, 45, "Generated by Cotton Disease Detection System")

    p.showPage()
    p.save()

    buffer.seek(0)
    return send_file(buffer, as_attachment=True,
                     download_name=f"{report.filename}_report.pdf",
                     mimetype='application/pdf')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ------------------- Routes -------------------
@csrf.exempt
@app.route('/predict', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        # Check if user is logged in
        if current_user.is_authenticated:
            # Check upload limit for authenticated users
            if not current_user.is_admin and current_user.upload_attempts >= current_user.upload_limit:
                return jsonify({
                    'status': 'error',
                    'message': 'Your free trial has ended. Please subscribe to continue.',
                    'redirect': url_for('subscription')
                }), 403
        else:
            # For unauthenticated users, allow only 1 upload using cookie
            if request.cookies.get('guest_upload_done'):
                return jsonify({
                    'status': 'error',
                    'message': 'You have already used your free upload. Please log in to continue.',
                    'redirect': url_for('login')
                }), 401

    try:
        f = request.files['file']
        if not f or f.filename == '':
            return jsonify({
                'status': 'error',
                'message': 'No file selected'
            }), 400

        # Save file and predict
        file_path = os.path.join(os.path.dirname(__file__), 'uploads', f.filename)
        f.save(file_path)
        preds = model_predict(file_path, model)

        # Extract prediction and confidence properly
        prediction = preds.split("(")[0].strip() if "(" in preds else preds
        confidence = None
        if "Confidence:" in preds:
            try:
                confidence = float(preds.split("Confidence:")[1].replace("%", "").replace(")", "").strip())
            except:
                pass

        # Prepare response
        response_data = {
            'status': 'success',
            'prediction': prediction,
            'full_result': preds,
            'confidence': confidence
        }

        if current_user.is_authenticated:
            # Save to database
            report = Report(
                user_id=current_user.id,
                filename=f.filename,
                prediction=prediction,
                confidence=confidence
            )
            db.session.add(report)
            current_user.upload_attempts += 1
            db.session.commit()
            response_data['report_id'] = report.id
            return jsonify(response_data)

        else:
            # Mark guest upload as done via cookie
            response = jsonify(response_data)
            response.set_cookie('guest_upload_done', 'true', max_age=60*60*24*30)  # 30 days
            return response

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@csrf.exempt
@app.route('/get_latest_report_id')
@login_required
def get_latest_report_id():
    latest_report = Report.query.filter_by(user_id=current_user.id).order_by(Report.id.desc()).first()
    if latest_report:
        return jsonify({'report_id': latest_report.id})
    return jsonify({'report_id': None})


@app.route('/')
def home():
    return render_template('index.html')

@csrf.exempt
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username or not email or not password or not confirm_password:
            flash('All fields are required.', 'warning')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match.', 'warning')
            return redirect(url_for('register'))

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'warning')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please log in or use another.', 'danger')
            return redirect(url_for('register'))

        # Create user and hash password
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

       # Save to SignupHistory
        signup_log = SignupHistory(username=username)
        db.session.add(signup_log)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@csrf.exempt
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username).first()
        login_success = user and check_password_hash(user.password, password)


 # ✅ Clear guest upload flag after login
        session.pop('guest_uploaded', None)
        
        login_log = LoginHistory(
            user_id=user.id if user else None,
            username=username,
            success=login_success
        )
        db.session.add(login_log)

        if not login_success:
            db.session.commit()
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))

        login_user(user)
        session['is_admin'] = user.is_admin
        db.session.add(SessionHistory(user_id=user.id, username=user.username, action='login'))
        db.session.commit()

        flash(f'Welcome, {user.username}!', 'success')
        return redirect(url_for('home'))

    return render_template('login.html')

@csrf.exempt
@app.route('/verify-user', methods=['POST'])
def verify_user():
    data = request.get_json()
    email = data.get('email')
    username = data.get('username')

    # Query user from DB
    user = User.query.filter_by(username=username).first()
    if user and user.email.lower() == email.lower():
        return jsonify({'exists': True})
    return jsonify({'exists': False})

@csrf.exempt
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    email = request.form.get('forgot_email')
    username = request.form.get('forgot_username')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_new_password')

    user = User.query.filter_by(username=username).first()
    if not user or user.email.lower() != email.lower():
        flash("User does not exist or incorrect credentials.", "danger")
        return redirect(url_for('login'))

    if new_password != confirm_password:
        flash("Passwords do not match.", "danger")
        return redirect(url_for('login'))

    if len(new_password) < 6:
        flash("Password must be at least 6 characters long.", "danger")
        return redirect(url_for('login'))

    # Hash the new password and update user
    user.set_password(new_password)
    db.session.commit()

    flash("Password reset successfully! Please login.", "success")
    return redirect(url_for('login'))


@app.route('/logout')
@login_required
def logout():
    try:
        session_record = SessionHistory(
            user_id=current_user.id,
            username=current_user.username,
            action='logout',
            timestamp=datetime.utcnow()
        )
        db.session.add(session_record)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Failed to log logout: {e}")
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/profile')
@login_required
def profile():
    user = User.query.get(current_user.id)
  
    remaining_uploads = user.upload_limit - user.upload_attempts
    subscription_plan = user.subscription_plan or "Free"
    if user.upload_limit == 20:
        subscription_plan = "Premium"
    elif user.upload_limit == 100:
        subscription_plan = "Diamond"

    return render_template("profile.html",  user=user, plan=subscription_plan, remaining=remaining_uploads)

@app.route('/subscription')
def subscription():
    return render_template('subscription.html')

@csrf.exempt
@app.route('/buy_subscription/<plan>', methods=['GET'])
@login_required
def buy_subscription(plan):
    
    if plan not in PRICE_IDS:
        return "Invalid plan selected", 400
    
    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price': PRICE_IDS[plan],
                'quantity': 1,
            }],
            mode='payment',
            success_url = url_for('payment_success', _external=True) + f'?plan={plan}&session_id={{CHECKOUT_SESSION_ID}}',
            cancel_url=url_for('payment_cancel', _external=True),
            customer_email=current_user.email # optional to pre-fill email
        )
        return redirect(checkout_session.url, code=303)
    except Exception as e:
        return str(e), 400

@csrf.exempt
@app.route('/payment_success')
def payment_success():
    session_id = request.args.get('session_id')
    plan = request.args.get('plan')

    if not session_id or not plan:
        return "Missing session or plan info", 400

    try:
        checkout_session = stripe.checkout.Session.retrieve(session_id)
        if checkout_session.payment_status == 'paid':
            user = User.query.get(current_user.id)
            if not user:
                return redirect(url_for('login'))

            # Determine upload amount and readable name
            if plan == 'premium':
                new_uploads = 20
                plan_name = "Premium"
            elif plan == 'diamond':
                new_uploads = 100
                plan_name = "Diamond"
            else:
                return "Invalid plan", 400

            # ✅ Add new uploads
            user.upload_limit += new_uploads

            # ✅ Update subscription plan list
            if user.subscription_plan:
                if plan_name not in user.subscription_plan:
                    user.subscription_plan += f"+{plan_name}"
            else:
                user.subscription_plan = plan_name

            user.subscribed = True
            user.subscription_date = datetime.utcnow()
            # ✅ Save payment history
            new_payment = payment_history(
            user_id=current_user.id,
            username=user.username,
            plan=plan_name,
            amount=checkout_session.amount_total / 100,  # Stripe amount 
            payment_time=datetime.utcnow()
            )
            db.session.add(new_payment)
            db.session.commit()
            flash(f'Subscription Successful! You now have {user.upload_limit} total image uploads.', 'success')
            return redirect(url_for('profile'))
        else:
            return "Payment not successful", 400
    except Exception as e:
        return f"Error verifying payment: {str(e)}", 400

@app.route('/payment_cancel')
def payment_cancel():
    return "Payment canceled. Please try again."

# You also need your login, logout, and user DB functions implemented

def update_user_subscription(user_id, new_uploads):
    user = User.query.get(user_id)
    if user:
        user.upload_limit = new_uploads
        user.upload_attempts = 0  # Reset attempts
        user.subscribed = True
        db.session.commit()

@app.route('/try')
def try_page():
    return render_template('try.html')


@app.route('/my-reports')
@app.route('/my-reports/page/<int:page>')
@login_required
def my_reports(page=1):
    per_page = 10
    username_filter = request.args.get('username', '').strip()
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    if current_user.is_admin:
        # Admin: fetch all reports, optionally filter by username
        query = Report.query.options(joinedload(Report.user)).order_by(Report.timestamp.desc())

        if username_filter:
            query = query.join(User).filter(User.username.ilike(f"%{username_filter}%"))
        # Apply date filter if valid
        if start_date_str and end_date_str:
            try:
                start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
                end_date = datetime.strptime(end_date_str, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
                query = query.filter(Report.timestamp.between(start_date, end_date))
            except ValueError:
                flash("Invalid date format", "warning")
    else:
        # Regular user: only their reports
        query = Report.query.filter_by(user_id=current_user.id).order_by(Report.timestamp.desc())
    total_reports = query.count()
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    reports = pagination.items
     # ✅ Disease frequency analysis (admin only)
    disease_counts = {}
    if current_user.is_admin:
        all_filtered_reports = query.all()
        for report in all_filtered_reports:
            disease = report.prediction.split("(")[0].strip()
            disease_counts[disease] = disease_counts.get(disease, 0) + 1
    return render_template('my-reports.html', reports=reports, pagination=pagination, username_filter=username_filter,start_date=start_date_str,
        end_date=end_date_str,
        disease_counts=disease_counts if current_user.is_admin else None,total_reports=total_reports)


@app.route('/diseases-info')
def diseases_info():
    return render_template('5 diseases info.html')

@app.route('/aphids')
def aphids():
    return render_template('aphids.html')

@app.route('/army-worm')
def army_worm():
    return render_template('army-worm.html')

@app.route('/bacterial-blight')
def bacterial_blight():
    return render_template('bacterial-blight.html')

@app.route('/powdery-mildew')
def powdery_mildew():
    return render_template('powdery-mildew.html')

@app.route('/target-spot')
def target_spot():
    return render_template('target-spot.html')



@csrf.exempt
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('home'))
    # filering singup
    signup_username = request.args.get('signup_username', '').strip()
    signup_start = request.args.get('signup_start')
    signup_end = request.args.get('signup_end')

    signup_query = SignupHistory.query
    # Filter by username
    if signup_username:
         signup_query = signup_query.filter(SignupHistory.username.ilike(f"%{signup_username}%"))
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    # Filter by date range
    if signup_start and signup_end:
        try:
             start = datetime.strptime(signup_start, '%Y-%m-%d')
             end = datetime.strptime(signup_end, '%Y-%m-%d')
             signup_query = signup_query.filter(
             SignupHistory.timestamp >= start,
             SignupHistory.timestamp < end + timedelta(days=1))
        except ValueError:
         flash("Invalid signup date format", "warning")
    # --- Login Filter ---
    login_username = request.args.get('login_username', '').strip()
    login_start = request.args.get('login_start')
    login_end = request.args.get('login_end')  
    login_query = LoginHistory.query

    if login_username:
         login_query = login_query.filter(LoginHistory.username.ilike(f"%{login_username}%")) 
    if login_start and login_end:
        try:
            start = datetime.strptime(login_start, '%Y-%m-%d')
            end = datetime.strptime(login_end, '%Y-%m-%d') + timedelta(days=1)
            login_query = login_query.filter(LoginHistory.timestamp >= start, LoginHistory.timestamp < end)
        except ValueError:
             flash("Invalid login date format", "warning")
    payments_query = payment_history.query
    start_date = None
    end_date = None
    if start_date_str and end_date_str:
      try:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
        end_date = end_date.replace(hour=23, minute=59, second=59)

        payments_query = payments_query.filter(
            payment_history.payment_time.between(start_date, end_date)
        )
      except ValueError:
        flash("Invalid date format", "warning")

    # ✅ Always assign payments after filtering logic
    payments = payments_query.order_by(payment_history.payment_time.desc()).all()
    # Revenue calculation
    total_revenue = sum(p.amount for p in payments)
    revenue_by_plan = {
        'Premium': sum(p.amount for p in payments if p.plan == 'Premium'),
        'Diamond': sum(p.amount for p in payments if p.plan == 'Diamond')
    }
    # --- Session Logs Filter ---
    session_username = request.args.get('session_username', '').strip()
    session_start = request.args.get('session_start')
    session_end = request.args.get('session_end')
    session_query = SessionHistory.query

    if session_username:
        session_query = session_query.filter(SessionHistory.username.ilike(f"%{session_username}%"))
    
    if session_start and session_end:
        try:
         start = datetime.strptime(session_start, '%Y-%m-%d')
         end = datetime.strptime(session_end, '%Y-%m-%d') + timedelta(days=1)
         session_query = session_query.filter(SessionHistory.timestamp >= start, SessionHistory.timestamp < end)
        except ValueError:
         flash("Invalid session date format", "warning")
    
    user_search = request.args.get('user_search', '').strip()
    user_query = User.query
    if user_search:
        user_query = user_query.filter(User.username.ilike(f"%{user_search}%"))
    signup_logs = signup_query.order_by(SignupHistory.timestamp.desc()).all()
    login_logs = login_query.order_by(LoginHistory.timestamp.desc()).all()
    session_logs = session_query.order_by(SessionHistory.timestamp.desc()).all()
    users = user_query.all()  # Replace old 'users = User.query.all()'

    # Count successful logins by username for Chart.js
    login_usernames = [log.username for log in login_logs if log.success]
    login_chart_data = dict(Counter(login_usernames))
    plan_counts = {
        'Free': 0,
        'Premium': 0,
        'Diamond': 0
    }

    for user in users:
        if user.subscription_plan:
            if "Premium" in user.subscription_plan:
                plan_counts['Premium'] += 1
            if "Diamond" in user.subscription_plan:
                plan_counts['Diamond'] += 1
        if not user.subscribed or user.subscription_plan == 'Free':
            plan_counts['Free'] += 1 

    return render_template(
        'admin_dashboard.html',
        signup_logs=signup_logs,
        login_logs=login_logs,
        session_logs=session_logs,
        login_chart_data=login_chart_data,
        payments=payments,
        plan_counts=plan_counts,
        total_revenue=total_revenue,
        revenue_by_plan=revenue_by_plan,
        start_date=start_date_str,
        end_date=end_date_str,
        users=users
    )
@app.before_request
def restrict_to_admin():
    if request.path.startswith('/admin') and not session.get('is_admin'):
        return redirect(url_for('login'))


@csrf.exempt
@app.route('/admin/view-users')
@login_required
def view_users():
    if not current_user.is_admin:
        return redirect(url_for('home'))
    users = User.query.all()
    return render_template('view_users.html', users=users)

# Route to Add a New User
@csrf.exempt
@app.route('/admin/add_user', methods=['POST'])
def add_user():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']
    
    if User.query.filter_by(username=username).first():
        flash('Username already exists', 'error')
        return redirect(url_for('admin_dashboard'))
    # Optional: check if user already exists
    if User.query.filter_by(email=email).first():
        flash('Email already exists', 'error')
        return redirect(url_for('admin_dashboard'))

    if len(password) < 6:
        flash('Password must be at least 6 characters long.', 'error')
        return redirect(url_for('admin_dashboard'))

    hashed_password = generate_password_hash(password)
     # Determine is_admin based on role
    is_admin = True if role == 'admin' else False

    new_user = User(username=username, email=email, password=hashed_password, role=role,  is_admin=is_admin)
    db.session.add(new_user)
    db.session.commit()

    flash('User added successfully', 'success')
    return redirect(url_for('admin_dashboard'))

@csrf.exempt
@app.route('/manage_users')
def manage_users():
    search_query = request.args.get('search', '').strip().lower()
    if search_query:
        users = User.query.filter(
            (User.username.ilike(f'%{search_query}%')) |
            (User.email.ilike(f'%{search_query}%'))
        ).all()
    else:
        users = User.query.all()
    
    # Include required data for dashboard context
    payments = payment_history.query.order_by(payment_history.payment_time.desc()).all()

    total_revenue = sum(p.amount for p in payments)
    revenue_by_plan = {
        'Premium': sum(p.amount for p in payments if p.plan == 'Premium'),
        'Diamond': sum(p.amount for p in payments if p.plan == 'Diamond')
    }

    plan_counts = {
        'Free': 0,
        'Premium': 0,
        'Diamond': 0
    }
    for user in users:
        if user.subscription_plan:
            if "Premium" in user.subscription_plan:
                plan_counts['Premium'] += 1
            if "Diamond" in user.subscription_plan:
                plan_counts['Diamond'] += 1
        if not user.subscribed or user.subscription_plan == 'Free':
            plan_counts['Free'] += 1

    return render_template('admin_dashboard.html', users=users,
        payments=payments,
        plan_counts=plan_counts,
        total_revenue=total_revenue,
        revenue_by_plan=revenue_by_plan,
        login_logs=LoginHistory.query.all(),
        session_logs=SessionHistory.query.all(),
        signup_logs=SignupHistory.query.all(),
        start_date=None,
        end_date=None)


@csrf.exempt
@app.route('/admin/edit_user/<int:user_id>', methods=['POST']) 
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    new_username = request.form.get('username')
    new_email = request.form.get('email')
    new_password = request.form.get('password')
    new_role = request.form.get('role')

    print(f"Edit Request - ID: {user_id}, New Username: {new_username}, New Email: {new_email}")

    # Check for conflicts
    existing_username = User.query.filter(User.username == new_username, User.id != user_id).first()
    existing_email = User.query.filter(User.email == new_email, User.id != user_id).first()

    if existing_username:
        print("❌ Username already exists.")
        flash("Username already exists.", "danger")
        return redirect(url_for('admin_dashboard'))

    if existing_email:
        print("❌ Email already exists.")
        flash("Email already exists.", "danger")
        return redirect(url_for('admin_dashboard'))

    # Track whether any changes were made
    changes = False

    if new_username != user.username:
        user.username = new_username
        changes = True

    if new_email != user.email:
        user.email = new_email
        changes = True

    if new_password:
        if len(new_password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return redirect(url_for('admin_dashboard'))
        user.password = generate_password_hash(new_password)
        changes = True

    if new_role != user.role:
        user.role = new_role
        user.is_admin = True if new_role == 'admin' else False
        changes = True

    if changes:
        try:
            db.session.commit()
            print("✅ User updated successfully.")
            flash("User updated successfully.", "success")
        except Exception as e:
            db.session.rollback()
            print("❌ Commit failed:", e)
            flash("Something went wrong during update.", "danger")
    else:
        print("ℹ️ No changes were made.")
        flash("No changes were made.", "info")

    return redirect(url_for('admin_dashboard'))



# Route to Delete a User
@csrf.exempt
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()

    flash('User deleted successfully', 'success')
    return redirect(url_for('admin_dashboard'))

@csrf.exempt
@app.route('/admin/export_summary_csv')
@login_required
def export_summary_csv():
    if not current_user.is_admin:
        return "Access denied", 403

    users = User.query.all()
    payments = payment_history.query.all()

    total_revenue = sum(p.amount for p in payments)
    premium_revenue = sum(p.amount for p in payments if p.plan == 'Premium')
    diamond_revenue = sum(p.amount for p in payments if p.plan == 'Diamond')

    plan_counts = {
        'Free': 0,
        'Premium': 0,
        'Diamond': 0
    }
    for user in users:
        if user.subscription_plan:
            if "Premium" in user.subscription_plan:
                plan_counts['Premium'] += 1
            if "Diamond" in user.subscription_plan:
                plan_counts['Diamond'] += 1
        if not user.subscribed or user.subscription_plan == 'Free':
            plan_counts['Free'] += 1

    # Prepare CSV
    output = []
    output.append(['Revenue Summary'])
    output.append(['Total Revenue', f"${total_revenue:.2f}"])
    output.append(['Premium Revenue', f"${premium_revenue:.2f}"])
    output.append(['Diamond Revenue', f"${diamond_revenue:.2f}"])
    output.append([])

    output.append(['Subscription Tier Breakdown'])
    output.append(['Free Users', plan_counts['Free']])
    output.append(['Premium Users', plan_counts['Premium']])
    output.append(['Diamond Users', plan_counts['Diamond']])

    si = '\n'.join([','.join(map(str, row)) for row in output])
    return Response(
        si,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=revenue_summary.csv"}
    )

@app.route('/export_disease_frequency_csv')
@login_required
def export_disease_frequency_csv():
    if not current_user.is_admin:
        flash("Access denied", "danger")
        return redirect(url_for('home'))

    # Apply the same filters from /my-reports
    username_filter = request.args.get('username', '').strip()
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    query = Report.query.join(User)

    if username_filter:
        query = query.filter(User.username.ilike(f"%{username_filter}%"))

    if start_date_str and end_date_str:
        try:
            start_date = datetime.strptime(start_date_str, "%Y-%m-%d")
            end_date = datetime.strptime(end_date_str, "%Y-%m-%d").replace(hour=23, minute=59, second=59)
            query = query.filter(Report.timestamp.between(start_date, end_date))
        except ValueError:
            flash("Invalid date format", "warning")

    # Count diseases
    disease_counts = {}
    for report in query.all():
        disease = report.prediction.split("(")[0].strip()
        disease_counts[disease] = disease_counts.get(disease, 0) + 1

    # Generate CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Disease', 'Count'])
    for disease, count in disease_counts.items():
        writer.writerow([disease, count])

    output.seek(0)
    return Response(
        output,
        mimetype='text/csv',
        headers={
            "Content-Disposition": "attachment; filename=disease_frequency.csv"
        }
    )

@app.route('/export_signup_csv')
@login_required
def export_signup_csv():
    if not current_user.is_admin:
        flash("Access denied", "danger")
        return redirect(url_for('home'))

    username = request.args.get('signup_username', '').strip()
    start = request.args.get('signup_start', '')
    end = request.args.get('signup_end', '')

    query = SignupHistory.query

    if username:
        query = query.filter(SignupHistory.username.ilike(f"%{username}%"))

    if start and end:
     try:
        start_date = datetime.strptime(start, "%Y-%m-%d")
        end_date = datetime.strptime(end, "%Y-%m-%d") + timedelta(days=1)  # add 1 day
        query = query.filter(
            SignupHistory.timestamp >= start_date,
            SignupHistory.timestamp < end_date
        )
     except ValueError:
        flash("Invalid date format", "warning")

    logs = query.order_by(SignupHistory.timestamp.desc()).all()

    # ✅ Write CSV to memory using StringIO
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Username", "Timestamp"])
    for log in logs:
        writer.writerow([log.id, log.username, log.timestamp.strftime('%Y-%m-%d %H:%M:%S')])

    # ✅ Prepare response
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=signup_logs.csv"
    response.headers["Content-type"] = "text/csv"
    return response

@app.route('/export_login_csv')
@login_required
def export_login_csv():
    if not current_user.is_admin:
        flash("Access denied", "danger")
        return redirect(url_for('home'))

    username = request.args.get('login_username', '').strip()
    start = request.args.get('login_start', '')
    end = request.args.get('login_end', '')

    query = LoginHistory.query

    if username:
        query = query.filter(LoginHistory.username.ilike(f"%{username}%"))

    if start and end:
        try:
            start_date = datetime.strptime(start, "%Y-%m-%d")
            end_date = datetime.strptime(end, "%Y-%m-%d") + timedelta(days=1)
            query = query.filter(LoginHistory.timestamp >= start_date, LoginHistory.timestamp < end_date)
        except ValueError:
            flash("Invalid date format", "warning")

    logs = query.order_by(LoginHistory.timestamp.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "User ID", "Username", "Success", "Timestamp"])
    for log in logs:
        writer.writerow([log.id, log.user_id, log.username, "Yes" if log.success else "No", log.timestamp.strftime('%Y-%m-%d %H:%M:%S')])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=login_logs.csv"
    response.headers["Content-type"] = "text/csv"
    return response

@app.route('/export_session_csv')
@login_required
def export_session_csv():
    if not current_user.is_admin:
        flash("Access denied", "danger")
        return redirect(url_for('home'))

    username = request.args.get('session_username', '').strip()
    start = request.args.get('session_start', '')
    end = request.args.get('session_end', '')

    query = SessionHistory.query

    if username:
        query = query.filter(SessionHistory.username.ilike(f"%{username}%"))

    if start and end:
        try:
            start_date = datetime.strptime(start, "%Y-%m-%d")
            end_date = datetime.strptime(end, "%Y-%m-%d") + timedelta(days=1)
            query = query.filter(SessionHistory.timestamp >= start_date, SessionHistory.timestamp < end_date)
        except ValueError:
            flash("Invalid date format", "warning")

    logs = query.order_by(SessionHistory.timestamp.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "User ID", "Username", "Action", "Timestamp"])
    for log in logs:
        writer.writerow([log.id, log.user_id, log.username, log.action, log.timestamp.strftime('%Y-%m-%d %H:%M:%S')])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=session_logs.csv"
    response.headers["Content-type"] = "text/csv"
    return response

@app.route('/export_users_csv')
@login_required
def export_users_csv():
    if not current_user.is_admin:
        flash("Access denied", "danger")
        return redirect(url_for('home'))

    user_search = request.args.get('user_search', '').strip()
    query = User.query
    if user_search:
        query = query.filter(User.username.ilike(f"%{user_search}%"))

    users = query.order_by(User.id).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Username", "Email", "Role", "Subscribed", "Subscription Plan", "Upload Limit", "Upload Attempts", "Subscription Date"])

    for user in users:
        writer.writerow([
            user.id,
            user.username,
            user.email,
            user.role,
            "Yes" if user.subscribed else "No",
            user.subscription_plan,
            user.upload_limit,
            user.upload_attempts,
            user.subscription_date.strftime('%Y-%m-%d') if user.subscription_date else 'N/A'
        ])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=filtered_users.csv"
    response.headers["Content-type"] = "text/csv"
    return response

@csrf.exempt
@app.route('/api/login_chart_data')
@login_required
def get_login_chart_data():
    if current_user.username != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403

    login_logs = LoginHistory.query.filter_by(success=True).all()
    login_usernames = [log.username for log in login_logs]
    login_chart_data = dict(Counter(login_usernames))

    return jsonify(login_chart_data)

# ------------------- Run App -------------------

if __name__ == '__main__':
    with app.app_context():
     db.create_all()
    app.run(debug=True)



