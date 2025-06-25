import io
import os
import pickle
import base64
import logging
import json
import uuid
from functools import wraps
from datetime import datetime, timezone
import pandas as pd
from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
)
# from flask_login import login_required  # Removed unused import
from flask_login import login_required 
from email.mime.text import MIMEText
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from flask_migrate import Migrate


# Load environment variables
load_dotenv()

# Initialize extensions
db = SQLAlchemy()
bcrypt = Bcrypt()
migrate = Migrate()

# Constants
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

# Flask App Setup
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'super_secret_default_key_change_me!')
BOOKINGS_FILE = 'bookings.json'
# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///laundry.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions with app
db.init_app(app)
bcrypt.init_app(app)
migrate.init_app(app, db)


# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')
    active = db.Column(db.Boolean, default=True)
    theme = db.Column(db.String(50), default='light')
    timezone = db.Column(db.String(50), default='UTC')
    notification = db.Column(db.String(10), default='on')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    def __init__(self, username, email, password, role='user'):
        self.username = username
        self.email = email
        self.set_password(password)
        self.role = role

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"{self.username}"

    @property
    def is_admin(self):
        return self.role == 'admin'

    @property
    def is_client(self):
        return self.role == 'client'


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String(150), nullable=False)
    service_type = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), nullable=False, default="pending")
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    total_price = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship('OrderItem', backref='order', lazy=True)
    
    def __init__(self, customer_name, service_type, price, total_price, status="pending", user_id=None):       
        self.customer_name = customer_name
        self.service_type = service_type
        self.price = price
        self.total_price = total_price
        self.status = status
        self.user_id = user_id

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.String(100), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(250))
    delivery_option = db.Column(db.String(20))
    washing_type = db.Column(db.String(50))
    delivery_type = db.Column(db.String(50))
    clothes = db.Column(db.Text)  # JSON string
    subtotal = db.Column(db.Integer)
    delivery_fee = db.Column(db.Integer)
    total = db.Column(db.Integer)
    payment_method = db.Column(db.String(50))
    payment_reference = db.Column(db.String(100))
    special_instructions = db.Column(db.Text)
    status = db.Column(db.String(20), default="pending")
    created_at = db.Column(db.DateTime)
    
    def __init__(self, order_id, full_name, email, phone, address, delivery_option, washing_type, delivery_type, clothes, subtotal, delivery_fee, total, payment_method, payment_reference='', special_instructions='', created_at=None):
        self.order_id = order_id
        self.full_name = full_name
        self.email = email
        self.phone = phone
        self.address = address
        self.delivery_option = delivery_option
        self.washing_type = washing_type
        self.delivery_type = delivery_type
        self.clothes = clothes
        self.subtotal = subtotal
        self.delivery_fee = delivery_fee
        self.total = total
        self.payment_method = payment_method
        self.payment_reference = payment_reference
        self.special_instructions = special_instructions
        if created_at is None:
            created_at = datetime.now()
        self.created_at = created_at

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    service = db.Column(db.String(100), nullable=False)
    num_clothes = db.Column(db.Integer, nullable=False)
    weight = db.Column(db.Float, nullable=False)
    item_total = db.Column(db.Float, nullable=False)
    
    def __init__(self, order_id, service, num_clothes, weight, item_total):
        self.order_id = order_id
        self.service = service
        self.num_clothes = num_clothes
        self.weight = weight
        self.item_total = item_total
# Create tables
with app.app_context():
    db.create_all()

# --- Gmail API helper ---
def get_gmail_service():
    creds = None
    token_path = os.path.join(app.instance_path, 'token.pickle')
    
    if os.path.exists(token_path):
        with open(token_path, 'rb') as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', 
                SCOPES
            )
            creds = flow.run_local_server(port=0)
        
        os.makedirs(app.instance_path, exist_ok=True)
        with open(token_path, 'wb') as token:
            pickle.dump(creds, token)
    
    return build('gmail', 'v1', credentials=creds)


def send_email(to, subject, body_text):
    try:
        service = get_gmail_service()
        sender = os.getenv("GMAIL_USER")
        message = MIMEText(body_text)
        message['to'] = to
        message['from'] = sender
        message['subject'] = subject
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
        body = {'raw': raw}
        
        service.users().messages().send(userId='me', body=body).execute()
        return True
    except Exception as e:
        app.logger.error(f"Failed to send email: {str(e)}")
        return False

# --- Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        user = db.session.get(User, session['user_id'])
        if not user or not user.is_admin:
            flash('Unauthorized access.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return wrapper


def get_admin_stats():
    return {
        "total_users": User.query.count(),
        "total_orders": Order.query.count()
    }

# --- Routes ---
@app.route("/")
def home():
    return render_template("index.html")

@app.route('/submit-booking', methods=['POST'])
def submit_booking():
    data = request.get_json()
    order_id = f"ORD-{uuid.uuid4().hex[:8].upper()}"

    new_booking = Booking(
        order_id=order_id,
        full_name=data['customerDetails']['fullName'],
        email=data['customerDetails']['email'],
        phone=data['customerDetails']['phone'],
        address=data['customerDetails'].get('address', ''),
        delivery_option=data['deliveryOption'],
        washing_type=data['washingType'],
        delivery_type=data['deliveryType'],
        clothes=json.dumps(data['clothes']),
        subtotal=data['subtotal'],
        delivery_fee=data['deliveryFee'],
        total=data['total'],
        payment_method=data['customerDetails']['paymentMethod'],
        payment_reference=data.get('paymentReference', ''),
        special_instructions=data.get('specialInstructions', ''),
        created_at=datetime.now()
    )

    # Save to database
    db.session.add(new_booking)
    db.session.commit()

    # Save to bookings.json (as archive)
    new_json_entry = {
        'order_id': new_booking.order_id,
        'full_name': new_booking.full_name,
        'email': new_booking.email,
        'phone': new_booking.phone,
        'address': new_booking.address,
        'delivery_option': new_booking.delivery_option,
        'washing_type': new_booking.washing_type,
        'delivery_type': new_booking.delivery_type,
        'clothes': json.loads(new_booking.clothes),
        'subtotal': new_booking.subtotal,
        'delivery_fee': new_booking.delivery_fee,
        'total': new_booking.total,
        'payment_method': new_booking.payment_method,
        'payment_reference': new_booking.payment_reference,
        'special_instructions': new_booking.special_instructions,
        'status': new_booking.status,
        'created_at': new_booking.created_at.isoformat()
    }

    # Append to JSON file
    bookings = []
    if os.path.exists(BOOKINGS_FILE):
        with open(BOOKINGS_FILE, 'r') as f:
            bookings = json.load(f)

    bookings.append(new_json_entry)

    with open(BOOKINGS_FILE, 'w') as f:
        json.dump(bookings, f, indent=4)

    return jsonify({'message': 'Booking saved!', 'order_id': order_id})
def migrate_json_to_sql():
    if not os.path.exists(BOOKINGS_FILE):
        app.logger.warning(f"{BOOKINGS_FILE} not found for migration.")
        return

    with open(BOOKINGS_FILE, 'r') as f:
        data = json.load(f)

    with app.app_context():
        for item in data:
            try:
                booking = Booking(
                    order_id=item.get("order_id", f"ORD-{uuid.uuid4().hex[:8].upper()}"),
                    full_name=item.get("full_name", "Unknown"),
                    email=item.get("email", ""),
                    phone=item.get("phone", ""),
                    address=item.get("address", ""),
                    delivery_option=item.get("delivery_option", ""),
                    washing_type=item.get("washing_type", ""),
                    delivery_type=item.get("delivery_type", ""),
                    clothes=json.dumps(item.get("clothes", [])),
                    subtotal=item.get("subtotal", 0),
                    delivery_fee=item.get("delivery_fee", 0),
                    total=item.get("total", 0),
                    payment_method=item.get("payment_method", ""),
                    payment_reference=item.get("payment_reference", ""),
                    special_instructions=item.get("special_instructions", ""),
                    created_at=datetime.fromisoformat(item.get("created_at")) if item.get("created_at") else datetime.utcnow()
                )
                # Set status separately since Booking.__init__ does not accept it
                booking.status = item.get("status", "pending")
                db.session.add(booking)
            except Exception as e:
                app.logger.error(f"Skipping bad record {item}: {e}")

        db.session.commit()
@app.route("/dashboard")
@login_required
def dashboard():
    user = db.session.get(User, session["user_id"])
    return render_template("dashboard.html", user=user)

@app.route("/admin")
@admin_required
def admin():
    user = db.session.get(User, session["user_id"])

    # Get all bookings ordered by date
    bookings_query = Booking.query.order_by(Booking.created_at.desc()).all()

    # Prepare booking data
    bookings = [{
        'order_id': b.order_id,
        'name': b.full_name,
        'email': b.email,
        'phone': b.phone,
        'total': b.total,
        'status': b.status,
        'date': b.created_at.strftime('%Y-%m-%d %H:%M')
    } for b in bookings_query]

    # Calculate admin stats
    stats = {
        'total_bookings': len(bookings),
        'total_revenue': sum(b['total'] for b in bookings),
        'pending': sum(1 for b in bookings if b['status'] == 'pending'),
        'completed': sum(1 for b in bookings if b['status'] == 'completed')
    }

    # Return JSON if it's an API call
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({
            'bookings': bookings,
            'stats': stats
        })

    # Otherwise, render the admin dashboard template
    return render_template(
        "admin.html",
        bookings=bookings,
        stats=stats,
        user=user
    )
@app.route('/admin/booking/<order_id>')
@admin_required
def get_booking_by_id(order_id):
    booking = Booking.query.filter_by(order_id=order_id).first()
    
    if not booking:
        return jsonify({'error': 'Booking not found'}), 404

    return jsonify({
        'order_id': booking.order_id,
        'name': booking.full_name,  # ⛔ Could be None or misnamed
        'email': booking.email,
        'phone': booking.phone,
        'address': booking.address,
        'delivery_option': booking.delivery_option,
        'washing_type': booking.washing_type,
        'delivery_type': booking.delivery_type,
        'status': booking.status,
        'total': booking.total,
        'payment_method': booking.payment_method,
        'payment_status': 'Paid' if booking.payment_reference else 'Unpaid',
        'special_instruction': booking.special_instructions,
        'created_at': booking.created_at.strftime('%Y-%m-%d %H:%M')
    })

@app.route('/export-excel')
@admin_required
def export_excel():
    bookings = Booking.query.all()
    data = [{
        'Order ID': b.order_id,
        'Customer': b.full_name,
        'Email': b.email,
        'Phone': b.phone,
        'Total': b.total,
        'Status': b.status,
        'Date': b.created_at.strftime('%Y-%m-%d %H:%M')
    } for b in bookings]

    df = pd.DataFrame(data)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Bookings')

    output.seek(0)
    return send_file(output, attachment_filename="bookings.xlsx", as_attachment=True)

@app.route("/about")
def about():
    return render_template("about.html")
@app.route("/price")
def price():
    return render_template("price.html")
@app.route("/service")
def service():
    return render_template("service.html")


@app.route("/booking", methods=["GET", "POST"])
def booking():
    if "user_id" in session:
        user = db.session.get(User, session["user_id"])
        if user:
            return redirect(url_for('admin' if user.is_admin else 'dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not email or not password:
            flash("All fields are required!", "warning")
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session["user_id"] = user.id
            session["role"] = user.role
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()
            
            flash("Logged in successfully!", "success")
            return redirect(url_for('admin' if user.is_admin else 'dashboard'))
        
        flash("Invalid email or password!", "danger")

    return render_template('login.html')


@app.route('/admin/orders')
@admin_required
def admin_orders():
    orders = Order.query.order_by(Order.created_at.desc()).all()
    return render_template("admin_orders.html", orders=orders)

@app.route('/create_admin', methods=['GET', 'POST'])
def create_admin():
    if User.query.filter_by(role='admin').first():
        flash("Admin already exists.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([username, email, password, confirm_password]):
            flash("All fields are required.", "danger")
            return redirect(url_for('create_admin'))
        
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('create_admin'))
        
        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return redirect(url_for('create_admin'))
        
        try:
            new_admin = User(
                username=username,
                email=email,
                password=password,
                role='admin'
            )
            db.session.add(new_admin)
            db.session.commit()
            flash("Admin account created! You can now log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error creating admin: {str(e)}")
            flash("An error occurred while creating admin account.", "danger")
    
    return render_template('create_admin.html')
@app.route("/admin/booking/<order_id>")
@admin_required
def get_booking_details(order_id):
    booking = Booking.query.filter_by(order_id=order_id).first()

    if not booking:
        return jsonify({"error": "Booking not found"}), 404

    return jsonify({
        "order_id": booking.order_id,
        "name": booking.full_name,
        "email": booking.email,
        "phone": booking.phone,
        "address": booking.address,
        "delivery_option": booking.delivery_option,
        "washing_type": booking.washing_type,
        "delivery_type": booking.delivery_type,
        "clothes": json.loads(booking.clothes),
        "subtotal": booking.subtotal,
        "delivery_fee": booking.delivery_fee,
        "total": booking.total,
        "payment_method": booking.payment_method,
        "payment_reference": booking.payment_reference,
        "special_instructions": booking.special_instructions,
        "status": booking.status,
        "created_at": booking.created_at.strftime("%Y-%m-%d %H:%M")
    })

@app.route("/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    search_query = request.args.get("search", "")
    role_filter = request.args.get("role", "")
    active_filter = request.args.get("active", "")

    users_query = User.query

    if search_query:
        users_query = users_query.filter(
            User.username.ilike(f"%{search_query}%") |
            User.email.ilike(f"%{search_query}%")
        )

    if role_filter in ["admin", "staff", "user"]:
        users_query = users_query.filter_by(role=role_filter)

    if active_filter in ["true", "false"]:
        users_query = users_query.filter_by(active=(active_filter == "true"))

    users = users_query.all()

    if request.method == "POST":
        user_id = request.form.get("user_id")
        user = User.query.get(user_id)

        if request.form.get("delete_user"):
            if user:
                db.session.delete(user)
                db.session.commit()
                flash(f"User {user.username} deleted.", "warning")
            return redirect(url_for("admin_settings"))

        if user:
            user.theme = request.form.get("theme")
            user.timezone = request.form.get("timezone")
            user.notification = request.form.get("notification")
            user.active = request.form.get("active") == "on"
            user.role = request.form.get("role")
            db.session.commit()
            flash(f"Settings updated for {user.username}.", "success")

        return redirect(url_for("admin_settings"))

    return render_template(
        "admin_settings.html",
        users=users,
        search_query=search_query,
        role_filter=role_filter,
        active_filter=active_filter
    )

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not all([username, email, password, confirm_password]):
            flash("All fields are required.", "danger")
            return redirect(url_for('register'))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return redirect(url_for('register'))

        try:
            new_user = User(
                username=username,
                email=email,
                password=password
            )
            db.session.add(new_user)
            db.session.commit()
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Registration error: {str(e)}")
            flash("An error occurred during registration.", "danger")
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if "user_id" in session:
        user = db.session.get(User, session["user_id"])
        if user:
            return redirect(url_for('admin' if user.is_admin else 'dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not email or not password:
            flash("All fields are required!", "warning")
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session["user_id"] = user.id
            session["role"] = user.role
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()
            
            flash("Logged in successfully!", "success")
            return redirect(url_for('admin' if user.is_admin else 'dashboard'))
        
        flash("Invalid email or password!", "danger")

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('home'))

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')

        if not all([name, email, message]):
            flash("All fields are required!", "danger")
            return redirect(url_for('contact'))

        try:
            recipient = os.getenv("RECEIVER_EMAIL") or os.getenv("GMAIL_USER")
            subject = f"New message from {name}"
            body_text = f"Name: {name}\nEmail: {email}\n\nMessage:\n{message}"

            if send_email(recipient, subject, body_text):
                flash("Thanks for reaching out! We got your message.", "success")
            else:
                flash("Failed to send your message. Try again later.", "danger")
        except Exception as e:
            app.logger.error(f"Contact form error: {str(e)}")
            flash("An error occurred while sending your message.", "danger")

        return redirect(url_for('contact'))

    return render_template('contact.html')

# Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    return render_template('500.html'), 500

if __name__ == "__main__":
    app.run(debug=True)
