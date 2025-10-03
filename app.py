from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_file, make_response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email
import razorpay
import os
import re
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
import uuid
import hashlib
import hmac
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
import io
import csv
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from functools import wraps
import secrets
import pyotp
from services.analytics import get_revenue_timeseries

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///moringa_orders.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return wrapper

# Enable CSRF protection across forms
csrf = CSRFProtect(app)

# Initialize Razorpay client
razorpay_client = razorpay.Client(auth=(os.getenv('RAZORPAY_KEY_ID'), os.getenv('RAZORPAY_KEY_SECRET')))

# Product Configuration
PRODUCT_CONFIG = {
    'name': 'Premium Organic Moringa Powder',
    'price_per_unit': 499,
    'unit_size': '200g',
    'shipping_charge': 50
}

# Database Models
class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

class AdminSecurity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False, unique=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    totp_secret = db.Column(db.String(32), nullable=True)

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.String(100), unique=True, nullable=False)
    razorpay_order_id = db.Column(db.String(100), nullable=True)
    razorpay_payment_id = db.Column(db.String(100), nullable=True)
    razorpay_signature = db.Column(db.String(200), nullable=True)
    
    # Customer Information
    customer_name = db.Column(db.String(100), nullable=False)
    customer_email = db.Column(db.String(100), nullable=False)
    customer_phone = db.Column(db.String(20), nullable=False)
    shipping_address = db.Column(db.Text, nullable=False)
    pincode = db.Column(db.String(10), nullable=False)
    
    # Order Details
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Float, nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    
    # Status and Timestamps
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    payment_date = db.Column(db.DateTime, nullable=True)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Admin, int(user_id))

# Helper Functions
def calculate_total(quantity):
    product_total = PRODUCT_CONFIG['price_per_unit'] * int(quantity)
    shipping = 0 if int(quantity) >= 3 else PRODUCT_CONFIG['shipping_charge']
    return product_total + shipping

def generate_order_id():
    return f"ORD_{datetime.now().strftime('%Y%m%d%H%M%S')}_{str(uuid.uuid4())[:8]}"

# Routes
@app.route('/')
def index():
    resp = make_response(render_template('index.html', PLAUSIBLE_DOMAIN=os.getenv('PLAUSIBLE_DOMAIN')))
    try:
        from flask_wtf.csrf import generate_csrf
        token = generate_csrf()
        resp.set_cookie('csrf_token', token, samesite='Lax', secure=False)
    except Exception:
        pass
    return resp

# Lightweight CSRF check for JSON APIs using cookie/header token
def _check_csrf_json():
    token = request.headers.get('X-CSRFToken') or request.headers.get('X-CSRF-Token')
    cookie = request.cookies.get('csrf_token')
    return bool(token and cookie and token == cookie)

@app.route('/api/create-order', methods=['POST'])
def create_order():
    try:
        if not _check_csrf_json():
            return jsonify({'error': 'Invalid CSRF token'}), 400
        data = request.get_json() or {}
        
        # Sanitize inputs
        def sanitize_string(s, max_len=500):
            if not isinstance(s, str):
                return ''
            s = s.strip()
            return s[:max_len]
        
        def validate_phone(phone):
            return bool(re.fullmatch(r"\d{10}", phone or ''))
        
        def validate_pincode(pin):
            return bool(re.fullmatch(r"\d{6}", pin or ''))
        
        def validate_email_format(email):
            return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email or ''))
        
        required_fields = ['name', 'email', 'phone', 'address', 'pincode', 'quantity']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        name = sanitize_string(data.get('name'), 100)
        email = sanitize_string(data.get('email'), 100)
        phone = sanitize_string(data.get('phone'), 20)
        address = sanitize_string(data.get('address'), 1000)
        pincode = sanitize_string(data.get('pincode'), 10)
        
        if not validate_email_format(email):
            return jsonify({'error': 'Invalid email format'}), 400
        if not validate_phone(phone):
            return jsonify({'error': 'Phone must be 10 digits'}), 400
        if not validate_pincode(pincode):
            return jsonify({'error': 'Pincode must be 6 digits'}), 400
        
        # Calculate total amount
        try:
            quantity = int(str(data['quantity']).strip())
            if quantity <= 0:
                return jsonify({'error': 'Quantity must be a positive integer'}), 400
        except ValueError:
            return jsonify({'error': 'Quantity must be a valid integer'}), 400
        total_amount = calculate_total(quantity)
        
        # Generate unique order ID
        order_id = generate_order_id()
        
        # Create Razorpay order
        razorpay_order = razorpay_client.order.create({
            'amount': int(total_amount * 100),  # Amount in paise
            'currency': 'INR',
            'receipt': order_id,
            'payment_capture': 1
        })
        
        # Store order in database
        order = Order(
            order_id=order_id,
            razorpay_order_id=razorpay_order['id'],
            customer_name=name,
            customer_email=email,
            customer_phone=phone,
            shipping_address=address,
            pincode=pincode,
            quantity=quantity,
            unit_price=PRODUCT_CONFIG['price_per_unit'],
            total_amount=total_amount
        )
        
        db.session.add(order)
        db.session.commit()
        
        return jsonify({
            'key': os.getenv('RAZORPAY_KEY_ID'),
            'amount': total_amount,
            'currency': 'INR',
            'name': 'Pure Moringa',
            'description': f"Order {order_id}",
            'order_id': razorpay_order['id'],
            'prefill': {
                'name': name,
                'email': email,
                'contact': phone
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/verify-payment', methods=['POST'])
def verify_payment():
    try:
        if not _check_csrf_json():
            return jsonify({'error': 'Invalid CSRF token'}), 400
        data = request.get_json()
        
        # Verify signature
        razorpay_order_id = data['razorpay_order_id']
        razorpay_payment_id = data['razorpay_payment_id']
        razorpay_signature = data['razorpay_signature']
        
        # Create signature
        body = razorpay_order_id + "|" + razorpay_payment_id
        expected_signature = hmac.new(
            key=os.getenv('RAZORPAY_KEY_SECRET').encode(),
            msg=body.encode(),
            digestmod=hashlib.sha256
        ).hexdigest()
        
        if expected_signature == razorpay_signature:
            # Update order status
            order = Order.query.filter_by(razorpay_order_id=razorpay_order_id).first()
            if order:
                order.razorpay_payment_id = razorpay_payment_id
                order.status = 'processing'
                order.payment_date = datetime.now(timezone.utc)
                db.session.commit()
                
                return jsonify({
                    'status': 'success',
                    'order_id': order.id,
                    'message': 'Payment verified successfully'
                })
            else:
                return jsonify({'error': 'Order not found'}), 404
        else:
            return jsonify({'error': 'Invalid signature'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-receipt/<int:order_id>')
def generate_receipt(order_id):
    try:
        order = Order.query.get_or_404(order_id)
        
        # Create PDF
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        
        # Header
        p.setFont("Helvetica-Bold", 20)
        p.drawString(50, height - 50, "Pure Moringa")
        p.setFont("Helvetica", 12)
        p.drawString(50, height - 70, "Premium Organic Moringa Powder")
        p.drawString(50, height - 85, "Bundelkhand, South Uttar Pradesh, India")
        
        # Order details
        y = height - 130
        p.setFont("Helvetica-Bold", 16)
        p.drawString(50, y, "Order Receipt")
        
        y -= 30
        p.setFont("Helvetica", 12)
        p.drawString(50, y, f"Order ID: {order.order_id}")
        y -= 20
        p.drawString(50, y, f"Date: {order.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
        y -= 20
        p.drawString(50, y, f"Payment ID: {order.razorpay_payment_id or 'N/A'}")
        
        # Customer details
        y -= 40
        p.setFont("Helvetica-Bold", 14)
        p.drawString(50, y, "Customer Details:")
        y -= 20
        p.setFont("Helvetica", 12)
        p.drawString(50, y, f"Name: {order.customer_name}")
        y -= 15
        p.drawString(50, y, f"Email: {order.customer_email}")
        y -= 15
        p.drawString(50, y, f"Phone: {order.customer_phone}")
        y -= 15
        p.drawString(50, y, f"Address: {order.shipping_address}")
        y -= 15
        p.drawString(50, y, f"Pincode: {order.pincode}")
        
        # Order items
        y -= 40
        p.setFont("Helvetica-Bold", 14)
        p.drawString(50, y, "Order Items:")
        y -= 20
        p.setFont("Helvetica", 12)
        p.drawString(50, y, f"Moringa Powder (200g pouch) x {order.quantity}")
        p.drawString(400, y, f"₹{order.total_amount:.2f}")
        
        # Total
        y -= 30
        p.setFont("Helvetica-Bold", 14)
        p.drawString(50, y, f"Total Amount: ₹{order.total_amount:.2f}")
        
        # Footer
        y -= 60
        p.setFont("Helvetica", 10)
        p.drawString(50, y, "Thank you for choosing Pure Moringa!")
        p.drawString(50, y - 15, "For any queries, contact us at info@puremoringa.com")
        
        p.showPage()
        p.save()
        
        buffer.seek(0)
        
        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=receipt_{order.order_id}.pdf'
        
        return response
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

class AdminLoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    otp = StringField('Authenticator Code (if MFA enabled)')
    remember_me = BooleanField('Remember me')
    submit = SubmitField('Login')

@csrf.exempt
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()
    if request.method == 'POST' and request.is_json:
        data = request.get_json()
        username = (data.get('username') or '').strip().lower()
        password = data.get('password')
        otp_val = data.get('otp')
        admin = db.session.query(Admin).filter(db.func.lower(Admin.username) == username).first()
        if admin and check_password_hash(admin.password_hash, password):
            sec = AdminSecurity.query.filter_by(admin_id=admin.id).first()
            if sec and sec.mfa_enabled:
                if not otp_val or not sec.totp_secret or not pyotp.TOTP(sec.totp_secret).verify(otp_val):
                    return jsonify({'error': 'Invalid MFA code'}), 401
            login_user(admin)
            app.logger.info(f"Admin '{username}' logged in via JSON")
            return jsonify({'status': 'success', 'redirect': '/admin/dashboard'})
        app.logger.warning(f"Admin login failed for '{username}' via JSON")
        return jsonify({'error': 'Invalid credentials'}), 401

    if request.method == 'POST':
        if form.validate_on_submit():
            username_input = (form.username.data or '').strip().lower()
            admin = db.session.query(Admin).filter(db.func.lower(Admin.username) == username_input).first()
            if admin and check_password_hash(admin.password_hash, form.password.data):
                sec = AdminSecurity.query.filter_by(admin_id=admin.id).first()
                if sec and sec.mfa_enabled:
                    otp_val = form.otp.data
                    if not otp_val or not sec.totp_secret or not pyotp.TOTP(sec.totp_secret).verify(otp_val):
                        flash('Invalid MFA code', 'error')
                        app.logger.warning(f"Admin '{username_input}' provided invalid MFA code")
                        return render_template('admin_login.html', form=form)
                login_user(admin, remember=form.remember_me.data)
                app.logger.info(f"Admin '{username_input}' logged in successfully")
                return redirect(url_for('admin_dashboard'))
            flash('Invalid credentials', 'error')
            app.logger.warning(f"Admin login failed for '{username_input}' via form")
        else:
            # Form submission failed (e.g., CSRF or validation errors)
            if hasattr(form, 'csrf_token') and form.csrf_token.errors:
                flash('Session expired or invalid CSRF token. Please refresh and try again.', 'error')
                app.logger.warning('Admin login CSRF validation failed')
            else:
                flash('Please correct the highlighted errors and try again.', 'error')
                app.logger.warning('Admin login form validation failed')
            return render_template('admin_login.html', form=form)
    return render_template('admin_login.html', form=form)


def customer_login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('customer_id'):
            return redirect(url_for('customer_login'))
        return f(*args, **kwargs)
    return wrapper

# Forms
class CustomerRegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class CustomerLoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Customer authentication routes
@app.route('/customer/register', methods=['GET', 'POST'])
def customer_register():
    form = CustomerRegisterForm()
    if form.validate_on_submit():
        existing = Customer.query.filter_by(email=form.email.data.lower()).first()
        if existing:
            flash('An account with this email already exists. Please log in.', 'error')
            return redirect(url_for('customer_login'))
        customer = Customer(
            name=form.name.data.strip(),
            email=form.email.data.lower().strip(),
            phone=form.phone.data.strip(),
            password_hash=generate_password_hash(form.password.data)
        )
        db.session.add(customer)
        db.session.commit()
        session['customer_id'] = customer.id
        flash('Registration successful. Welcome!', 'success')
        return redirect(url_for('customer_dashboard'))
    return render_template('customer_register.html', form=form)

@app.route('/customer/login', methods=['GET', 'POST'])
def customer_login():
    form = CustomerLoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            email_input = ((form.email.data or '').strip().lower())
            customer = Customer.query.filter_by(email=email_input).first()
            if customer and check_password_hash(customer.password_hash, form.password.data):
                session['customer_id'] = customer.id
                flash('Logged in successfully.', 'success')
                app.logger.info(f"Customer '{email_input}' logged in successfully")
                return redirect(url_for('index'))
            # Keep generic error for security, but log specifics
            if not customer:
                app.logger.warning(f"Customer login failed: account not found for '{email_input}'")
            else:
                app.logger.warning(f"Customer login failed: incorrect password for '{email_input}'")
            flash('Invalid credentials', 'error')
        else:
            if hasattr(form, 'csrf_token') and form.csrf_token.errors:
                flash('Session expired or invalid CSRF token. Please refresh and try again.', 'error')
                app.logger.warning('Customer login CSRF validation failed')
            else:
                flash('Please correct the highlighted errors and try again.', 'error')
                app.logger.warning('Customer login form validation failed')
            return render_template('customer_login.html', form=form)
    return render_template('customer_login.html', form=form)

@app.route('/customer/logout')
@customer_login_required
def customer_logout():
    session.pop('customer_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('customer_login'))

@app.route('/customer/dashboard')
@customer_login_required
def customer_dashboard():
    customer_id = session.get('customer_id')
    customer = Customer.query.get_or_404(customer_id)
    orders = Order.query.filter_by(customer_email=customer.email).order_by(Order.created_at.desc()).all()
    return render_template('customer_dashboard.html', customer=customer, orders=orders)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # Get filter parameters from request
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    status_filter = request.args.get('status', '')
    search_query = request.args.get('search', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    # Build query for orders
    orders_query = Order.query
    
    # Apply status filter
    if status_filter:
        orders_query = orders_query.filter(Order.status == status_filter)
    
    # Apply search filter
    if search_query:
        search_pattern = f"%{search_query}%"
        orders_query = orders_query.filter(
            or_(
                Order.order_id.ilike(search_pattern),
                Order.customer_name.ilike(search_pattern),
                Order.customer_email.ilike(search_pattern),
                Order.customer_phone.ilike(search_pattern)
            )
        )
    
    # Apply date filters
    if date_from:
        try:
            from_date = datetime.strptime(date_from, '%Y-%m-%d')
            orders_query = orders_query.filter(Order.created_at >= from_date)
        except ValueError:
            pass
    
    if date_to:
        try:
            to_date = datetime.strptime(date_to, '%Y-%m-%d')
            to_date = to_date.replace(hour=23, minute=59, second=59)
            orders_query = orders_query.filter(Order.created_at <= to_date)
        except ValueError:
            pass
    
    # Order by creation date (newest first)
    orders_query = orders_query.order_by(Order.created_at.desc())
    
    # Paginate orders
    pagination = orders_query.paginate(
        page=page, 
        per_page=per_page, 
        error_out=False
    )
    
    # Get order statistics
    total_orders = Order.query.count()
    pending_orders = Order.query.filter_by(status='pending').count()
    processing_orders = Order.query.filter_by(status='processing').count()
    shipped_orders = Order.query.filter_by(status='shipped').count()
    delivered_orders = Order.query.filter_by(status='delivered').count()
    cancelled_orders = Order.query.filter_by(status='cancelled').count()
    
    # Calculate total revenue (only from paid orders)
    paid_statuses = ['processing', 'shipped', 'delivered']
    total_revenue = db.session.query(db.func.sum(Order.total_amount)).filter(
        Order.status.in_(paid_statuses)
    ).scalar() or 0
    
    # Calculate today's revenue
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = datetime.now(timezone.utc).replace(hour=23, minute=59, second=59, microsecond=999999)
    today_revenue = db.session.query(db.func.sum(Order.total_amount)).filter(
        Order.status.in_(paid_statuses),
        Order.created_at >= today_start,
        Order.created_at <= today_end
    ).scalar() or 0
    
    # Create stats dictionary for template
    stats = {
        'total_orders': total_orders,
        'total_revenue': float(total_revenue),
        'pending_orders': pending_orders,
        'today_revenue': float(today_revenue)
    }
    
    # Get monthly revenue data for the last 12 months
    monthly_revenue = []
    for i in range(12):
        month_start = datetime.now(timezone.utc).replace(day=1) - timedelta(days=30*i)
        month_end = (month_start + timedelta(days=32)).replace(day=1) - timedelta(days=1)
        
        revenue = db.session.query(db.func.sum(Order.total_amount)).filter(
            Order.status.in_(paid_statuses),
            Order.created_at >= month_start,
            Order.created_at <= month_end
        ).scalar() or 0
        
        monthly_revenue.append({
            'month': month_start.strftime('%b %Y'),
            'revenue': float(revenue)
        })
    
    monthly_revenue.reverse()  # Show oldest to newest
    
    return render_template('admin_dashboard.html', 
                         stats=stats,
                         pagination=pagination,
                         orders=pagination.items,
                         monthly_revenue=monthly_revenue)

@app.route('/admin/logout')
@admin_required
def admin_logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('admin_login'))

@app.route('/api/admin/orders')
@admin_required
def get_orders():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        status_filter = request.args.get('status', '')
        search_query = request.args.get('search', '')
        
        # Build query
        query = Order.query
        
        # Apply status filter
        if status_filter:
            query = query.filter(Order.status == status_filter)
        
        # Apply search filter
        if search_query:
            search_pattern = f"%{search_query}%"
            query = query.filter(
                db.or_(
                    Order.order_id.ilike(search_pattern),
                    Order.customer_name.ilike(search_pattern),
                    Order.customer_email.ilike(search_pattern),
                    Order.customer_phone.ilike(search_pattern)
                )
            )
        
        # Order by creation date (newest first)
        query = query.order_by(Order.created_at.desc())
        
        # Paginate
        pagination = query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        orders = []
        for order in pagination.items:
            orders.append({
                'id': order.id,
                'order_id': order.order_id,
                'customer_name': order.customer_name,
                'customer_email': order.customer_email,
                'customer_phone': order.customer_phone,
                'quantity': order.quantity,
                'total_amount': order.total_amount,
                'status': order.status,
                'created_at': order.created_at.isoformat(),
                'payment_date': order.payment_date.isoformat() if order.payment_date else None,
                'razorpay_payment_id': order.razorpay_payment_id
            })
        
        return jsonify({
            'orders': orders,
            'pagination': {
                'page': pagination.page,
                'pages': pagination.pages,
                'per_page': pagination.per_page,
                'total': pagination.total,
                'has_next': pagination.has_next,
                'has_prev': pagination.has_prev
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/images/<path:filename>')
def images(filename):
    return send_from_directory('images', filename)

@app.route('/api/admin/orders/<int:order_id>')
@admin_required
def api_admin_order_detail(order_id):
    try:
        order = Order.query.get_or_404(order_id)
        return jsonify({
            'id': order.id,
            'order_id': order.order_id,
            'customer_name': order.customer_name,
            'customer_email': order.customer_email,
            'customer_phone': order.customer_phone,
            'shipping_address': order.shipping_address,
            'pincode': order.pincode,
            'quantity': order.quantity,
            'unit_price': order.unit_price,
            'total_amount': order.total_amount,
            'status': order.status,
            'created_at': order.created_at.isoformat(),
            'payment_date': order.payment_date.isoformat() if order.payment_date else None,
            'razorpay_order_id': order.razorpay_order_id,
            'razorpay_payment_id': order.razorpay_payment_id
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/orders/<int:order_id>/edit', methods=['PUT'])
@csrf.exempt
@admin_required
def edit_order(order_id):
    try:
        order = Order.query.get_or_404(order_id)
        data = request.get_json()
        
        # Update allowed fields
        if 'customer_name' in data:
            order.customer_name = data['customer_name']
        if 'customer_email' in data:
            order.customer_email = data['customer_email']
        if 'customer_phone' in data:
            order.customer_phone = data['customer_phone']
        if 'shipping_address' in data:
            order.shipping_address = data['shipping_address']
        if 'pincode' in data:
            order.pincode = data['pincode']
        if 'quantity' in data:
            new_quantity = int(data['quantity'])
            if new_quantity > 0:
                order.quantity = new_quantity
                # Recalculate total amount
                order.total_amount = calculate_total(new_quantity)
        
        order.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Order updated successfully',
            'order': {
                'id': order.id,
                'order_id': order.order_id,
                'customer_name': order.customer_name,
                'customer_email': order.customer_email,
                'customer_phone': order.customer_phone,
                'shipping_address': order.shipping_address,
                'pincode': order.pincode,
                'quantity': order.quantity,
                'total_amount': order.total_amount,
                'status': order.status,
                'updated_at': order.updated_at.isoformat()
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/orders/<int:order_id>/status', methods=['PUT'])
@csrf.exempt
@admin_required
def update_order_status(order_id):
    try:
        order = Order.query.get_or_404(order_id)
        data = request.get_json()
        
        new_status = data.get('status')
        known_statuses = ['pending', 'processing', 'shipped', 'delivered', 'cancelled']
        
        if new_status not in known_statuses:
            return jsonify({'error': 'Invalid status'}), 400
        
        order.status = new_status
        order.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'Order status updated to {new_status}',
            'order': {
                'id': order.id,
                'status': order.status,
                'updated_at': order.updated_at.isoformat()
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/orders/<int:order_id>/delete', methods=['DELETE'])
@csrf.exempt
@admin_required
def delete_order(order_id):
    try:
        order = Order.query.get_or_404(order_id)
        db.session.delete(order)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Order deleted successfully'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/export-orders')
@admin_required
def export_orders():
    try:
        # Get all orders
        orders = Order.query.order_by(Order.created_at.desc()).all()
        
        # Create CSV content
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Order ID', 'Customer Name', 'Email', 'Phone', 'Address', 'Pincode', 
                        'Quantity', 'Total Amount', 'Status', 'Created At', 'Payment Date', 'Payment ID'])
        
        # Write data
        for order in orders:
            writer.writerow([
                order.order_id,
                order.customer_name,
                order.customer_email,
                order.customer_phone,
                order.shipping_address,
                order.pincode,
                order.quantity,
                order.total_amount,
                order.status,
                order.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                order.payment_date.strftime('%Y-%m-%d %H:%M:%S') if order.payment_date else '',
                order.razorpay_payment_id or ''
            ])
        
        output.seek(0)
        
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename=orders_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        
        return response
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def init_db():
    """Initialize the database with tables and default admin user."""
    with app.app_context():
        db.create_all()
        
        # Create default admin if it doesn't exist
        admin = Admin.query.filter_by(username='admin').first()
        if not admin:
            admin = Admin(
                username='admin',
                password_hash=generate_password_hash('admin123')
            )
            db.session.add(admin)
            db.session.commit()
            print("Default admin user created: admin/admin123")

@app.route('/api/payment-cancel', methods=['POST'])
def payment_cancel():
    try:
        if not _check_csrf_json():
            return jsonify({'error': 'Invalid CSRF token'}), 400
        
        data = request.get_json()
        razorpay_order_id = data.get('razorpay_order_id')
        
        if razorpay_order_id:
            # Update order status to cancelled
            order = Order.query.filter_by(razorpay_order_id=razorpay_order_id).first()
            if order:
                order.status = 'cancelled'
                order.updated_at = datetime.now(timezone.utc)
                db.session.commit()
        
        return jsonify({'status': 'cancelled'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/send-receipt', methods=['POST'])
def send_receipt():
    try:
        if not _check_csrf_json():
            return jsonify({'error': 'Invalid CSRF token'}), 400
        
        data = request.get_json()
        order_id = data.get('order_id')
        
        if not order_id:
            return jsonify({'error': 'Order ID is required'}), 400
        
        order = Order.query.get_or_404(order_id)
        
        # Here you would implement email sending logic
        # For now, we'll just return success
        
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.mime.base import MIMEBase
        from email import encoders
        
        # Email configuration
        smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        smtp_port = int(os.getenv('SMTP_PORT', '587'))
        smtp_user = os.getenv('SMTP_USER')
        smtp_pass = os.getenv('SMTP_PASS')
        
        if not all([smtp_user, smtp_pass]):
            return jsonify({'error': 'Email configuration not found'}), 500
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = smtp_user
        msg['To'] = order.customer_email
        msg['Subject'] = f"Receipt for Order {order.order_id}"
        
        body = f"""
        Dear {order.customer_name},
        
        Thank you for your order! Please find your receipt attached.
        
        Order Details:
        - Order ID: {order.order_id}
        - Total Amount: ₹{order.total_amount}
        - Status: {order.status}
        
        Best regards,
        Pure Moringa Team
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email
        server = smtplib.SMTP(smtp_server, smtp_port)
        use_tls = os.getenv('SMTP_USE_TLS', 'true').lower() == 'true'
        if use_tls:
            server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        
        return jsonify({'status': 'sent'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def run_server():
    """Initialize database and start the Flask development server."""
    init_db()
    port = int(os.getenv('FLASK_RUN_PORT', '5001'))
    host = os.getenv('FLASK_RUN_HOST', '0.0.0.0')
    app.run(debug=True, host=host, port=port, use_reloader=False)

@app.route('/admin/mfa')
@admin_required
def admin_mfa():
    sec = AdminSecurity.query.filter_by(admin_id=current_user.id).first()
    if not sec:
        sec = AdminSecurity(admin_id=current_user.id, mfa_enabled=False)
        db.session.add(sec)
        db.session.commit()
    
    secret = None
    otp_uri = None
    if not sec.mfa_enabled:
        secret = session.get('mfa_setup_secret')
        if not secret:
            secret = pyotp.random_base32()
            session['mfa_setup_secret'] = secret
        issuer = 'Pure Moringa Admin'
        label = f"{current_user.username}"
        otp_uri = pyotp.TOTP(secret).provisioning_uri(name=label, issuer_name=issuer)
    
    return render_template('admin_mfa.html', sec=sec, secret=secret, otp_uri=otp_uri)

@app.route('/admin/mfa/enable', methods=['POST'])
@admin_required
def admin_mfa_enable():
    code = request.form.get('otp', '').strip()
    secret = session.get('mfa_setup_secret')
    if not secret:
        flash('MFA setup was not initiated. Please start setup again.', 'error')
        return redirect(url_for('admin_mfa'))
    if not code or not pyotp.TOTP(secret).verify(code):
        flash('Invalid verification code. Please try again.', 'error')
        return redirect(url_for('admin_mfa'))
    sec = AdminSecurity.query.filter_by(admin_id=current_user.id).first()
    if not sec:
        sec = AdminSecurity(admin_id=current_user.id)
        db.session.add(sec)
    sec.mfa_enabled = True
    sec.totp_secret = secret
    db.session.commit()
    session.pop('mfa_setup_secret', None)
    flash('Multi-Factor Authentication has been enabled successfully.', 'success')
    return redirect(url_for('admin_mfa'))

@app.route('/admin/mfa/disable', methods=['POST'])
@admin_required
def admin_mfa_disable():
    code = request.form.get('otp', '').strip()
    sec = AdminSecurity.query.filter_by(admin_id=current_user.id).first()
    if not sec or not sec.mfa_enabled:
        flash('MFA is not currently enabled.', 'error')
        return redirect(url_for('admin_mfa'))
    if not sec.totp_secret or not code or not pyotp.TOTP(sec.totp_secret).verify(code):
        flash('Invalid code. Cannot disable MFA.', 'error')
        return redirect(url_for('admin_mfa'))
    sec.mfa_enabled = False
    sec.totp_secret = None
    db.session.commit()
    flash('Multi-Factor Authentication has been disabled.', 'success')
    return redirect(url_for('admin_mfa'))

@app.route('/api/admin/revenue-timeseries')
@admin_required
def api_revenue_timeseries():
    days = request.args.get('days', 30, type=int)
    status_arg = (request.args.get('status', '') or '').strip().lower()
    data = get_revenue_timeseries(db, Order, days, status_arg)
    return jsonify(data)