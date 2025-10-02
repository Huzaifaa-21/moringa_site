from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_file, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email
import razorpay
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
import uuid
import hashlib
import hmac
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
import io
import csv
from werkzeug.security import generate_password_hash, check_password_hash

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    payment_date = db.Column(db.DateTime, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

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
    return render_template('index.html')

@app.route('/api/create-order', methods=['POST'])
def create_order():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'email', 'phone', 'address', 'pincode', 'quantity']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Calculate total amount
        quantity = int(data['quantity'])
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
            customer_name=data['name'],
            customer_email=data['email'],
            customer_phone=data['phone'],
            shipping_address=data['address'],
            pincode=data['pincode'],
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
            'order_id': razorpay_order['id'],
            'name': 'Pure Moringa',
            'description': f'Moringa Powder - {quantity} pouches',
            'prefill': {
                'name': data['name'],
                'email': data['email'],
                'contact': data['phone']
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/verify-payment', methods=['POST'])
def verify_payment():
    try:
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
                order.payment_date = datetime.utcnow()
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

# Admin Routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        data = request.json if request.is_json else request.form
        username = data.get('username')
        password = data.get('password')
        
        admin = Admin.query.filter_by(username=username).first()
        
        if admin and check_password_hash(admin.password_hash, password):
            login_user(admin)
            if request.is_json:
                return jsonify({'status': 'success', 'redirect': '/admin/dashboard'})
            return redirect(url_for('admin_dashboard'))
        
        if request.is_json:
            return jsonify({'error': 'Invalid credentials'}), 401
        return render_template('admin_login.html', error='Invalid credentials')
    
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('admin_login'))

@app.route('/api/admin/orders')
@login_required
def get_orders():
    """API endpoint for AJAX order fetching with real-time updates"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        status_filter = request.args.get('status')
        search = request.args.get('search')
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')
        
        query = Order.query
        
        # Apply filters
        if status_filter:
            query = query.filter(Order.status == status_filter)
        
        if search:
            query = query.filter(
                db.or_(
                    Order.order_id.contains(search),
                    Order.customer_name.contains(search),
                    Order.customer_email.contains(search),
                    Order.customer_phone.contains(search)
                )
            )
        
        if date_from:
            try:
                from_date = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(Order.created_at >= from_date)
            except ValueError:
                pass
        
        if date_to:
            try:
                to_date = datetime.strptime(date_to, '%Y-%m-%d')
                to_date = to_date.replace(hour=23, minute=59, second=59)
                query = query.filter(Order.created_at <= to_date)
            except ValueError:
                pass
        
        # Pagination
        orders = query.order_by(Order.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        # Calculate statistics
        total_orders = Order.query.count()
        total_revenue = db.session.query(db.func.sum(Order.total_amount)).filter(
            Order.status.in_(['processing', 'shipped', 'delivered'])
        ).scalar() or 0
        pending_orders = Order.query.filter(Order.status == 'pending').count()
        
        # Check for new orders (orders created in last 30 seconds)
        thirty_seconds_ago = datetime.utcnow() - timedelta(seconds=30)
        new_orders_count = Order.query.filter(Order.created_at >= thirty_seconds_ago).count()
        
        return jsonify({
            'orders': [{
                'id': order.id,
                'order_id': order.order_id,
                'razorpay_payment_id': order.razorpay_payment_id,
                'customer_name': order.customer_name,
                'customer_email': order.customer_email,
                'customer_phone': order.customer_phone,
                'shipping_address': order.shipping_address,
                'pincode': order.pincode,
                'quantity': order.quantity,
                'total_amount': order.total_amount,
                'status': order.status,
                'created_at': order.created_at.isoformat(),
                'updated_at': order.updated_at.isoformat()
            } for order in orders.items],
            'stats': {
                'total_orders': total_orders,
                'total_revenue': float(total_revenue),
                'pending_orders': pending_orders
            },
            'pagination': {
                'page': orders.page,
                'pages': orders.pages,
                'per_page': orders.per_page,
                'total': orders.total,
                'has_prev': orders.has_prev,
                'has_next': orders.has_next
            },
            'new_orders_count': new_orders_count
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/orders/<int:order_id>')
@login_required
def api_admin_order_detail(order_id):
    """API endpoint for fetching individual order details"""
    order = Order.query.get(order_id)
    if not order:
        return jsonify({'error': 'Order not found'}), 404
    
    return jsonify({
        'id': order.id,
        'order_id': order.order_id,
        'customer_name': order.customer_name,
        'customer_email': order.customer_email,
        'customer_phone': order.customer_phone,
        'shipping_address': order.shipping_address,
        'pincode': order.pincode,
        'quantity': order.quantity,
        'unit_price': float(order.unit_price),
        'total_amount': float(order.total_amount),
        'status': order.status,
        'razorpay_payment_id': order.razorpay_payment_id,
        'created_at': order.created_at.isoformat()
    })

@app.route('/api/admin/orders/<int:order_id>/status', methods=['PUT'])
@login_required
def update_order_status(order_id):
    """API endpoint for updating order status"""
    try:
        order = Order.query.get(order_id)
        if not order:
            return jsonify({'error': 'Order not found'}), 404
        
        data = request.get_json()
        new_status = data.get('status')
        
        if new_status not in ['pending', 'processing', 'shipped', 'delivered', 'cancelled']:
            return jsonify({'error': 'Invalid status'}), 400
        
        order.status = new_status
        order.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Order status updated successfully',
            'order': {
                'id': order.id,
                'order_id': order.order_id,
                'status': order.status
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/export-orders')
@login_required
def export_orders():
    try:
        orders = Order.query.all()
        
        # Create CSV data
        csv_data = "Order ID,Payment ID,Customer Name,Email,Phone,Address,Quantity,Total Amount,Payment Status,Delivery Status,Created At\n"
        
        for order in orders:
            csv_data += f"{order.order_id},{order.payment_id},{order.customer_name},{order.customer_email},{order.customer_phone},\"{order.customer_address}, {order.customer_pincode}\",{order.quantity},{order.total_amount},{order.payment_status},{order.delivery_status},{order.created_at}\n"
        
        # Create file-like object
        output = io.StringIO()
        output.write(csv_data)
        output.seek(0)
        
        return send_file(
            io.BytesIO(output.getvalue().encode()),
            as_attachment=True,
            download_name=f'orders_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
            mimetype='text/csv'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Initialize database and create admin user
def init_db():
    with app.app_context():
        db.create_all()
        
        # Create admin user if not exists
        admin = Admin.query.filter_by(username=os.getenv('ADMIN_USERNAME', 'admin')).first()
        if not admin:
            admin = Admin(
                username=os.getenv('ADMIN_USERNAME', 'admin'),
                password_hash=generate_password_hash(os.getenv('ADMIN_PASSWORD', 'moringa@2024'))
            )
            db.session.add(admin)
            db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)