"""
Payment processing service module.
Handles Razorpay payment creation, verification, and related operations.
"""

import hashlib
import hmac
from datetime import datetime, timezone


class PaymentService:
    """Service class for payment processing operations."""
    
    def __init__(self, razorpay_client, razorpay_key_secret):
        self.razorpay_client = razorpay_client
        self.razorpay_key_secret = razorpay_key_secret
    
    def create_razorpay_order(self, order_id, total_amount):
        """
        Create a Razorpay order for payment processing.
        
        Args:
            order_id (str): Unique order ID
            total_amount (float): Total amount in INR
            
        Returns:
            dict: Razorpay order data
        """
        razorpay_order = self.razorpay_client.order.create({
            'amount': int(total_amount * 100),  # Amount in paise
            'currency': 'INR',
            'receipt': order_id,
            'payment_capture': 1
        })
        
        return razorpay_order
    
    def verify_payment_signature(self, razorpay_order_id, razorpay_payment_id, razorpay_signature):
        """
        Verify Razorpay payment signature for security.
        
        Args:
            razorpay_order_id (str): Razorpay order ID
            razorpay_payment_id (str): Razorpay payment ID
            razorpay_signature (str): Razorpay signature
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        # Create signature
        body = razorpay_order_id + "|" + razorpay_payment_id
        expected_signature = hmac.new(
            key=self.razorpay_key_secret.encode(),
            msg=body.encode(),
            digestmod=hashlib.sha256
        ).hexdigest()
        
        return expected_signature == razorpay_signature
    
    def process_payment_verification(self, db, Order, payment_data):
        """
        Process payment verification and update order status.
        
        Args:
            db: Database session
            Order: Order model class
            payment_data (dict): Payment verification data
            
        Returns:
            tuple: (success: bool, order_data: dict|None, error_message: str|None)
        """
        razorpay_order_id = payment_data.get('razorpay_order_id')
        razorpay_payment_id = payment_data.get('razorpay_payment_id')
        razorpay_signature = payment_data.get('razorpay_signature')
        
        if not all([razorpay_order_id, razorpay_payment_id, razorpay_signature]):
            return False, None, "Missing payment data"
        
        # Verify signature
        if not self.verify_payment_signature(razorpay_order_id, razorpay_payment_id, razorpay_signature):
            return False, None, "Invalid payment signature"
        
        # Find and update order
        order = Order.query.filter_by(razorpay_order_id=razorpay_order_id).first()
        if not order:
            return False, None, "Order not found"
        
        try:
            order.razorpay_payment_id = razorpay_payment_id
            order.razorpay_signature = razorpay_signature
            order.status = 'processing'
            order.payment_date = datetime.now(timezone.utc)
            db.session.commit()
            
            return True, {
                'order_id': order.id,
                'status': order.status,
                'payment_date': order.payment_date.isoformat()
            }, None
            
        except Exception as e:
            db.session.rollback()
            return False, None, str(e)
    
    def create_order_and_payment(self, db, Order, order_data, calculate_total_func, generate_order_id_func):
        """
        Create order and Razorpay payment in one transaction.
        
        Args:
            db: Database session
            Order: Order model class
            order_data (dict): Order creation data
            calculate_total_func (callable): Function to calculate total amount
            generate_order_id_func (callable): Function to generate order ID
            
        Returns:
            tuple: (success: bool, payment_data: dict|None, error_message: str|None)
        """
        try:
            # Calculate total amount
            quantity = int(order_data['quantity'])
            if quantity <= 0:
                return False, None, "Quantity must be a positive integer"
            
            total_amount = calculate_total_func(quantity)
            
            # Generate unique order ID
            order_id = generate_order_id_func()
            
            # Create Razorpay order
            razorpay_order = self.create_razorpay_order(order_id, total_amount)
            
            # Store order in database
            order = Order(
                order_id=order_id,
                razorpay_order_id=razorpay_order['id'],
                customer_name=order_data['name'],
                customer_email=order_data['email'],
                customer_phone=order_data['phone'],
                shipping_address=order_data['address'],
                pincode=order_data['pincode'],
                quantity=quantity,
                unit_price=order_data['unit_price'],
                total_amount=total_amount
            )
            
            db.session.add(order)
            db.session.commit()
            
            return True, {
                'order_id': razorpay_order['id'],
                'amount': total_amount,
                'currency': 'INR',
                'name': 'Pure Moringa',
                'description': f"Order {order_id}",
                'prefill': {
                    'name': order_data['name'],
                    'email': order_data['email'],
                    'contact': order_data['phone']
                }
            }, None
            
        except Exception as e:
            db.session.rollback()
            return False, None, str(e)