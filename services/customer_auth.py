"""
Customer authentication and authorization service module.
Handles customer login, session management, access control, email verification, and MFA.
"""

import json
import secrets
from datetime import datetime, timezone, timedelta
from flask import session, request, jsonify, redirect, url_for, flash, render_template_string
import logging
import pyotp
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class CustomerAuthService:
    """Service class for customer authentication and authorization operations."""
    
    def __init__(self, db, Customer, Order, CustomerSecurity=None):
        self.db = db
        self.Customer = Customer
        self.Order = Order
        self.CustomerSecurity = CustomerSecurity
        self.logger = logging.getLogger(__name__)
    
    def generate_verification_token(self):
        """Generate a secure email verification token."""
        return secrets.token_urlsafe(32)
    
    def send_verification_email(self, customer, verification_url):
        """
        Send email verification email to customer.
        Uses SMTP configuration from environment variables if available.
        Falls back to logging the verification link in development.
        """
        self.logger.info(f"Email verification URL for {customer.email}: {verification_url}")
        
        # Compose HTML email content
        email_template = f"""
        <h2>Welcome to Pure Moringa!</h2>
        <p>Hi {customer.name},</p>
        <p>Thank you for registering with Pure Moringa. Please verify your email address by clicking the link below:</p>
        <p><a href="{verification_url}">Verify Email Address</a></p>
        <p>If you didn't create this account, please ignore this email.</p>
        <p>Best regards,<br>Pure Moringa Team</p>
        """
        
        # Try sending via SMTP if configured
        try:
            smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
            smtp_port = int(os.getenv('SMTP_PORT', '587'))
            smtp_user = os.getenv('SMTP_USER')
            smtp_pass = os.getenv('SMTP_PASS')
            use_tls = os.getenv('SMTP_USE_TLS', 'true').lower() == 'true'
            
            if not smtp_user or not smtp_pass:
                # Fallback to logging only in development
                self.logger.warning("SMTP configuration missing (SMTP_USER or SMTP_PASS not set). Email not sent to %s", customer.email)
                self.logger.info("To enable email sending, configure SMTP settings in .env file:")
                self.logger.info("SMTP_USER=your_email@gmail.com")
                self.logger.info("SMTP_PASS=your_app_password")
                self.logger.info(f"Verification email content for {customer.email}: {email_template}")
                return False
            
            msg = MIMEMultipart()
            msg['From'] = smtp_user
            msg['To'] = customer.email
            msg['Subject'] = "Verify your Pure Moringa account"
            
            msg.attach(MIMEText(email_template, 'html'))
            
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
            if use_tls:
                server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"Verification email sent successfully to {customer.email}")
            return True
        except Exception as e:
            self.logger.error(f"Error sending verification email to {customer.email}: {e}")
            self.logger.info("Please check your SMTP configuration in .env file")
            return False
    
    def verify_email_token(self, token):
        """
        Verify email verification token and activate customer account.
        
        Args:
            token (str): Email verification token
            
        Returns:
            tuple: (success: bool, customer: Customer|None, message: str)
        """
        customer = self.Customer.query.filter_by(email_verification_token=token).first()
        
        if not customer:
            return False, None, "Invalid verification token"
        
        # Check if token is expired (24 hours)
        if customer.email_verification_sent_at:
            expiry_time = customer.email_verification_sent_at + timedelta(hours=24)
            if datetime.now(timezone.utc) > expiry_time:
                return False, None, "Verification token has expired"
        
        # Verify email
        customer.email_verified = True
        customer.email_verification_token = None
        customer.email_verification_sent_at = None
        self.db.session.commit()
        
        self.logger.info(f"Email verified successfully for customer: {customer.email}")
        return True, customer, "Email verified successfully"
    
    def resend_verification_email(self, email):
        """
        Resend verification email to customer.
        
        Args:
            email (str): Customer email
            
        Returns:
            tuple: (success: bool, message: str)
        """
        customer = self.Customer.query.filter_by(email=email.lower().strip()).first()
        
        if not customer:
            return False, "Customer not found"
        
        if customer.email_verified:
            return False, "Email is already verified"
        
        # Check rate limiting (minimum 10 seconds between resends)
        last_sent = customer.email_verification_sent_at
        try:
            if last_sent:
                # Normalize type: handle string and naive datetimes
                if isinstance(last_sent, str):
                    try:
                        last_sent = datetime.fromisoformat(last_sent)
                    except Exception:
                        self.logger.warning("Invalid email_verification_sent_at for %s: %s", customer.email, last_sent)
                        last_sent = None
                if isinstance(last_sent, datetime) and last_sent.tzinfo is None:
                    last_sent = last_sent.replace(tzinfo=timezone.utc)
            if last_sent:
                time_since_last = datetime.now(timezone.utc) - last_sent
                if time_since_last < timedelta(seconds=10):
                    seconds_left = int((timedelta(seconds=10) - time_since_last).total_seconds()) + 1
                    return False, f"Please wait {seconds_left} seconds before requesting another verification email"
        except Exception as e:
            # Do not block resend due to unexpected type issues; log and continue
            self.logger.error("Rate limit computation error for %s: %s", customer.email, e)
        
        # Generate new token and send email
        token = self.generate_verification_token()
        customer.email_verification_token = token
        customer.email_verification_sent_at = datetime.now(timezone.utc)
        self.db.session.commit()
        
        # In production, construct proper URL
        verification_url = url_for('verify_customer_email', token=token, _external=True)
        self.send_verification_email(customer, verification_url)
        
        return True, "Verification email sent successfully"
    
    def setup_customer_mfa(self, customer):
        """
        Set up MFA for customer account.
        
        Args:
            customer (Customer): Customer object
            
        Returns:
            tuple: (secret: str, qr_uri: str)
        """
        if not self.CustomerSecurity:
            raise ValueError("CustomerSecurity model not available")
        
        # Get or create customer security record
        security = self.CustomerSecurity.query.filter_by(customer_id=customer.id).first()
        if not security:
            security = self.CustomerSecurity(customer_id=customer.id)
            self.db.session.add(security)
        
        # Generate TOTP secret
        secret = pyotp.random_base32()
        issuer = 'Pure Moringa Customer'
        label = f"{customer.name} ({customer.email})"
        
        totp = pyotp.TOTP(secret)
        qr_uri = totp.provisioning_uri(name=label, issuer_name=issuer)
        
        # Store secret temporarily (will be confirmed when MFA is enabled)
        session['customer_mfa_setup_secret'] = secret
        session['customer_mfa_setup_id'] = customer.id
        
        return secret, qr_uri
    
    def enable_customer_mfa(self, customer, otp_code):
        """
        Enable MFA for customer after verifying setup.
        
        Args:
            customer (Customer): Customer object
            otp_code (str): OTP code from authenticator app
            
        Returns:
            tuple: (success: bool, backup_codes: list|None, error_message: str|None)
        """
        if not self.CustomerSecurity:
            return False, None, "MFA not available"
        
        # Get setup secret from session
        setup_secret = session.get('customer_mfa_setup_secret')
        setup_customer_id = session.get('customer_mfa_setup_id')
        
        if not setup_secret or setup_customer_id != customer.id:
            return False, None, "MFA setup not initiated"
        
        # Verify OTP code
        if not pyotp.TOTP(setup_secret).verify(otp_code):
            return False, None, "Invalid verification code"
        
        # Get or create security record
        security = self.CustomerSecurity.query.filter_by(customer_id=customer.id).first()
        if not security:
            security = self.CustomerSecurity(customer_id=customer.id)
            self.db.session.add(security)
        
        # Generate backup codes
        backup_codes = [secrets.token_hex(4).upper() for _ in range(8)]
        
        # Enable MFA
        security.mfa_enabled = True
        security.totp_secret = setup_secret
        security.backup_codes = json.dumps(backup_codes)
        security.mfa_setup_at = datetime.now(timezone.utc)
        
        self.db.session.commit()
        
        # Clear setup session
        session.pop('customer_mfa_setup_secret', None)
        session.pop('customer_mfa_setup_id', None)
        
        self.logger.info(f"MFA enabled for customer: {customer.email}")
        return True, backup_codes, None
    
    def disable_customer_mfa(self, customer, otp_code):
        """
        Disable MFA for customer.
        
        Args:
            customer (Customer): Customer object
            otp_code (str): OTP code or backup code
            
        Returns:
            tuple: (success: bool, error_message: str|None)
        """
        if not self.CustomerSecurity:
            return False, "MFA not available"
        
        security = self.CustomerSecurity.query.filter_by(customer_id=customer.id).first()
        if not security or not security.mfa_enabled:
            return False, "MFA is not enabled"
        
        # Verify OTP or backup code
        valid_code = False
        
        # Check TOTP
        if security.totp_secret and pyotp.TOTP(security.totp_secret).verify(otp_code):
            valid_code = True
        
        # Check backup codes
        if not valid_code and security.backup_codes:
            backup_codes = json.loads(security.backup_codes)
            if otp_code.upper() in backup_codes:
                valid_code = True
                # Remove used backup code
                backup_codes.remove(otp_code.upper())
                security.backup_codes = json.dumps(backup_codes)
        
        if not valid_code:
            return False, "Invalid verification code"
        
        # Disable MFA
        security.mfa_enabled = False
        security.totp_secret = None
        security.backup_codes = None
        security.mfa_setup_at = None
        
        self.db.session.commit()
        
        self.logger.info(f"MFA disabled for customer: {customer.email}")
        return True, None
    
    def verify_customer_mfa(self, customer, otp_code):
        """
        Verify customer MFA code during login.
        
        Args:
            customer (Customer): Customer object
            otp_code (str): OTP code or backup code
            
        Returns:
            bool: True if code is valid, False otherwise
        """
        if not self.CustomerSecurity:
            return False
        
        security = self.CustomerSecurity.query.filter_by(customer_id=customer.id).first()
        if not security or not security.mfa_enabled:
            return True  # MFA not enabled, allow login
        
        # Check TOTP
        if security.totp_secret and pyotp.TOTP(security.totp_secret).verify(otp_code):
            security.last_mfa_used = datetime.now(timezone.utc)
            self.db.session.commit()
            return True
        
        # Check backup codes
        if security.backup_codes:
            backup_codes = json.loads(security.backup_codes)
            if otp_code.upper() in backup_codes:
                # Remove used backup code
                backup_codes.remove(otp_code.upper())
                security.backup_codes = json.dumps(backup_codes)
                security.last_mfa_used = datetime.now(timezone.utc)
                self.db.session.commit()
                return True
        
        return False
    
    def is_customer_mfa_enabled(self, customer):
        """
        Check if customer has MFA enabled.
        
        Args:
            customer (Customer): Customer object
            
        Returns:
            bool: True if MFA is enabled, False otherwise
        """
        if not self.CustomerSecurity:
            return False
        
        security = self.CustomerSecurity.query.filter_by(customer_id=customer.id).first()
        return security and security.mfa_enabled
    
    def authenticate_customer(self, email, password, otp_code=None):
        """
        Authenticate customer with email, password, and optional MFA.
        
        Args:
            email (str): Customer email
            password (str): Customer password
            otp_code (str, optional): MFA code if MFA is enabled
            
        Returns:
            tuple: (success: bool, customer: Customer|None, error_message: str|None, needs_mfa: bool)
        """
        from werkzeug.security import check_password_hash
        
        email = email.strip().lower()
        customer = self.Customer.query.filter_by(email=email).first()
        
        if not customer:
            return False, None, "Invalid email or password", False
        
        if not check_password_hash(customer.password_hash, password):
            return False, None, "Invalid email or password", False
        
        # Check if email is verified
        if not customer.email_verified:
            return False, None, "Please verify your email address before logging in", False
        
        # Check if MFA is enabled
        if self.is_customer_mfa_enabled(customer):
            if not otp_code:
                return False, customer, "MFA code required", True
            
            if not self.verify_customer_mfa(customer, otp_code):
                return False, None, "Invalid MFA code", True
        
        return True, customer, None, False
    
    def create_customer_session(self, customer):
        """
        Create a secure session for the customer.
        
        Args:
            customer (Customer): Customer object
        """
        session['customer_id'] = customer.id
        session['customer_email'] = customer.email
        session['login_time'] = datetime.now(timezone.utc).isoformat()
        
        # Log successful login
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        self.logger.info(f"Customer '{customer.email}' logged in from IP {client_ip}")
    
    def validate_customer_session(self, customer_id):
        """
        Validate customer session and return customer object.
        
        Args:
            customer_id (int): Customer ID from session
            
        Returns:
            Customer|None: Customer object if valid, None otherwise
        """
        if not customer_id:
            return None
        
        customer = self.Customer.query.get(customer_id)
        if not customer:
            # Invalid customer ID in session
            self.clear_customer_session()
            return None
        
        # Verify session integrity
        session_email = session.get('customer_email')
        if session_email and session_email != customer.email:
            # Session tampering detected
            self.logger.warning(f"Session tampering detected for customer {customer_id}")
            self.clear_customer_session()
            return None
        
        return customer
    
    def clear_customer_session(self):
        """Clear customer session data."""
        session.pop('customer_id', None)
        session.pop('customer_email', None)
        session.pop('login_time', None)
    
    def customer_owns_order(self, customer, order_id):
        """
        Check if customer owns the specified order.
        
        Args:
            customer (Customer): Customer object
            order_id (int): Order ID
            
        Returns:
            bool: True if customer owns the order, False otherwise
        """
        order = self.Order.query.get(order_id)
        if not order:
            return False
        
        # Check ownership by email (primary method)
        if order.customer_email == customer.email:
            return True
        
        # Additional check: verify customer name and phone match
        if (order.customer_name == customer.name and 
            order.customer_phone == customer.phone):
            return True
        
        return False
    
    def get_customer_orders(self, customer, limit=None, status_filter=None):
        """
        Get orders belonging to the customer with proper data isolation.
        
        Args:
            customer (Customer): Customer object
            limit (int, optional): Maximum number of orders to return
            status_filter (str, optional): Filter by order status
            
        Returns:
            list: List of orders belonging to the customer
        """
        query = self.Order.query.filter_by(customer_email=customer.email)
        
        if status_filter:
            query = query.filter_by(status=status_filter)
        
        query = query.order_by(self.Order.created_at.desc())
        
        if limit:
            query = query.limit(limit)
        
        return query.all()
    
    def get_customer_order_by_id(self, customer, order_id):
        """
        Get a specific order if it belongs to the customer.
        
        Args:
            customer (Customer): Customer object
            order_id (int): Order ID
            
        Returns:
            Order|None: Order object if owned by customer, None otherwise
        """
        order = self.Order.query.get(order_id)
        if not order:
            return None
        
        if not self.customer_owns_order(customer, order_id):
            # Log unauthorized access attempt
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            self.logger.warning(
                f"Customer '{customer.email}' attempted unauthorized access to order {order_id} "
                f"(belongs to '{order.customer_email}') from IP {client_ip}"
            )
            return None
        
        return order
    
    def update_customer_profile(self, customer, update_data):
        """
        Update customer profile with validation.
        
        Args:
            customer (Customer): Customer object
            update_data (dict): Data to update
            
        Returns:
            tuple: (success: bool, error_message: str|None)
        """
        try:
            # Update allowed fields
            if 'name' in update_data and update_data['name'].strip():
                customer.name = update_data['name'].strip()
            
            if 'phone' in update_data and update_data['phone'].strip():
                customer.phone = update_data['phone'].strip()
            
            # Email updates require additional verification
            if 'email' in update_data:
                new_email = update_data['email'].strip().lower()
                if new_email != customer.email:
                    # Check if email is already taken
                    existing = self.Customer.query.filter_by(email=new_email).first()
                    if existing:
                        return False, "Email address is already registered"
                    
                    customer.email = new_email
                    # Update session email
                    session['customer_email'] = new_email
            
            self.db.session.commit()
            
            # Log profile update
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            self.logger.info(f"Customer '{customer.email}' updated profile from IP {client_ip}")
            
            return True, None
            
        except Exception as e:
            self.db.session.rollback()
            self.logger.error(f"Error updating customer profile: {str(e)}")
            return False, "An error occurred while updating your profile"
    
    def get_customer_statistics(self, customer):
        """
        Get customer-specific statistics.
        
        Args:
            customer (Customer): Customer object
            
        Returns:
            dict: Customer statistics
        """
        orders = self.get_customer_orders(customer)
        
        total_orders = len(orders)
        total_spent = sum(order.total_amount for order in orders if order.status in ['processing', 'shipped', 'delivered'])
        
        status_counts = {}
        for order in orders:
            status_counts[order.status] = status_counts.get(order.status, 0) + 1
        
        return {
            'total_orders': total_orders,
            'total_spent': total_spent,
            'status_counts': status_counts,
            'recent_orders': orders[:5] if orders else []
        }