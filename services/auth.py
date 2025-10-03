"""
Authentication and security service module.
Handles admin login, MFA setup/verification, and security-related operations.
"""

import pyotp
from werkzeug.security import check_password_hash
from flask import session, flash, redirect, url_for
from flask_login import login_user


class AuthService:
    """Service class for authentication and security operations."""
    
    def __init__(self, db, Admin, AdminSecurity):
        self.db = db
        self.Admin = Admin
        self.AdminSecurity = AdminSecurity
    
    def authenticate_admin(self, username, password, otp_code=None):
        """
        Authenticate admin user with optional MFA verification.
        
        Args:
            username (str): Admin username
            password (str): Admin password
            otp_code (str, optional): OTP code for MFA verification
            
        Returns:
            tuple: (success: bool, admin: Admin|None, error_message: str|None)
        """
        # Find admin by username (case-insensitive)
        admin = self.db.session.query(self.Admin).filter(
            self.db.func.lower(self.Admin.username) == username.lower()
        ).first()
        
        if not admin or not check_password_hash(admin.password_hash, password):
            return False, None, "Invalid credentials"
        
        # Check MFA if enabled
        sec = self.AdminSecurity.query.filter_by(admin_id=admin.id).first()
        if sec and sec.mfa_enabled:
            if not otp_code:
                return False, None, "MFA code required"
            
            if not sec.totp_secret or not pyotp.TOTP(sec.totp_secret).verify(otp_code):
                return False, None, "Invalid MFA code"
        
        return True, admin, None
    
    def login_admin(self, admin, remember_me=False):
        """
        Log in the admin user.
        
        Args:
            admin (Admin): Admin user object
            remember_me (bool): Whether to remember the login
        """
        login_user(admin, remember=remember_me)
    
    def get_or_create_admin_security(self, admin_id):
        """
        Get or create AdminSecurity record for the given admin.
        
        Args:
            admin_id (int): Admin user ID
            
        Returns:
            AdminSecurity: Security record for the admin
        """
        sec = self.AdminSecurity.query.filter_by(admin_id=admin_id).first()
        if not sec:
            sec = self.AdminSecurity(admin_id=admin_id, mfa_enabled=False)
            self.db.session.add(sec)
            self.db.session.commit()
        return sec
    
    def setup_mfa(self, admin_id):
        """
        Set up MFA for an admin user.
        
        Args:
            admin_id (int): Admin user ID
            
        Returns:
            tuple: (secret: str, provisioning_uri: str)
        """
        sec = self.get_or_create_admin_security(admin_id)
        
        # Generate new secret for setup
        secret = session.get('mfa_setup_secret')
        if not secret:
            secret = pyotp.random_base32()
            session['mfa_setup_secret'] = secret
        
        # Generate provisioning URI for QR code
        totp = pyotp.TOTP(secret)
        admin = self.db.session.get(self.Admin, admin_id)
        provisioning_uri = totp.provisioning_uri(
            name=admin.username,
            issuer_name="Pure Moringa Admin"
        )
        
        return secret, provisioning_uri
    
    def enable_mfa(self, admin_id, otp_code):
        """
        Enable MFA for an admin user after verifying the setup code.
        
        Args:
            admin_id (int): Admin user ID
            otp_code (str): OTP code to verify
            
        Returns:
            tuple: (success: bool, error_message: str|None)
        """
        secret = session.get('mfa_setup_secret')
        if not secret:
            return False, "MFA setup was not initiated. Please start setup again."
        
        if not otp_code or not pyotp.TOTP(secret).verify(otp_code):
            return False, "Invalid verification code. Please try again."
        
        sec = self.get_or_create_admin_security(admin_id)
        sec.mfa_enabled = True
        sec.totp_secret = secret
        self.db.session.commit()
        
        # Clear setup secret from session
        session.pop('mfa_setup_secret', None)
        
        return True, None
    
    def disable_mfa(self, admin_id, otp_code):
        """
        Disable MFA for an admin user after verifying the current code.
        
        Args:
            admin_id (int): Admin user ID
            otp_code (str): Current OTP code to verify
            
        Returns:
            tuple: (success: bool, error_message: str|None)
        """
        sec = self.AdminSecurity.query.filter_by(admin_id=admin_id).first()
        if not sec or not sec.mfa_enabled:
            return False, "MFA is not currently enabled."
        
        if not sec.totp_secret or not otp_code or not pyotp.TOTP(sec.totp_secret).verify(otp_code):
            return False, "Invalid code. Cannot disable MFA."
        
        sec.mfa_enabled = False
        sec.totp_secret = None
        self.db.session.commit()
        
        return True, None
    
    def is_mfa_enabled(self, admin_id):
        """
        Check if MFA is enabled for an admin user.
        
        Args:
            admin_id (int): Admin user ID
            
        Returns:
            bool: True if MFA is enabled, False otherwise
        """
        sec = self.AdminSecurity.query.filter_by(admin_id=admin_id).first()
        return sec and sec.mfa_enabled if sec else False