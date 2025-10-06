"""Enhanced Security Configuration Module

This module provides comprehensive security configurations and utilities
for the Moringa site application, including session management, authentication
security, environment variable validation, and security best practices.
"""

import os
import secrets
import logging
from datetime import datetime, timedelta, timezone
from cryptography.fernet import Fernet
from typing import Dict, List, Optional, Any, Union
import base64
import hashlib
import json
from flask import session, request, current_app
from functools import wraps

logger = logging.getLogger(__name__)

class SessionManager:
    """Enhanced session management with security features.
    
    Provides:
    - Session expiration
    - Session validation
    - Secure session storage
    - Session activity tracking
    """
    
    # Session configuration
    SESSION_LIFETIME = timedelta(hours=8)  # 8 hours for admin sessions
    CUSTOMER_SESSION_LIFETIME = timedelta(days=30)  # 30 days for customer sessions
    SESSION_REFRESH_THRESHOLD = timedelta(minutes=30)  # Refresh if session expires in 30 min
    MAX_CONCURRENT_SESSIONS = 3  # Maximum concurrent sessions per user
    
    @staticmethod
    def create_admin_session(admin_id: int, username: str, remember_me: bool = False) -> Dict[str, Any]:
        """Create a secure admin session.
        
        Args:
            admin_id: Admin user ID
            username: Admin username
            remember_me: Whether to extend session lifetime
            
        Returns:
            Session data dictionary
        """
        now = datetime.now(timezone.utc)
        lifetime = SessionManager.SESSION_LIFETIME
        
        if remember_me:
            lifetime = timedelta(days=7)  # 7 days for "remember me"
        
        session_data = {
            'admin_id': admin_id,
            'username': username,
            'login_time': now.isoformat(),
            'last_activity': now.isoformat(),
            'expires_at': (now + lifetime).isoformat(),
            'session_id': secrets.token_urlsafe(32),
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', '')[:200],  # Limit length
            'remember_me': remember_me,
            'mfa_verified': False,
            'session_type': 'admin'
        }
        
        # Store in Flask session
        session.update(session_data)
        session.permanent = True
        
        return session_data
    
    @staticmethod
    def create_customer_session(customer_id: int, email: str) -> Dict[str, Any]:
        """Create a secure customer session.
        
        Args:
            customer_id: Customer user ID
            email: Customer email
            
        Returns:
            Session data dictionary
        """
        now = datetime.now(timezone.utc)
        lifetime = SessionManager.CUSTOMER_SESSION_LIFETIME
        
        session_data = {
            'customer_id': customer_id,
            'customer_email': email,
            'login_time': now.isoformat(),
            'last_activity': now.isoformat(),
            'expires_at': (now + lifetime).isoformat(),
            'session_id': secrets.token_urlsafe(32),
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', '')[:200],
            'session_type': 'customer'
        }
        
        # Store in Flask session
        session.update(session_data)
        session.permanent = True
        
        return session_data
    
    @staticmethod
    def validate_session() -> Dict[str, Any]:
        """Validate current session and return validation results.
        
        Returns:
            Dictionary with validation status and details
        """
        if not session:
            return {'valid': False, 'reason': 'no_session'}
        
        # Check if session has required fields
        session_type = session.get('session_type')
        if not session_type:
            return {'valid': False, 'reason': 'invalid_session_type'}
        
        # Check expiration
        expires_at_str = session.get('expires_at')
        if not expires_at_str:
            return {'valid': False, 'reason': 'no_expiration'}
        
        try:
            expires_at = datetime.fromisoformat(expires_at_str)
            now = datetime.now(timezone.utc)
            
            if now > expires_at:
                return {'valid': False, 'reason': 'expired'}
            
            # Check if session needs refresh
            time_until_expiry = expires_at - now
            needs_refresh = time_until_expiry < SessionManager.SESSION_REFRESH_THRESHOLD
            
            # Validate session integrity
            required_fields = ['session_id', 'login_time', 'last_activity', 'ip_address']
            if session_type == 'admin':
                required_fields.extend(['admin_id', 'username'])
            elif session_type == 'customer':
                required_fields.extend(['customer_id', 'customer_email'])
            
            for field in required_fields:
                if field not in session:
                    return {'valid': False, 'reason': f'missing_field_{field}'}
            
            # Update last activity
            session['last_activity'] = now.isoformat()
            
            return {
                'valid': True,
                'session_type': session_type,
                'needs_refresh': needs_refresh,
                'expires_at': expires_at,
                'time_until_expiry': time_until_expiry.total_seconds()
            }
            
        except (ValueError, TypeError) as e:
            return {'valid': False, 'reason': f'invalid_expiration_format: {e}'}
    
    @staticmethod
    def refresh_session() -> bool:
        """Refresh the current session expiration.
        
        Returns:
            True if session was refreshed, False otherwise
        """
        validation = SessionManager.validate_session()
        if not validation['valid']:
            return False
        
        session_type = validation['session_type']
        now = datetime.now(timezone.utc)
        
        if session_type == 'admin':
            lifetime = SessionManager.SESSION_LIFETIME
            if session.get('remember_me'):
                lifetime = timedelta(days=7)
        else:  # customer
            lifetime = SessionManager.CUSTOMER_SESSION_LIFETIME
        
        session['expires_at'] = (now + lifetime).isoformat()
        session['last_activity'] = now.isoformat()
        
        return True
    
    @staticmethod
    def clear_session() -> None:
        """Clear the current session securely."""
        session.clear()
    
    @staticmethod
    def is_admin_session() -> bool:
        """Check if current session is an admin session."""
        validation = SessionManager.validate_session()
        return validation['valid'] and validation.get('session_type') == 'admin'
    
    @staticmethod
    def is_customer_session() -> bool:
        """Check if current session is a customer session."""
        validation = SessionManager.validate_session()
        return validation['valid'] and validation.get('session_type') == 'customer'

class AuthenticationSecurity:
    """Enhanced authentication security utilities."""
    
    # Rate limiting configuration
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = timedelta(minutes=15)
    
    @staticmethod
    def check_rate_limit(identifier: str, attempt_type: str = 'login') -> Dict[str, Any]:
        """Check rate limiting for authentication attempts.
        
        Args:
            identifier: User identifier (username, email, IP)
            attempt_type: Type of attempt (login, mfa, etc.)
            
        Returns:
            Dictionary with rate limit status
        """
        key = f"{attempt_type}_attempts_{identifier}"
        lockout_key = f"{attempt_type}_lockout_{identifier}"
        lockout_time_key = f"{lockout_key}_time"
        
        # Check if currently locked out
        if session.get(lockout_key):
            lockout_time = session.get(lockout_time_key, 0)
            if datetime.now().timestamp() - lockout_time < AuthenticationSecurity.LOCKOUT_DURATION.total_seconds():
                return {
                    'allowed': False,
                    'reason': 'locked_out',
                    'lockout_remaining': AuthenticationSecurity.LOCKOUT_DURATION.total_seconds() - (datetime.now().timestamp() - lockout_time)
                }
            else:
                # Lockout expired, clear it
                session.pop(lockout_key, None)
                session.pop(lockout_time_key, None)
                session.pop(key, None)
        
        attempts = session.get(key, 0)
        
        if attempts >= AuthenticationSecurity.MAX_LOGIN_ATTEMPTS:
            # Lock out user
            session[lockout_key] = True
            session[lockout_time_key] = datetime.now().timestamp()
            return {
                'allowed': False,
                'reason': 'too_many_attempts',
                'lockout_duration': AuthenticationSecurity.LOCKOUT_DURATION.total_seconds()
            }
        
        return {
            'allowed': True,
            'attempts': attempts,
            'remaining_attempts': AuthenticationSecurity.MAX_LOGIN_ATTEMPTS - attempts
        }
    
    @staticmethod
    def record_failed_attempt(identifier: str, attempt_type: str = 'login') -> None:
        """Record a failed authentication attempt."""
        key = f"{attempt_type}_attempts_{identifier}"
        attempts = session.get(key, 0) + 1
        session[key] = attempts
    
    @staticmethod
    def clear_failed_attempts(identifier: str, attempt_type: str = 'login') -> None:
        """Clear failed authentication attempts for successful login."""
        key = f"{attempt_type}_attempts_{identifier}"
        lockout_key = f"{attempt_type}_lockout_{identifier}"
        lockout_time_key = f"{lockout_key}_time"
        
        session.pop(key, None)
        session.pop(lockout_key, None)
        session.pop(lockout_time_key, None)

class SecurityConfig:
    """Handles secure configuration management and environment variable validation."""
    
    def __init__(self):
        self.required_vars = {
            'SECRET_KEY': 'Flask secret key for session management',
            'DATABASE_URL': 'Database connection string',
            'ADMIN_USERNAME': 'Initial admin username',
            'ADMIN_PASSWORD': 'Initial admin password'
        }
        
        self.sensitive_vars = {
            'SECRET_KEY', 'DATABASE_URL', 'ADMIN_PASSWORD', 
            'RAZORPAY_KEY_SECRET', 'SMTP_PASS'
        }
        
        self.default_insecure_values = {
            'your_secret_key_here_change_this_in_production',
            'change_this_secure_password',
            'CHANGE_THIS_SECURE_PASSWORD',
            'CHANGE_THIS_SECURE_PASSWORD_NOW',
            'your_app_password_here',
            'your_razorpay_key_secret'
        }
    
    def validate_environment(self) -> Dict[str, Any]:
        """
        Validate environment variables for security issues.
        
        Returns:
            Dict containing validation results and recommendations
        """
        issues = []
        warnings = []
        recommendations = []
        
        # Check for missing required variables
        for var, description in self.required_vars.items():
            if not os.getenv(var):
                issues.append(f"Missing required environment variable: {var} ({description})")
        
        # Check for insecure default values
        for var in self.sensitive_vars:
            value = os.getenv(var, '')
            if value in self.default_insecure_values:
                issues.append(f"Insecure default value detected for {var}")
        
        # Check SECRET_KEY strength
        secret_key = os.getenv('SECRET_KEY', '')
        if secret_key and len(secret_key) < 32:
            warnings.append("SECRET_KEY should be at least 32 characters long")
        
        # Check for production credentials in development
        razorpay_key = os.getenv('RAZORPAY_KEY_ID', '')
        if razorpay_key.startswith('rzp_live_') and os.getenv('FLASK_ENV') == 'development':
            issues.append("Production Razorpay credentials detected in development environment")
        
        # Check database URL security
        db_url = os.getenv('DATABASE_URL', '')
        if 'password' in db_url.lower() and ('localhost' not in db_url and '127.0.0.1' not in db_url):
            warnings.append("Database credentials in URL for remote connection - consider using connection pooling")
        
        # Generate recommendations
        if issues or warnings:
            recommendations.extend([
                "Use strong, randomly generated passwords",
                "Enable MFA for admin accounts immediately after setup",
                "Use test credentials for development environments",
                "Consider using a secret management service for production",
                "Regularly rotate sensitive credentials"
            ])
        
        return {
            'issues': issues,
            'warnings': warnings,
            'recommendations': recommendations,
            'is_secure': len(issues) == 0
        }
    
    def generate_secure_secret_key(self) -> str:
        """Generate a cryptographically secure secret key."""
        return secrets.token_hex(32)
    
    def encrypt_sensitive_data(self, data: str, key: Optional[str] = None) -> str:
        """
        Encrypt sensitive data using Fernet encryption.
        
        Args:
            data: Data to encrypt
            key: Encryption key (if None, uses SECRET_KEY)
            
        Returns:
            Base64 encoded encrypted data
        """
        if key is None:
            key = os.getenv('SECRET_KEY', self.generate_secure_secret_key())
        
        # Ensure key is 32 bytes for Fernet
        key_bytes = key.encode()[:32].ljust(32, b'0')
        fernet_key = base64.urlsafe_b64encode(key_bytes)
        
        fernet = Fernet(fernet_key)
        encrypted_data = fernet.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted_data).decode()
    
    def decrypt_sensitive_data(self, encrypted_data: str, key: Optional[str] = None) -> str:
        """
        Decrypt sensitive data using Fernet encryption.
        
        Args:
            encrypted_data: Base64 encoded encrypted data
            key: Encryption key (if None, uses SECRET_KEY)
            
        Returns:
            Decrypted data
        """
        if key is None:
            key = os.getenv('SECRET_KEY', self.generate_secure_secret_key())
        
        # Ensure key is 32 bytes for Fernet
        key_bytes = key.encode()[:32].ljust(32, b'0')
        fernet_key = base64.urlsafe_b64encode(key_bytes)
        
        fernet = Fernet(fernet_key)
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
        decrypted_data = fernet.decrypt(encrypted_bytes)
        return decrypted_data.decode()
    
    def get_secure_config(self, var_name: str, default: Optional[str] = None, 
                         decrypt: bool = False) -> Optional[str]:
        """
        Get configuration value with optional decryption.
        
        Args:
            var_name: Environment variable name
            default: Default value if not found
            decrypt: Whether to decrypt the value
            
        Returns:
            Configuration value
        """
        value = os.getenv(var_name, default)
        
        if value and decrypt:
            try:
                value = self.decrypt_sensitive_data(value)
            except Exception as e:
                logger.warning(f"Failed to decrypt {var_name}: {e}")
                return default
        
        return value
    
    def log_security_status(self):
        """Log the current security status of the application."""
        validation = self.validate_environment()
        
        if validation['is_secure']:
            logger.info("Security validation passed - no critical issues found")
        else:
            logger.warning("Security validation failed - critical issues found:")
            for issue in validation['issues']:
                logger.warning(f"  - {issue}")
        
        if validation['warnings']:
            logger.info("Security warnings:")
            for warning in validation['warnings']:
                logger.info(f"  - {warning}")
        
        if validation['recommendations']:
            logger.info("Security recommendations:")
            for rec in validation['recommendations']:
                logger.info(f"  - {rec}")

# Global security config instances
security_config = SecurityConfig()
session_manager = SessionManager()
auth_security = AuthenticationSecurity()