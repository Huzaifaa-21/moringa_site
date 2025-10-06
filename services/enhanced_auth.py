"""
Enhanced Authentication Module

This module provides secure authentication decorators and utilities
with proper session management, rate limiting, and security features.
"""

import logging
from datetime import datetime, timezone
from functools import wraps
from flask import request, jsonify, redirect, url_for, flash, session, current_app
from flask_login import current_user, logout_user
from services.security_config import session_manager, auth_security

logger = logging.getLogger(__name__)

def secure_admin_required(f):
    """
    Enhanced admin authentication decorator with proper session management.
    
    Features:
    - Session validation and expiration
    - Rate limiting
    - MFA verification
    - Security logging
    - Automatic session refresh
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        # Validate session first
        session_validation = session_manager.validate_session()
        
        if not session_validation['valid']:
            reason = session_validation.get('reason', 'unknown')
            logger.warning(f"Admin access denied - invalid session: {reason} from IP {request.remote_addr}")
            
            # Clear invalid session
            session_manager.clear_session()
            logout_user()
            
            if request.path.startswith('/api/'):
                return jsonify({
                    'error': 'Authentication required',
                    'reason': 'session_invalid',
                    'redirect': '/admin/login'
                }), 401
            
            flash('Your session has expired. Please log in again.', 'warning')
            return redirect(url_for('admin_login'))
        
        # Check if this is an admin session
        if not session_manager.is_admin_session():
            logger.warning(f"Non-admin session attempted admin access from IP {request.remote_addr}")
            
            if request.path.startswith('/api/'):
                return jsonify({
                    'error': 'Admin access required',
                    'redirect': '/admin/login'
                }), 403
            
            flash('Admin access required.', 'error')
            return redirect(url_for('admin_login'))
        
        # Check if Flask-Login user is authenticated (double verification)
        if not current_user.is_authenticated:
            logger.warning(f"Flask-Login user not authenticated for admin access from IP {request.remote_addr}")
            session_manager.clear_session()
            
            if request.path.startswith('/api/'):
                return jsonify({
                    'error': 'Authentication required',
                    'redirect': '/admin/login'
                }), 401
            
            return redirect(url_for('admin_login'))
        
        # Verify session belongs to current user
        session_admin_id = session.get('admin_id')
        if session_admin_id != current_user.id:
            logger.error(f"Session admin ID mismatch: session={session_admin_id}, user={current_user.id} from IP {request.remote_addr}")
            session_manager.clear_session()
            logout_user()
            
            if request.path.startswith('/api/'):
                return jsonify({
                    'error': 'Session security violation',
                    'redirect': '/admin/login'
                }), 401
            
            flash('Security violation detected. Please log in again.', 'error')
            return redirect(url_for('admin_login'))
        
        # Check MFA requirement (except for MFA setup routes)
        if not request.path.startswith('/admin/mfa') and request.path != '/admin/logout':
            # Use current_app to avoid circular imports
            with current_app.app_context():
                from sqlalchemy import text
                # Query AdminSecurity directly using raw SQL to avoid import issues
                result = current_app.extensions['sqlalchemy'].db.session.execute(
                    text("SELECT mfa_enabled FROM admin_security WHERE admin_id = :admin_id"),
                    {'admin_id': current_user.id}
                ).fetchone()
                
                mfa_enabled = result[0] if result else False
                
                if not mfa_enabled:
                    if request.path.startswith('/api/'):
                        return jsonify({
                            'error': 'MFA setup required',
                            'redirect': '/admin/mfa'
                        }), 403
                    
                    flash('Multi-Factor Authentication setup is required for security.', 'warning')
                    return redirect(url_for('admin_mfa'))
        
        # Refresh session if needed
        if session_validation.get('needs_refresh'):
            session_manager.refresh_session()
            logger.info(f"Admin session refreshed for user {current_user.username}")
        
        # Log successful access
        logger.info(f"Admin access granted to {current_user.username} for {request.path} from IP {request.remote_addr}")
        
        return f(*args, **kwargs)
    
    return wrapper

def secure_customer_required(f):
    """
    Enhanced customer authentication decorator with proper session management.
    
    Features:
    - Session validation and expiration
    - Customer verification
    - Security logging
    - Automatic session refresh
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        # Validate session first
        session_validation = session_manager.validate_session()
        
        if not session_validation['valid']:
            reason = session_validation.get('reason', 'unknown')
            logger.warning(f"Customer access denied - invalid session: {reason} from IP {request.remote_addr}")
            
            # Clear invalid session
            session_manager.clear_session()
            
            if request.path.startswith('/api/'):
                return jsonify({
                    'error': 'Authentication required',
                    'reason': 'session_invalid',
                    'redirect': '/customer/login'
                }), 401
            
            flash('Your session has expired. Please log in again.', 'warning')
            return redirect(url_for('customer_login'))
        
        # Check if this is a customer session
        if not session_manager.is_customer_session():
            logger.warning(f"Non-customer session attempted customer access from IP {request.remote_addr}")
            
            if request.path.startswith('/api/'):
                return jsonify({
                    'error': 'Customer access required',
                    'redirect': '/customer/login'
                }), 403
            
            flash('Customer login required.', 'error')
            return redirect(url_for('customer_login'))
        
        # Get customer from session
        customer_id = session.get('customer_id')
        customer_email = session.get('customer_email')
        
        if not customer_id or not customer_email:
            logger.warning(f"Invalid customer session data from IP {request.remote_addr}")
            session_manager.clear_session()
            
            if request.path.startswith('/api/'):
                return jsonify({
                    'error': 'Invalid session data',
                    'redirect': '/customer/login'
                }), 401
            
            return redirect(url_for('customer_login'))
        
        # Verify customer exists in database using raw SQL to avoid circular imports
        with current_app.app_context():
            from sqlalchemy import text
            result = current_app.extensions['sqlalchemy'].db.session.execute(
                text("SELECT email, email_verified FROM customer WHERE id = :customer_id"),
                {'customer_id': customer_id}
            ).fetchone()
            
            if not result or result[0] != customer_email:
                logger.error(f"Customer session verification failed: ID={customer_id}, email={customer_email} from IP {request.remote_addr}")
                session_manager.clear_session()
                
                if request.path.startswith('/api/'):
                    return jsonify({
                        'error': 'Customer verification failed',
                        'redirect': '/customer/login'
                    }), 401
                
                flash('Account verification failed. Please log in again.', 'error')
                return redirect(url_for('customer_login'))
            
            # Check if customer email is verified
            email_verified = result[1] if result else False
            if not email_verified:
                if request.path.startswith('/api/'):
                    return jsonify({
                        'error': 'Email verification required',
                        'redirect': '/customer/verify'
                    }), 403
                
                flash('Please verify your email address to continue.', 'warning')
                return redirect(url_for('customer_verify'))
            
            # Create a simple customer object for request context
            class CustomerContext:
                def __init__(self, customer_id, email):
                    self.id = customer_id
                    self.email = email
            
            request.current_customer = CustomerContext(customer_id, customer_email)
        
        # Refresh session if needed
        if session_validation.get('needs_refresh'):
            session_manager.refresh_session()
            logger.info(f"Customer session refreshed for user {customer_email}")
        
        # Log successful access
        logger.info(f"Customer access granted to {customer_email} for {request.path} from IP {request.remote_addr}")
        
        return f(*args, **kwargs)
    
    return wrapper

def admin_route_required(f):
    """
    Decorator to ensure admin routes are only accessible via /admin/ or /api/admin/ paths.
    
    This prevents admin access through the root URL and enforces proper routing.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        # Check if the request path starts with /admin/ or /api/admin/
        if not (request.path.startswith('/admin/') or request.path.startswith('/api/admin/')):
            logger.warning(f"Admin route accessed via non-admin path: {request.path} from IP {request.remote_addr}")
            
            if request.path.startswith('/api/'):
                return jsonify({
                    'error': 'Invalid admin route access',
                    'redirect': '/admin/login'
                }), 403
            
            # Redirect to proper admin login
            return redirect(url_for('admin_login'))
        
        return f(*args, **kwargs)
    
    return wrapper

def rate_limited(attempt_type: str = 'general', identifier_func=None):
    """
    Rate limiting decorator for authentication endpoints.
    
    Args:
        attempt_type: Type of attempt being rate limited
        identifier_func: Function to get identifier for rate limiting
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Get identifier for rate limiting
            if identifier_func:
                identifier = identifier_func()
            else:
                identifier = request.remote_addr
            
            # Check rate limit
            rate_limit_result = auth_security.check_rate_limit(identifier, attempt_type)
            
            if not rate_limit_result['allowed']:
                reason = rate_limit_result['reason']
                logger.warning(f"Rate limit exceeded for {attempt_type}: {identifier} from IP {request.remote_addr}")
                
                if reason == 'locked_out':
                    remaining = rate_limit_result.get('lockout_remaining', 0)
                    message = f"Too many failed attempts. Please try again in {int(remaining/60)} minutes."
                else:
                    duration = rate_limit_result.get('lockout_duration', 900)
                    message = f"Too many attempts. Account locked for {int(duration/60)} minutes."
                
                if request.path.startswith('/api/'):
                    return jsonify({
                        'error': message,
                        'rate_limited': True,
                        'retry_after': rate_limit_result.get('lockout_remaining', 900)
                    }), 429
                
                flash(message, 'error')
                return redirect(request.url)
            
            return f(*args, **kwargs)
        
        return wrapper
    return decorator

def csrf_protected(f):
    """
    Enhanced CSRF protection decorator.
    
    Validates CSRF tokens for both form and JSON requests.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            # Check CSRF token
            token = None
            
            # For JSON requests, check headers
            if request.is_json:
                token = request.headers.get('X-CSRFToken') or request.headers.get('X-CSRF-Token')
                cookie_token = request.cookies.get('csrf_token')
                
                if not token or not cookie_token or token != cookie_token:
                    logger.warning(f"CSRF validation failed for JSON request to {request.path} from IP {request.remote_addr}")
                    return jsonify({'error': 'CSRF token validation failed'}), 403
            
            # For form requests, Flask-WTF handles CSRF automatically
            # This decorator is mainly for API endpoints
        
        return f(*args, **kwargs)
    
    return wrapper

def admin_or_customer_required(f):
    """
    Decorator that allows both admin and customer access.
    Used for routes like receipt generation that should be accessible by both.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        # Check if user is an admin
        if current_user.is_authenticated:
            session_validation = session_manager.validate_session()
            if session_validation['valid'] and session_manager.is_admin_session():
                # Admin access - no additional checks needed
                logger.info(f"Admin access granted to {current_user.username} for {request.path} from IP {request.remote_addr}")
                return f(*args, **kwargs)
        
        # Check if user is a customer
        session_validation = session_manager.validate_session()
        if session_validation['valid'] and session_manager.is_customer_session():
            # Customer access - verify customer details
            customer_id = session.get('customer_id')
            customer_email = session.get('customer_email')
            
            if customer_id and customer_email:
                # Verify customer exists in database
                with current_app.app_context():
                    from sqlalchemy import text
                    result = current_app.extensions['sqlalchemy'].db.session.execute(
                        text("SELECT email, email_verified FROM customer WHERE id = :customer_id"),
                        {'customer_id': customer_id}
                    ).fetchone()
                    
                    if result and result[0] == customer_email and result[1]:
                        # Create customer context
                        class CustomerContext:
                            def __init__(self, customer_id, email):
                                self.id = customer_id
                                self.email = email
                        
                        request.current_customer = CustomerContext(customer_id, customer_email)
                        logger.info(f"Customer access granted to {customer_email} for {request.path} from IP {request.remote_addr}")
                        return f(*args, **kwargs)
        
        # No valid authentication found
        logger.warning(f"Unauthorized access attempt to {request.path} from IP {request.remote_addr}")
        
        if request.path.startswith('/api/'):
            return jsonify({
                'error': 'Authentication required',
                'redirect': '/customer/login'
            }), 401
        
        flash('Please log in to access this resource.', 'error')
        return redirect(url_for('customer_login'))
    
    return wrapper

def security_headers(f):
    """
    Add security headers to responses.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        response = f(*args, **kwargs)
        
        # Add security headers
        if hasattr(response, 'headers'):
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            
            # Add CSP for admin pages
            if request.path.startswith('/admin/'):
                response.headers['Content-Security-Policy'] = (
                    "default-src 'self'; "
                    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                    "img-src 'self' data:; "
                    "font-src 'self' https://cdn.jsdelivr.net;"
                )
        
        return response
    
    return wrapper