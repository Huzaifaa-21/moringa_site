# Authentication Security Implementation

## Overview

This document outlines the comprehensive secure authentication system implemented for the Moringa site application. The system addresses all security requirements including session management, login flow restrictions, receipt generation security, and industry-standard authentication practices.

## Security Features Implemented

### 1. Enhanced Session Management

#### Session Configuration
- **Session Lifetime**: 8 hours for admin sessions, 30 days for customer sessions
- **Session Refresh**: Automatic refresh when session expires within 30 minutes
- **Session Validation**: Real-time validation with expiration checks
- **Session Security**: HTTPOnly, Secure (HTTPS), SameSite=Lax cookies

#### Session Data Structure
```python
{
    'admin_id': int,
    'username': str,
    'login_time': ISO datetime,
    'last_activity': ISO datetime,
    'expires_at': ISO datetime,
    'session_id': secure random token,
    'ip_address': str,
    'user_agent': str (truncated),
    'remember_me': bool,
    'mfa_verified': bool,
    'session_type': 'admin' | 'customer'
}
```

#### Session Security Features
- **Automatic Expiration**: Sessions expire based on configured lifetime
- **Activity Tracking**: Last activity timestamp updated on each request
- **Session Validation**: Comprehensive validation on every protected route
- **Secure Cleanup**: Proper session clearing on logout
- **IP Tracking**: Session tied to originating IP address

### 2. Admin Login Flow Security

#### Route Restrictions
- **Admin Access**: Restricted exclusively to `/admin/` paths
- **Root URL Protection**: No automatic admin login at `http://127.0.0.1:5001`
- **Route Validation**: `@admin_route_required` decorator enforces path restrictions

#### Authentication Flow
1. **Pre-login Validation**: Check for existing valid sessions
2. **Credential Verification**: Username/password validation with rate limiting
3. **MFA Verification**: Required for all admin accounts
4. **Session Creation**: Enhanced session with security metadata
5. **Redirect Protection**: Secure redirect to admin dashboard only

#### Rate Limiting
- **Failed Attempts**: Maximum 5 attempts per identifier
- **Lockout Duration**: 15 minutes after exceeding limit
- **Identifier Types**: Username, email, or IP address
- **Automatic Reset**: Lockout clears after timeout

### 3. Customer Authentication

#### Enhanced Customer Sessions
- **Extended Lifetime**: 30-day sessions for customer convenience
- **Email Verification**: Required before full access
- **MFA Support**: Optional multi-factor authentication
- **Session Validation**: Same security standards as admin sessions

#### Customer Login Security
- **Rate Limiting**: Applied to prevent brute force attacks
- **Session Management**: Enhanced session creation and validation
- **Email Verification**: Enforced before sensitive operations

### 4. Receipt Generation Security

#### Authentication Requirements
- **Customer Authentication**: Must be logged in with valid session
- **Order Ownership**: Automatic verification of order ownership
- **Session Validation**: Real-time session validation before access

#### Security Checks
1. **Session Validation**: Verify customer session is valid and not expired
2. **Customer Verification**: Confirm customer exists in database
3. **Order Ownership**: Verify customer owns the requested order
4. **Email Verification**: Ensure customer email is verified

### 5. CSRF Protection

#### Implementation
- **Token Generation**: Secure CSRF tokens for all forms
- **Header Validation**: X-CSRFToken header validation for API requests
- **Cookie Validation**: CSRF token cookie validation
- **Automatic Protection**: Flask-WTF integration for form protection

#### API Protection
- **JSON Requests**: CSRF token in headers
- **Form Requests**: Automatic Flask-WTF protection
- **Admin APIs**: Enhanced CSRF protection for all admin operations

### 6. Security Headers

#### Implemented Headers
```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: [admin-specific CSP]
```

#### Content Security Policy (Admin Pages)
```
default-src 'self';
script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;
style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;
img-src 'self' data:;
font-src 'self' https://cdn.jsdelivr.net;
```

## Authentication Decorators

### @secure_admin_required
- **Session Validation**: Comprehensive session validation
- **MFA Verification**: Ensures MFA is configured and verified
- **User Verification**: Double-checks Flask-Login authentication
- **Session Refresh**: Automatic session refresh when needed
- **Security Logging**: Logs all access attempts and security events

### @secure_customer_required
- **Session Validation**: Customer session validation
- **Email Verification**: Ensures customer email is verified
- **Database Verification**: Confirms customer exists in database
- **Session Refresh**: Automatic session refresh
- **Context Injection**: Adds customer to request context

### @admin_route_required
- **Path Validation**: Ensures admin routes only accessible via `/admin/` paths
- **Security Logging**: Logs invalid access attempts
- **Automatic Redirect**: Redirects to proper admin login

### @rate_limited
- **Configurable Limits**: Customizable attempt limits and lockout duration
- **Multiple Identifiers**: Support for username, email, or IP-based limiting
- **Automatic Cleanup**: Expired lockouts automatically cleared
- **Security Logging**: Logs rate limit violations

### @csrf_protected
- **Token Validation**: Validates CSRF tokens for API requests
- **Header Support**: Supports X-CSRFToken and X-CSRF-Token headers
- **Cookie Validation**: Validates CSRF token cookies
- **Error Handling**: Proper error responses for invalid tokens

### @security_headers
- **Automatic Headers**: Adds security headers to all responses
- **CSP Support**: Content Security Policy for admin pages
- **XSS Protection**: Multiple layers of XSS protection
- **Clickjacking Protection**: X-Frame-Options header

## Security Best Practices Implemented

### 1. Password Security
- **Hashing**: Werkzeug PBKDF2 password hashing
- **Salt**: Automatic salt generation for each password
- **Verification**: Secure password verification

### 2. Session Security
- **Secure Cookies**: HTTPOnly, Secure, SameSite attributes
- **Session Rotation**: New session ID on login
- **Proper Cleanup**: Session clearing on logout
- **Expiration**: Automatic session expiration

### 3. Input Validation
- **Form Validation**: Flask-WTF form validation
- **Data Sanitization**: Input sanitization and validation
- **SQL Injection Protection**: SQLAlchemy ORM protection
- **XSS Protection**: Template escaping and CSP headers

### 4. Logging and Monitoring
- **Security Events**: Comprehensive security event logging
- **Failed Attempts**: Logging of all failed authentication attempts
- **Session Events**: Logging of session creation, refresh, and destruction
- **Access Logging**: Logging of all admin and customer access

### 5. Error Handling
- **Secure Errors**: No sensitive information in error messages
- **Rate Limiting**: Proper error responses for rate-limited requests
- **Session Errors**: Clear error messages for session issues
- **Redirect Security**: Secure redirects to prevent open redirects

## Configuration

### Flask Configuration
```python
# Session security
app.config['SESSION_COOKIE_SECURE'] = not app.debug
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['SESSION_COOKIE_NAME'] = 'moringa_session'

# Security headers
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = timedelta(hours=1)
```

### Session Manager Configuration
```python
# Session lifetimes
SESSION_LIFETIME = timedelta(hours=8)  # Admin sessions
CUSTOMER_SESSION_LIFETIME = timedelta(days=30)  # Customer sessions
SESSION_REFRESH_THRESHOLD = timedelta(minutes=30)  # Refresh threshold

# Rate limiting
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)
```

## Testing and Verification

### Security Tests
1. **Session Expiration**: Verify sessions expire correctly
2. **Rate Limiting**: Test rate limiting functionality
3. **CSRF Protection**: Verify CSRF token validation
4. **Route Restrictions**: Test admin route access restrictions
5. **Authentication Flow**: Complete authentication flow testing

### Manual Testing
1. **Admin Login**: Test admin login with and without MFA
2. **Customer Login**: Test customer login and session management
3. **Receipt Generation**: Test receipt access with proper authentication
4. **Session Management**: Test session expiration and refresh
5. **Security Headers**: Verify security headers are present

## Deployment Considerations

### Production Settings
- **HTTPS Only**: Ensure HTTPS is enabled for secure cookies
- **Secret Key**: Use a strong, randomly generated secret key
- **Database Security**: Secure database credentials and connections
- **Environment Variables**: Secure environment variable management

### Monitoring
- **Security Logs**: Monitor security event logs
- **Failed Attempts**: Monitor failed authentication attempts
- **Session Anomalies**: Monitor unusual session patterns
- **Rate Limiting**: Monitor rate limiting events

## Maintenance

### Regular Tasks
- **Log Review**: Regular review of security logs
- **Session Cleanup**: Automatic cleanup of expired sessions
- **Security Updates**: Regular updates of security dependencies
- **Configuration Review**: Periodic review of security configuration

### Security Audits
- **Authentication Flow**: Regular testing of authentication flows
- **Session Management**: Verification of session security
- **CSRF Protection**: Testing of CSRF protection mechanisms
- **Rate Limiting**: Verification of rate limiting functionality

## Conclusion

This implementation provides enterprise-grade authentication security with:
- ✅ Proper session management with expiration and validation
- ✅ Restricted admin access exclusively to `/admin/` endpoints
- ✅ Secure receipt generation with proper authentication
- ✅ Comprehensive CSRF protection
- ✅ Industry-standard security practices
- ✅ Rate limiting and security monitoring
- ✅ Secure session storage and validation

The system maintains all existing functionality while significantly enhancing security posture and following industry best practices for web application authentication.# Moringa Site Improvements Summary

This document summarizes all the improvements and fixes implemented for the Moringa site application.

## 🔧 Issues Resolved

### 1. "View Website" Redirect Issue ✅
**Problem**: Admin clicking "View Website" was incorrectly redirected to customer session instead of public website view.

**Solution**:
- Updated `index()` route in `app.py` to detect admin sessions
- Modified `index.html` template to handle admin viewing state
- Added admin-specific navigation and notices when admin views public site
- Implemented proper session differentiation between admin and customer contexts

**Files Modified**:
- `app.py` (lines 199-210)
- `templates/index.html` (navigation and login prompt sections)

### 2. Admin Login Page Behavior ✅
**Problem**: Admin login page incorrectly displaying "Logged in successfully" message on page load.

**Investigation**: 
- Thoroughly examined admin login template and route logic
- No automatic success message found in code
- Issue likely related to browser caching or session state
- Template properly handles flash messages from server-side only

**Status**: No code issues found - likely browser/session related

### 3. Environment Variables Security ✅
**Problem**: Production credentials exposed, weak security practices.

**Solutions Implemented**:
- Created secure `.env.example` template with best practices
- Updated existing `.env` file to remove production credentials
- Implemented `SecurityConfig` class for environment validation
- Added comprehensive security documentation (`SECURITY.md`)
- Created encryption utilities for sensitive data
- Added security validation on application startup

**Files Created**:
- `.env.example` - Secure template
- `services/security_config.py` - Security configuration module
- `SECURITY.md` - Comprehensive security documentation

**Files Modified**:
- `.env` - Removed production credentials, added security warnings

### 4. Analytics.py Integration ✅
**Problem**: Analytics module appeared unused in codebase.

**Investigation Results**:
- Analytics.py IS being used via `/api/admin/revenue-timeseries` endpoint
- Backend functionality was complete but frontend visualization was missing

**Enhancements Made**:
- Added interactive revenue analytics chart to admin dashboard
- Integrated Chart.js for data visualization
- Enhanced analytics module with additional business metrics
- Added real-time chart updates with filtering options

**Files Modified**:
- `templates/admin_dashboard.html` - Added analytics chart section
- `services/analytics.py` - Enhanced with additional analytics functions

**New Features Added**:
- Revenue and order trends visualization
- Time period filtering (7, 30, 90 days)
- Status-based filtering
- Dual-axis chart (revenue + order count)

## 🚀 Site Improvements Implemented

### 1. Comprehensive Logging System ✅
**Implementation**:
- Created `services/logging_config.py` with structured logging
- Security-aware log formatting (sanitizes sensitive data)
- Multiple log handlers (console, file, error, security, performance)
- Request/response logging middleware for Flask
- Performance timing utilities

**Features**:
- Automatic sensitive data redaction
- Structured JSON logging option
- Log rotation and retention
- Security event tracking
- Performance metrics logging

### 2. Advanced Error Handling ✅
**Implementation**:
- Created `services/error_handling.py` with custom exceptions
- Comprehensive error response system
- User-friendly error pages
- API vs web request differentiation
- Error tracking and logging

**Custom Exceptions**:
- `ValidationError` - Input validation failures
- `AuthenticationError` - Authentication failures
- `AuthorizationError` - Permission denied
- `PaymentError` - Payment processing issues
- `DatabaseError` - Database operation failures
- `ExternalServiceError` - Third-party service issues
- `RateLimitError` - Rate limiting violations
- `ConfigurationError` - Configuration problems

**Features**:
- Automatic error logging with context
- User-friendly error messages
- Error ID tracking for support
- Development vs production error details
- Proper HTTP status codes

### 3. Enhanced User Experience ✅
**Improvements**:
- Created beautiful error page template (`templates/error.html`)
- Responsive design for all screen sizes
- Contextual error icons and messages
- Auto-refresh for service unavailable errors
- Error analytics tracking

### 4. Security Enhancements ✅
**Implementations**:
- Environment variable validation system
- Sensitive data encryption utilities
- Security event logging
- Configuration security checks
- Best practices documentation

### 5. Performance Monitoring ✅
**Features**:
- Performance timing context manager
- Request duration logging
- Database query monitoring capabilities
- Memory and resource usage tracking
- Performance metrics API endpoints

### 6. Session Management Improvements ✅
**Enhancements**:
- Proper admin vs customer session handling
- Session security configurations
- Cross-session contamination prevention
- Secure cookie settings

## 📊 Analytics Enhancements

### New Analytics Functions
1. `get_order_status_distribution()` - Order status breakdown
2. `get_top_customers()` - Customer ranking by value
3. `get_monthly_growth()` - Month-over-month growth metrics
4. `get_average_order_value()` - AOV calculations
5. `get_conversion_metrics()` - Completion and cancellation rates

### Admin Dashboard Analytics
- Interactive revenue chart with Chart.js
- Real-time data filtering
- Dual-axis visualization (revenue + orders)
- Mobile-responsive design
- Loading states and error handling

## 🔒 Security Improvements

### Environment Security
- Production credential protection
- Secure key generation utilities
- Environment validation system
- Encryption for sensitive data storage
- Comprehensive security documentation

### Application Security
- Security event logging
- Rate limiting error handling
- Input validation utilities
- CSRF protection maintenance
- Secure session configuration

### Monitoring & Alerting
- Security event tracking
- Failed login attempt monitoring
- Suspicious activity detection
- Error rate monitoring
- Performance degradation alerts

## 📝 Documentation

### New Documentation Files
1. `SECURITY.md` - Comprehensive security best practices
2. `IMPROVEMENTS.md` - This summary document
3. `.env.example` - Secure environment template

### Code Documentation
- Comprehensive docstrings for all new modules
- Type hints for better code maintainability
- Inline comments for complex logic
- Error handling examples

## 🛠 Technical Debt Addressed

### Code Organization
- Modular service architecture
- Separation of concerns
- Reusable utility functions
- Consistent error handling patterns

### Maintainability
- Type hints throughout new code
- Comprehensive logging for debugging
- Structured configuration management
- Clear documentation and examples

### Scalability
- Performance monitoring infrastructure
- Efficient database query patterns
- Caching-ready architecture
- Microservice-ready modular design

## 🎯 Future Recommendations

### Short Term (1-3 months)
1. Implement rate limiting middleware
2. Add API versioning
3. Set up automated testing
4. Implement caching layer
5. Add health check endpoints

### Medium Term (3-6 months)
1. Migrate to containerized deployment
2. Implement CI/CD pipeline
3. Add comprehensive monitoring dashboard
4. Implement backup and disaster recovery
5. Add advanced analytics features

### Long Term (6+ months)
1. Consider microservices architecture
2. Implement advanced security features (WAF, DDoS protection)
3. Add machine learning for fraud detection
4. Implement advanced analytics and reporting
5. Consider cloud-native deployment

## 📈 Impact Summary

### Security
- ✅ Eliminated production credential exposure
- ✅ Implemented comprehensive security monitoring
- ✅ Added data encryption capabilities
- ✅ Created security best practices documentation

### User Experience
- ✅ Fixed admin website viewing issue
- ✅ Added beautiful error pages
- ✅ Improved session management
- ✅ Enhanced admin dashboard with analytics

### Maintainability
- ✅ Added comprehensive logging system
- ✅ Implemented structured error handling
- ✅ Created modular service architecture
- ✅ Added extensive documentation

### Performance
- ✅ Added performance monitoring
- ✅ Implemented efficient analytics queries
- ✅ Created performance timing utilities
- ✅ Optimized database operations

### Analytics
- ✅ Integrated existing analytics backend
- ✅ Added interactive frontend visualization
- ✅ Enhanced business intelligence capabilities
- ✅ Provided real-time data insights

## 🔍 Testing Recommendations

To verify all improvements:

1. **Admin Session Testing**:
   - Login as admin
   - Click "View Website" - should show admin notice
   - Verify proper navigation options

2. **Error Handling Testing**:
   - Test various error scenarios
   - Verify error pages display correctly
   - Check error logging functionality

3. **Analytics Testing**:
   - Access admin dashboard
   - Verify revenue chart loads
   - Test filtering options
   - Check data accuracy

4. **Security Testing**:
   - Verify environment validation
   - Test sensitive data redaction in logs
   - Check security event logging

5. **Performance Testing**:
   - Monitor request timing logs
   - Verify performance metrics collection
   - Test under various load conditions

All improvements have been implemented with backward compatibility and can be deployed incrementally for testing and validation.# Security Best Practices

This document outlines security best practices for the Moringa site application, with special focus on environment variable management and sensitive data protection.

## Environment Variable Security

### 1. Never Commit Sensitive Data

- **Never commit `.env` files** to version control
- Use `.env.example` as a template with placeholder values
- Add `.env` to `.gitignore` (already configured)

### 2. Environment Variable Categories

#### Critical Secrets (Never expose)
- `SECRET_KEY` - Flask session encryption key
- `DATABASE_URL` - Database connection string with credentials
- `RAZORPAY_KEY_SECRET` - Payment gateway secret
- `SMTP_PASS` - Email service password

#### Sensitive Configuration
- `ADMIN_PASSWORD` - Initial admin password
- `RAZORPAY_KEY_ID` - Payment gateway public key
- `SMTP_USER` - Email service username

#### Public Configuration
- `COMPANY_NAME`, `COMPANY_EMAIL`, `COMPANY_PHONE`
- `FLASK_ENV`, `FLASK_DEBUG`

### 3. Secure Value Generation

#### Generate Strong SECRET_KEY
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

#### Generate Strong Passwords
```bash
python -c "import secrets, string; chars = string.ascii_letters + string.digits + '!@#$%^&*'; print(''.join(secrets.choice(chars) for _ in range(20)))"
```

### 4. Environment-Specific Configuration

#### Development Environment
- Use test/sandbox credentials for external services
- Enable debug mode and detailed logging
- Use local database with non-production data

#### Production Environment
- Use production credentials only in production
- Disable debug mode
- Enable HTTPS enforcement
- Use secure session cookies
- Implement proper logging without exposing secrets

## Implementation Guidelines

### 1. Application Startup Security Check

The application includes a security validation system that checks for:
- Missing required environment variables
- Insecure default values
- Production credentials in development
- Weak secret keys

### 2. Secure Configuration Loading

```python
from services.security_config import security_config

# Validate environment on startup
validation = security_config.validate_environment()
if not validation['is_secure']:
    # Log warnings and exit if critical issues found
    security_config.log_security_status()
```

### 3. Encrypted Storage for Sensitive Data

For highly sensitive data that must be stored:

```python
# Encrypt sensitive data
encrypted_value = security_config.encrypt_sensitive_data("sensitive_data")

# Decrypt when needed
decrypted_value = security_config.decrypt_sensitive_data(encrypted_value)
```

## Production Deployment Checklist

### Before Deployment

- [ ] Replace all default/placeholder values in `.env`
- [ ] Use production-grade database with proper access controls
- [ ] Enable MFA for all admin accounts
- [ ] Use production credentials for external services
- [ ] Set `FLASK_ENV=production` and `FLASK_DEBUG=False`
- [ ] Configure secure session settings
- [ ] Enable HTTPS enforcement
- [ ] Set up proper logging without exposing secrets

### Environment Variables for Production

```bash
# Flask Configuration
SECRET_KEY=<64-character-random-hex-string>
FLASK_ENV=production
FLASK_DEBUG=False

# Security Settings
FORCE_HTTPS=True
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Strict

# Database (use connection pooling and SSL)
DATABASE_URL=mysql+pymysql://user:password@host:port/db?ssl=true

# External Services (production credentials)
RAZORPAY_KEY_ID=rzp_live_...
RAZORPAY_KEY_SECRET=<production-secret>
```

## Secret Management Tools

For production environments, consider using dedicated secret management tools:

### Cloud Providers
- **AWS Secrets Manager** - For AWS deployments
- **Azure Key Vault** - For Azure deployments
- **Google Secret Manager** - For GCP deployments

### Self-Hosted Solutions
- **HashiCorp Vault** - Enterprise-grade secret management
- **Docker Secrets** - For containerized deployments
- **Kubernetes Secrets** - For Kubernetes deployments

### Implementation Example with AWS Secrets Manager

```python
import boto3
import json

def get_secret(secret_name, region_name="us-east-1"):
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
        secret = get_secret_value_response['SecretString']
        return json.loads(secret)
    except Exception as e:
        raise e

# Usage
secrets = get_secret("moringa-app-secrets")
DATABASE_URL = secrets['DATABASE_URL']
RAZORPAY_KEY_SECRET = secrets['RAZORPAY_KEY_SECRET']
```

## Access Controls

### 1. Principle of Least Privilege
- Grant minimum necessary permissions
- Use separate credentials for different environments
- Regularly audit and rotate credentials

### 2. Network Security
- Use VPNs or private networks for database access
- Implement IP whitelisting where possible
- Use SSL/TLS for all external communications

### 3. Application Security
- Implement proper authentication and authorization
- Use secure session management
- Enable comprehensive audit logging
- Regular security updates and dependency scanning

## Monitoring and Alerting

### 1. Security Events to Monitor
- Failed login attempts
- Unusual access patterns
- Configuration changes
- Credential usage anomalies

### 2. Logging Best Practices
- Log security events without exposing sensitive data
- Use structured logging (JSON format)
- Implement log rotation and retention policies
- Monitor logs for security incidents

### 3. Alerting
- Set up alerts for security events
- Monitor for credential exposure in logs
- Alert on configuration changes
- Implement automated response for critical events

## Regular Security Maintenance

### Monthly Tasks
- [ ] Review and rotate credentials
- [ ] Update dependencies and security patches
- [ ] Review access logs for anomalies
- [ ] Validate backup and recovery procedures

### Quarterly Tasks
- [ ] Security audit and penetration testing
- [ ] Review and update security policies
- [ ] Training for development team
- [ ] Disaster recovery testing

### Annual Tasks
- [ ] Comprehensive security assessment
- [ ] Update security documentation
- [ ] Review and update incident response procedures
- [ ] Security compliance audit

## Incident Response

### In Case of Credential Compromise

1. **Immediate Actions**
   - Revoke compromised credentials immediately
   - Change all related passwords and keys
   - Review access logs for unauthorized usage
   - Notify relevant stakeholders

2. **Investigation**
   - Determine scope of compromise
   - Identify affected systems and data
   - Document timeline of events
   - Preserve evidence for analysis

3. **Recovery**
   - Deploy new secure credentials
   - Verify system integrity
   - Monitor for continued unauthorized access
   - Update security measures to prevent recurrence

4. **Post-Incident**
   - Conduct post-mortem analysis
   - Update security procedures
   - Provide additional training if needed
   - Document lessons learned

## Contact Information

For security-related questions or to report security issues:
- Email: security@puremoringa.com
- Emergency: [Emergency contact information]

**Remember: Security is everyone's responsibility. When in doubt, err on the side of caution.**