"""
Secure Customer Orders API Module
Provides authenticated endpoints for customer order operations.
"""

from flask import Blueprint, request, jsonify, session
from functools import wraps
import logging

# This will be imported and configured in the main app
customer_orders_bp = Blueprint('customer_orders', __name__, url_prefix='/api/customer')

def create_customer_orders_api(app, db, Customer, Order, customer_auth_service):
    """
    Factory function to create customer orders API with dependencies.
    
    Args:
        app: Flask application instance
        db: Database instance
        Customer: Customer model
        Order: Order model
        customer_auth_service: CustomerAuthService instance
    """
    # Check if blueprint is already registered to prevent duplicate registration
    if 'customer_orders' in app.blueprints:
        return app.blueprints['customer_orders']
    
    logger = logging.getLogger(__name__)
    
    def api_customer_required(f):
        """API-specific customer authentication decorator."""
        @wraps(f)
        def wrapper(*args, **kwargs):
            customer_id = session.get('customer_id')
            if not customer_id:
                return jsonify({'error': 'Authentication required'}), 401
            
            customer = customer_auth_service.validate_customer_session(customer_id)
            if not customer:
                return jsonify({'error': 'Invalid session'}), 401
            
            request.current_customer = customer
            return f(*args, **kwargs)
        return wrapper
    
    def customer_owns_order_api(f):
        """Decorator to ensure customer owns the order in API context."""
        @wraps(f)
        def wrapper(order_id, *args, **kwargs):
            customer = request.current_customer
            
            if not customer_auth_service.customer_owns_order(customer, order_id):
                client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
                logger.warning(
                    f"Customer '{customer.email}' attempted unauthorized API access to order {order_id} from IP {client_ip}"
                )
                return jsonify({'error': 'Access denied'}), 403
            
            return f(order_id, *args, **kwargs)
        return wrapper
    
    @customer_orders_bp.route('/orders', methods=['GET'])
    @api_customer_required
    def get_customer_orders():
        """Get all orders for the authenticated customer."""
        try:
            customer = request.current_customer
            
            # Parse query parameters
            limit = request.args.get('limit', type=int)
            status_filter = request.args.get('status', '').strip()
            
            # Get orders using service
            orders = customer_auth_service.get_customer_orders(
                customer, 
                limit=limit, 
                status_filter=status_filter if status_filter else None
            )
            
            # Serialize orders
            orders_data = []
            for order in orders:
                orders_data.append({
                    'id': order.id,
                    'order_id': order.order_id,
                    'status': order.status,
                    'quantity': order.quantity,
                    'unit_price': order.unit_price,
                    'total_amount': order.total_amount,
                    'created_at': order.created_at.isoformat() if order.created_at else None,
                    'payment_date': order.payment_date.isoformat() if order.payment_date else None,
                    'shipping_address': order.shipping_address,
                    'pincode': order.pincode
                })
            
            return jsonify({
                'success': True,
                'orders': orders_data,
                'count': len(orders_data)
            })
            
        except Exception as e:
            logger.error(f"Error fetching customer orders: {str(e)}")
            return jsonify({'error': 'Internal server error'}), 500
    
    @customer_orders_bp.route('/orders/<int:order_id>', methods=['GET'])
    @api_customer_required
    @customer_owns_order_api
    def get_customer_order(order_id):
        """Get a specific order for the authenticated customer."""
        try:
            customer = request.current_customer
            order = customer_auth_service.get_customer_order_by_id(customer, order_id)
            
            if not order:
                return jsonify({'error': 'Order not found'}), 404
            
            order_data = {
                'id': order.id,
                'order_id': order.order_id,
                'razorpay_order_id': order.razorpay_order_id,
                'razorpay_payment_id': order.razorpay_payment_id,
                'status': order.status,
                'customer_name': order.customer_name,
                'customer_email': order.customer_email,
                'customer_phone': order.customer_phone,
                'shipping_address': order.shipping_address,
                'pincode': order.pincode,
                'quantity': order.quantity,
                'unit_price': order.unit_price,
                'total_amount': order.total_amount,
                'created_at': order.created_at.isoformat() if order.created_at else None,
                'payment_date': order.payment_date.isoformat() if order.payment_date else None,
                'updated_at': order.updated_at.isoformat() if order.updated_at else None
            }
            
            return jsonify({
                'success': True,
                'order': order_data
            })
            
        except Exception as e:
            logger.error(f"Error fetching customer order {order_id}: {str(e)}")
            return jsonify({'error': 'Internal server error'}), 500
    
    @customer_orders_bp.route('/orders/<int:order_id>/receipt', methods=['GET'])
    @api_customer_required
    @customer_owns_order_api
    def get_order_receipt(order_id):
        """Generate receipt for a customer's order."""
        try:
            customer = request.current_customer
            order = customer_auth_service.get_customer_order_by_id(customer, order_id)
            
            if not order:
                return jsonify({'error': 'Order not found'}), 404
            
            # Only allow receipt generation for paid orders
            if order.status not in ['processing', 'shipped', 'delivered']:
                return jsonify({'error': 'Receipt not available for this order status'}), 400
            
            # Generate receipt URL (this would typically redirect to the PDF generation)
            receipt_url = f"/api/generate-receipt/{order_id}"
            
            return jsonify({
                'success': True,
                'receipt_url': receipt_url,
                'order_id': order.order_id,
                'status': order.status
            })
            
        except Exception as e:
            logger.error(f"Error generating receipt for order {order_id}: {str(e)}")
            return jsonify({'error': 'Internal server error'}), 500
    
    @customer_orders_bp.route('/profile', methods=['GET'])
    @api_customer_required
    def get_customer_profile():
        """Get customer profile information."""
        try:
            customer = request.current_customer
            
            # Get customer statistics
            stats = customer_auth_service.get_customer_statistics(customer)
            
            profile_data = {
                'id': customer.id,
                'name': customer.name,
                'email': customer.email,
                'phone': customer.phone,
                'created_at': customer.created_at.isoformat() if customer.created_at else None,
                'statistics': stats
            }
            
            return jsonify({
                'success': True,
                'profile': profile_data
            })
            
        except Exception as e:
            logger.error(f"Error fetching customer profile: {str(e)}")
            return jsonify({'error': 'Internal server error'}), 500
    
    @customer_orders_bp.route('/profile', methods=['PUT'])
    @api_customer_required
    def update_customer_profile():
        """Update customer profile information."""
        try:
            customer = request.current_customer
            data = request.get_json()
            
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            # Update profile using service
            success, error_msg = customer_auth_service.update_customer_profile(customer, data)
            
            if not success:
                return jsonify({'error': error_msg}), 400
            
            return jsonify({
                'success': True,
                'message': 'Profile updated successfully'
            })
            
        except Exception as e:
            logger.error(f"Error updating customer profile: {str(e)}")
            return jsonify({'error': 'Internal server error'}), 500
    
    # Register blueprint with app only if not already registered
    if 'customer_orders' not in app.blueprints:
        app.register_blueprint(customer_orders_bp)
    
    return customer_orders_bp