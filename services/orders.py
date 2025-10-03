"""
Order management service module.
Handles order CRUD operations, status updates, and business logic.
"""

from datetime import datetime, timezone
from sqlalchemy import or_, func
import io
import csv


class OrderService:
    """Service class for order management operations."""
    
    def __init__(self, db, Order):
        self.db = db
        self.Order = Order
    
    def get_orders_paginated(self, page=1, per_page=10, status_filter=None, search_query=None):
        """
        Get paginated orders with optional filtering.
        
        Args:
            page (int): Page number
            per_page (int): Items per page
            status_filter (str, optional): Filter by order status
            search_query (str, optional): Search in order details
            
        Returns:
            dict: Paginated orders data
        """
        query = self.Order.query
        
        # Apply status filter
        if status_filter:
            query = query.filter(self.Order.status == status_filter)
        
        # Apply search filter
        if search_query:
            search_pattern = f"%{search_query}%"
            query = query.filter(
                or_(
                    self.Order.order_id.ilike(search_pattern),
                    self.Order.customer_name.ilike(search_pattern),
                    self.Order.customer_email.ilike(search_pattern),
                    self.Order.customer_phone.ilike(search_pattern)
                )
            )
        
        # Order by creation date (newest first)
        query = query.order_by(self.Order.created_at.desc())
        
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
        
        return {
            'orders': orders,
            'pagination': {
                'page': pagination.page,
                'pages': pagination.pages,
                'per_page': pagination.per_page,
                'total': pagination.total,
                'has_next': pagination.has_next,
                'has_prev': pagination.has_prev
            }
        }
    
    def get_order_by_id(self, order_id):
        """
        Get order by ID.
        
        Args:
            order_id (int): Order ID
            
        Returns:
            dict: Order data or None if not found
        """
        order = self.Order.query.get(order_id)
        if not order:
            return None
        
        return {
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
        }
    
    def update_order(self, order_id, update_data, calculate_total_func):
        """
        Update order details.
        
        Args:
            order_id (int): Order ID
            update_data (dict): Data to update
            calculate_total_func (callable): Function to calculate total amount
            
        Returns:
            tuple: (success: bool, order_data: dict|None, error_message: str|None)
        """
        order = self.Order.query.get(order_id)
        if not order:
            return False, None, "Order not found"
        
        try:
            # Update allowed fields
            if 'customer_name' in update_data:
                order.customer_name = update_data['customer_name']
            if 'customer_email' in update_data:
                order.customer_email = update_data['customer_email']
            if 'customer_phone' in update_data:
                order.customer_phone = update_data['customer_phone']
            if 'shipping_address' in update_data:
                order.shipping_address = update_data['shipping_address']
            if 'pincode' in update_data:
                order.pincode = update_data['pincode']
            if 'quantity' in update_data:
                new_quantity = int(update_data['quantity'])
                if new_quantity > 0:
                    order.quantity = new_quantity
                    # Recalculate total amount
                    order.total_amount = calculate_total_func(new_quantity)
            
            order.updated_at = datetime.now(timezone.utc)
            self.db.session.commit()
            
            return True, {
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
            }, None
            
        except Exception as e:
            self.db.session.rollback()
            return False, None, str(e)
    
    def update_order_status(self, order_id, new_status):
        """
        Update order status.
        
        Args:
            order_id (int): Order ID
            new_status (str): New status
            
        Returns:
            tuple: (success: bool, order_data: dict|None, error_message: str|None)
        """
        known_statuses = ['pending', 'processing', 'shipped', 'delivered', 'cancelled']
        
        if new_status not in known_statuses:
            return False, None, "Invalid status"
        
        order = self.Order.query.get(order_id)
        if not order:
            return False, None, "Order not found"
        
        try:
            order.status = new_status
            order.updated_at = datetime.now(timezone.utc)
            self.db.session.commit()
            
            return True, {
                'id': order.id,
                'status': order.status,
                'updated_at': order.updated_at.isoformat()
            }, None
            
        except Exception as e:
            self.db.session.rollback()
            return False, None, str(e)
    
    def delete_order(self, order_id):
        """
        Delete an order.
        
        Args:
            order_id (int): Order ID
            
        Returns:
            tuple: (success: bool, error_message: str|None)
        """
        order = self.Order.query.get(order_id)
        if not order:
            return False, "Order not found"
        
        try:
            self.db.session.delete(order)
            self.db.session.commit()
            return True, None
            
        except Exception as e:
            self.db.session.rollback()
            return False, str(e)
    
    def get_order_statistics(self):
        """
        Get order statistics for dashboard.
        
        Returns:
            dict: Order statistics
        """
        total_orders = self.Order.query.count()
        pending_orders = self.Order.query.filter_by(status='pending').count()
        processing_orders = self.Order.query.filter_by(status='processing').count()
        shipped_orders = self.Order.query.filter_by(status='shipped').count()
        delivered_orders = self.Order.query.filter_by(status='delivered').count()
        cancelled_orders = self.Order.query.filter_by(status='cancelled').count()
        
        # Calculate total revenue (only from paid orders)
        paid_statuses = ['processing', 'shipped', 'delivered']
        total_revenue = self.db.session.query(func.sum(self.Order.total_amount)).filter(
            self.Order.status.in_(paid_statuses)
        ).scalar() or 0
        
        return {
            'total_orders': total_orders,
            'pending_orders': pending_orders,
            'processing_orders': processing_orders,
            'shipped_orders': shipped_orders,
            'delivered_orders': delivered_orders,
            'cancelled_orders': cancelled_orders,
            'total_revenue': float(total_revenue),
            'status_counts': {
                'pending': pending_orders,
                'processing': processing_orders,
                'shipped': shipped_orders,
                'delivered': delivered_orders,
                'cancelled': cancelled_orders
            }
        }
    
    def get_recent_orders(self, limit=10):
        """
        Get recent orders for dashboard.
        
        Args:
            limit (int): Number of orders to return
            
        Returns:
            list: Recent orders
        """
        return self.Order.query.order_by(self.Order.created_at.desc()).limit(limit).all()
    
    def export_orders_csv(self):
        """
        Export all orders to CSV format.
        
        Returns:
            str: CSV content
        """
        orders = self.Order.query.order_by(self.Order.created_at.desc()).all()
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Order ID', 'Customer Name', 'Email', 'Phone', 'Address', 'Pincode',
            'Quantity', 'Total Amount', 'Status', 'Created At', 'Payment Date', 'Payment ID'
        ])
        
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
        return output.getvalue()
    
    def cancel_order_by_razorpay_id(self, razorpay_order_id):
        """
        Cancel order by Razorpay order ID.
        
        Args:
            razorpay_order_id (str): Razorpay order ID
            
        Returns:
            bool: True if order was found and cancelled, False otherwise
        """
        if not razorpay_order_id:
            return False
        
        order = self.Order.query.filter_by(razorpay_order_id=razorpay_order_id).first()
        if order:
            order.status = 'cancelled'
            order.updated_at = datetime.now(timezone.utc)
            self.db.session.commit()
            return True
        
        return False