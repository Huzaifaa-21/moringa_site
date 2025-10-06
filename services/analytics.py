from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple, Optional
from sqlalchemy import func, and_

# We expect db and Order models to be provided from the caller to avoid circular imports

def get_revenue_timeseries(db, Order, days: int, status_arg: str) -> Dict[str, List]:
    """Return labels, revenue, and orders arrays for the last N days.

    Args:
        db: SQLAlchemy db instance.
        Order: Order model class.
        days: Number of days to include.
        status_arg: Optional status filter string (comma-separated for multiple); defaults to paid/fulfilled statuses.

    Returns:
        Dict with keys: labels, revenue, orders.
    """
    now = datetime.now(timezone.utc)
    start_date = now - timedelta(days=days - 1)

    known_statuses = ['pending', 'processing', 'shipped', 'delivered', 'cancelled']
    
    # Handle multiple status filters (comma-separated)
    if status_arg and status_arg.strip():
        requested_statuses = [s.strip().lower() for s in status_arg.split(',') if s.strip()]
        statuses = [s for s in requested_statuses if s in known_statuses]
        # If no valid statuses provided, fall back to default
        if not statuses:
            statuses = ['processing', 'shipped', 'delivered']
    else:
        # Default to paid/fulfilled statuses
        statuses = ['processing', 'shipped', 'delivered']

    rows = (
        db.session.query(
            db.func.date(Order.created_at).label('day'),
            db.func.sum(Order.total_amount).label('revenue'),
            db.func.count(Order.id).label('orders'),
        )
        .filter(
            Order.created_at >= start_date,
            Order.status.in_(statuses),
        )
        .group_by(db.func.date(Order.created_at))
        .order_by(db.func.date(Order.created_at))
        .all()
    )

    series: Dict[str, Dict[str, float]] = {}
    for r in rows:
        d = str(r.day)
        series[d] = {
            'revenue': float(r.revenue or 0),
            'orders': int(r.orders or 0),
        }

    labels: List[str] = []
    revenue: List[float] = []
    orders: List[int] = []
    for i in range(days):
        d = (start_date + timedelta(days=i)).date().isoformat()
        labels.append(d)
        revenue.append(series.get(d, {'revenue': 0}).get('revenue', 0))
        orders.append(series.get(d, {'orders': 0}).get('orders', 0))

    return {
        'labels': labels,
        'revenue': revenue,
        'orders': orders,
    }


def get_order_status_distribution(db, Order) -> Dict[str, int]:
    """Get distribution of orders by status.
    
    Args:
        db: SQLAlchemy db instance.
        Order: Order model class.
        
    Returns:
        Dict with status as key and count as value.
    """
    results = (
        db.session.query(
            Order.status,
            func.count(Order.id).label('count')
        )
        .group_by(Order.status)
        .all()
    )
    
    return {result.status: result.count for result in results}


def get_top_customers(db, Order, limit: int = 10) -> List[Dict]:
    """Get top customers by total order value.
    
    Args:
        db: SQLAlchemy db instance.
        Order: Order model class.
        limit: Number of top customers to return.
        
    Returns:
        List of customer data with total spent and order count.
    """
    results = (
        db.session.query(
            Order.customer_email,
            Order.customer_name,
            func.sum(Order.total_amount).label('total_spent'),
            func.count(Order.id).label('order_count')
        )
        .filter(Order.status.in_(['processing', 'shipped', 'delivered']))
        .group_by(Order.customer_email, Order.customer_name)
        .order_by(func.sum(Order.total_amount).desc())
        .limit(limit)
        .all()
    )
    
    return [
        {
            'email': result.customer_email,
            'name': result.customer_name,
            'total_spent': float(result.total_spent),
            'order_count': result.order_count
        }
        for result in results
    ]


def get_monthly_growth(db, Order) -> Dict[str, float]:
    """Calculate month-over-month growth metrics.
    
    Args:
        db: SQLAlchemy db instance.
        Order: Order model class.
        
    Returns:
        Dict with growth metrics.
    """
    now = datetime.now(timezone.utc)
    current_month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    last_month_start = (current_month_start - timedelta(days=1)).replace(day=1)
    
    # Current month stats
    current_month_stats = (
        db.session.query(
            func.sum(Order.total_amount).label('revenue'),
            func.count(Order.id).label('orders')
        )
        .filter(
            Order.created_at >= current_month_start,
            Order.status.in_(['processing', 'shipped', 'delivered'])
        )
        .first()
    )
    
    # Last month stats
    last_month_stats = (
        db.session.query(
            func.sum(Order.total_amount).label('revenue'),
            func.count(Order.id).label('orders')
        )
        .filter(
            and_(
                Order.created_at >= last_month_start,
                Order.created_at < current_month_start
            ),
            Order.status.in_(['processing', 'shipped', 'delivered'])
        )
        .first()
    )
    
    current_revenue = float(current_month_stats.revenue or 0)
    current_orders = current_month_stats.orders or 0
    last_revenue = float(last_month_stats.revenue or 0)
    last_orders = last_month_stats.orders or 0
    
    # Calculate growth percentages
    revenue_growth = 0
    if last_revenue > 0:
        revenue_growth = ((current_revenue - last_revenue) / last_revenue) * 100
    
    order_growth = 0
    if last_orders > 0:
        order_growth = ((current_orders - last_orders) / last_orders) * 100
    
    return {
        'current_month_revenue': current_revenue,
        'current_month_orders': current_orders,
        'last_month_revenue': last_revenue,
        'last_month_orders': last_orders,
        'revenue_growth_percent': revenue_growth,
        'order_growth_percent': order_growth
    }


def get_average_order_value(db, Order, days: Optional[int] = None) -> float:
    """Calculate average order value.
    
    Args:
        db: SQLAlchemy db instance.
        Order: Order model class.
        days: Number of days to look back (None for all time).
        
    Returns:
        Average order value.
    """
    query = db.session.query(func.avg(Order.total_amount))
    query = query.filter(Order.status.in_(['processing', 'shipped', 'delivered']))
    
    if days:
        start_date = datetime.now(timezone.utc) - timedelta(days=days)
        query = query.filter(Order.created_at >= start_date)
    
    result = query.scalar()
    return float(result or 0)


def get_conversion_metrics(db, Order) -> Dict[str, float]:
    """Calculate conversion and completion metrics.
    
    Args:
        db: SQLAlchemy db instance.
        Order: Order model class.
        
    Returns:
        Dict with conversion metrics.
    """
    total_orders = db.session.query(func.count(Order.id)).scalar() or 0
    completed_orders = (
        db.session.query(func.count(Order.id))
        .filter(Order.status.in_(['delivered']))
        .scalar() or 0
    )
    cancelled_orders = (
        db.session.query(func.count(Order.id))
        .filter(Order.status == 'cancelled')
        .scalar() or 0
    )
    
    completion_rate = 0
    cancellation_rate = 0
    
    if total_orders > 0:
        completion_rate = (completed_orders / total_orders) * 100
        cancellation_rate = (cancelled_orders / total_orders) * 100
    
    return {
        'total_orders': total_orders,
        'completed_orders': completed_orders,
        'cancelled_orders': cancelled_orders,
        'completion_rate_percent': completion_rate,
        'cancellation_rate_percent': cancellation_rate
    }