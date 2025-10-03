from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple

# We expect db and Order models to be provided from the caller to avoid circular imports

def get_revenue_timeseries(db, Order, days: int, status_arg: str) -> Dict[str, List]:
    """Return labels, revenue, and orders arrays for the last N days.

    Args:
        db: SQLAlchemy db instance.
        Order: Order model class.
        days: Number of days to include.
        status_arg: Optional status filter string; defaults to paid/fulfilled statuses.

    Returns:
        Dict with keys: labels, revenue, orders.
    """
    now = datetime.now(timezone.utc)
    start_date = now - timedelta(days=days - 1)

    known_statuses = ['pending', 'processing', 'shipped', 'delivered', 'cancelled']
    statuses = [status_arg] if (status_arg and status_arg.lower() in known_statuses) else ['processing', 'shipped', 'delivered']

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