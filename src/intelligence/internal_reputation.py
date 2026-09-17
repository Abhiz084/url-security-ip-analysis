"""
Internal Reputation Provider
Aggregates reputation signals from our own MySQL database:
- ip_addresses table (threat_score, country, isp, ...)
- threat_intelligence table (active threats)
- alerts table (recent alerts for this IP)
- traffic_logs table (traffic frequency)
"""

from loguru import logger
from database.connection import db_manager


class InternalReputationProvider:
    """Aggregate internal reputation signals for an IP"""

    def __init__(self):
        pass

    def check(self, ip_address):
        """
        Returns:
            dict with internal threat data
        """
        result = {
            'ip': ip_address,
            'country': None,
            'city': None,
            'region': None,
            'latitude': None,
            'longitude': None,
            'asn': None,
            'organization': None,
            'isp': None,
            'internal_threat_score': 0.0,
            'internal_alerts': 0,
            'active_threats': 0,
            'threat_types': [],
            'total_requests': 0,
            'source': 'internal',
            'cached': False
        }

        try:
            # -------- 1. Base IP info --------
            ip_rows = db_manager.execute_query(
                "SELECT * FROM ip_addresses WHERE ip_address = %s",
                (ip_address,)
            )
            if ip_rows:
                row = ip_rows[0]
                result.update({
                    'country': row.get('country'),
                    'city': row.get('city'),
                    'region': row.get('region'),
                    'latitude': float(row['latitude']) if row.get('latitude') else None,
                    'longitude': float(row['longitude']) if row.get('longitude') else None,
                    'asn': row.get('asn'),
                    'organization': row.get('organization'),
                    'isp': row.get('isp'),
                    'internal_threat_score': float(row.get('threat_score', 0)),
                    'total_requests': int(row.get('total_requests', 0))
                })

            # -------- 2. Active threats --------
            threat_rows = db_manager.execute_query(
                """
                SELECT threat_type, confidence_score, source_feed
                FROM threat_intelligence
                WHERE ip_address = %s AND is_active = TRUE
                """,
                (ip_address,)
            )
            if threat_rows:
                result['active_threats'] = len(threat_rows)
                result['threat_types'] = list({
                    r['threat_type'] for r in threat_rows if r.get('threat_type')
                })
                # Boost threat score based on active threats
                avg_conf = sum(float(r.get('confidence_score', 0)) for r in threat_rows) / len(threat_rows)
                result['internal_threat_score'] = max(result['internal_threat_score'], avg_conf)

            # -------- 3. Recent alerts --------
            alert_rows = db_manager.execute_query(
                """
                SELECT COUNT(*) as cnt
                FROM alerts
                WHERE source_ip = %s
                  AND timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                """,
                (ip_address,)
            )
            if alert_rows:
                result['internal_alerts'] = int(alert_rows[0]['cnt'] or 0)

                # Boost threat score if there are recent alerts
                if result['internal_alerts'] > 0:
                    alert_boost = min(result['internal_alerts'] * 5, 40)
                    result['internal_threat_score'] = min(
                        100,
                        result['internal_threat_score'] + alert_boost
                    )

        except Exception as e:
            logger.debug(f"Internal reputation check failed for {ip_address}: {e}")

        return result