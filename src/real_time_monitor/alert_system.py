"""
Alert Generation & Management System

Features:
- FK-safe inserts (auto-creates IP rows for source/destination)
- ENUM validation (auto-fallback for invalid values)
- Status workflow with transition validation
- Audit logging on every status change
- Deduplication (same IP + type within 60s)
- Bulk operations
- Callback system for real-time notifications
"""

import json
import threading
from datetime import datetime
from loguru import logger

from database.crud_operations import CRUDOperations
from database.connection import db_manager


class AlertSystem:
    """Alert management system with workflow validation and FK safety"""

    # ============================================
    # VALIDATION SETS (must match DB schema ENUMs)
    # ============================================

    VALID_ALERT_TYPES = {
        'malicious_url',
        'suspicious_ip',
        'high_traffic',
        'dns_anomaly',
        'geolocation_mismatch',
        'frequency_attack',
        'other',
    }

    VALID_SEVERITIES = {'low', 'medium', 'high', 'critical'}

    VALID_STATUSES = {
        'new', 'acknowledged', 'investigating', 'resolved', 'false_positive'
    }

    # Valid status transitions
    VALID_TRANSITIONS = {
        'new':            {'acknowledged', 'investigating', 'resolved', 'false_positive'},
        'acknowledged':   {'investigating', 'resolved', 'false_positive'},
        'investigating':  {'resolved', 'false_positive'},
        'resolved':       {'investigating'},   # allow reopen for further review
        'false_positive': {'investigating'},   # allow reopen
    }

    def __init__(self):
        self.crud = CRUDOperations()
        self.alert_callbacks = []
        self.recent_alerts = {}     # dedup: {key: datetime}
        self.alert_count = 0
        self._lock = threading.Lock()

    # ============================================
    # CALLBACKS
    # ============================================

    def register_callback(self, callback):
        """Register a callback for new alerts"""
        self.alert_callbacks.append(callback)

    def _fire_callbacks(self, alert):
        """Fire all registered callbacks (safe)"""
        for cb in self.alert_callbacks:
            try:
                cb(alert)
            except Exception as e:
                logger.debug(f"Callback error: {e}")

    # ============================================
    # INTERNAL HELPERS
    # ============================================

    def _ensure_ip_exists(self, ip_address):
        """
        Ensure an IP exists in ip_addresses (FK requirement).
        Returns True on success, False on failure.
        """
        if not ip_address:
            return False

        try:
            self.crud.insert_ip_address(
                ip_address=ip_address,
                ip_version='IPv6' if ':' in ip_address else 'IPv4',
                threat_score=0.0,
            )
            return True
        except Exception as e:
            logger.debug(f"Could not ensure IP {ip_address}: {e}")
            return False

    @classmethod
    def _validate_alert_type(cls, alert_type):
        """Return a valid alert_type or fallback to 'other'"""
        if alert_type in cls.VALID_ALERT_TYPES:
            return alert_type
        logger.debug(f"Invalid alert_type '{alert_type}' → using 'other'")
        return 'other'

    @classmethod
    def _validate_severity(cls, severity):
        """Return a valid severity or fallback to 'low'"""
        if severity in cls.VALID_SEVERITIES:
            return severity
        logger.debug(f"Invalid severity '{severity}' → using 'low'")
        return 'low'

    def _is_duplicate(self, source_ip, alert_type, window_seconds=60):
        """Check dedup window and prune expired entries"""
        key = f"{source_ip}:{alert_type}"
        now = datetime.now()

        with self._lock:
            # Prune expired
            self.recent_alerts = {
                k: v for k, v in self.recent_alerts.items()
                if (now - v).total_seconds() < 300
            }

            # Check duplicate
            if key in self.recent_alerts:
                last = self.recent_alerts[key]
                if (now - last).total_seconds() < window_seconds:
                    return True

            self.recent_alerts[key] = now
            return False

    # ============================================
    # CREATE
    # ============================================

    def create_alert(self, alert_type, severity, source_ip,
                     destination_ip=None, url_id=None, description=None):
        """
        Create a new alert.

        Automatically:
        - Validates ENUM values
        - Ensures source/destination IPs exist in ip_addresses (FK)
        - Deduplicates (same IP + type within 60s)

        Returns:
            int | None: alert_id on success, None on failure/dedup
        """
        # ---- Deduplication ----
        if self._is_duplicate(source_ip, alert_type):
            logger.debug(f"Dedup: skipped duplicate alert for {source_ip}/{alert_type}")
            return None

        # ---- Validate ENUMs ----
        alert_type = self._validate_alert_type(alert_type)
        severity = self._validate_severity(severity)

        # ---- FK safety: ensure IPs exist ----
        self._ensure_ip_exists(source_ip)
        if destination_ip:
            self._ensure_ip_exists(destination_ip)

        # ---- Truncate description ----
        if description and len(str(description)) > 65000:
            description = str(description)[:65000]

        # ---- Insert ----
        try:
            alert_id = self.crud.insert_alert(
                alert_type=alert_type,
                severity=severity,
                source_ip=source_ip,
                destination_ip=destination_ip,
                url_id=url_id,
                description=description,
            )

            if alert_id is None:
                logger.warning(f"Alert insert returned None for {source_ip}")
                return None

            with self._lock:
                self.alert_count += 1

            # ---- Build alert dict for callbacks ----
            alert = {
                'alert_id': alert_id,
                'timestamp': datetime.now().isoformat(),
                'alert_type': alert_type,
                'severity': severity,
                'source_ip': source_ip,
                'destination_ip': destination_ip,
                'url_id': url_id,
                'description': description,
                'status': 'new',
            }

            logger.info(f"🚨 ALERT [{severity}] {alert_type}: {description}")
            self._fire_callbacks(alert)

            return alert_id

        except Exception as e:
            logger.error(f"Failed to create alert: {e}")
            return None

    def create_alerts_bulk(self, alerts):
        """
        Create multiple alerts in one call.

        alerts: list of dicts with keys:
            alert_type, severity, source_ip,
            destination_ip (opt), url_id (opt), description (opt)

        Returns: list of alert_ids (None for those that failed/were deduped)
        """
        return [self.create_alert(**a) for a in alerts]

    # ============================================
    # TRANSITION VALIDATION
    # ============================================

    def can_transition(self, current_status, new_status):
        """Check if a status transition is allowed"""
        allowed = self.VALID_TRANSITIONS.get(current_status, set())
        return new_status in allowed

    # ============================================
    # UPDATE WITH VALIDATION + VERIFICATION
    # ============================================

    def update_alert_status(self, alert_id, new_status, user='analyst',
                            notes=None):
        """
        Update alert status with validation + verification.

        Returns:
            dict: {
                'success': bool,
                'message': str,
                'alert_id': int,
                'old_status': str | None,
                'new_status': str,
            }
        """
        # ---- Validate target status ----
        if new_status not in self.VALID_STATUSES:
            return {
                'success': False,
                'message': f"Invalid status '{new_status}'. Valid: {self.VALID_STATUSES}",
                'alert_id': alert_id,
                'old_status': None,
                'new_status': new_status,
            }

        # ---- Fetch current alert ----
        try:
            rows = db_manager.execute_query(
                "SELECT alert_id, status, severity FROM alerts WHERE alert_id = %s",
                (alert_id,)
            )
        except Exception as e:
            return {
                'success': False,
                'message': f'DB error: {e}',
                'alert_id': alert_id,
                'old_status': None,
                'new_status': new_status,
            }

        if not rows:
            return {
                'success': False,
                'message': f'Alert {alert_id} not found',
                'alert_id': alert_id,
                'old_status': None,
                'new_status': new_status,
            }

        current_status = rows[0]['status']

        # ---- Same status? ----
        if current_status == new_status:
            return {
                'success': False,
                'message': f'Alert is already "{new_status}"',
                'alert_id': alert_id,
                'old_status': current_status,
                'new_status': new_status,
            }

        # ---- Validate transition ----
        if not self.can_transition(current_status, new_status):
            return {
                'success': False,
                'message': f'Cannot transition "{current_status}" → "{new_status}"',
                'alert_id': alert_id,
                'old_status': current_status,
                'new_status': new_status,
            }

        # ---- Perform update ----
        try:
            affected = self.crud.update_alert_status(
                alert_id=alert_id,
                status=new_status,
                resolved_by=user if new_status in ('resolved', 'false_positive') else None,
                resolution_notes=notes,
            )
        except Exception as e:
            return {
                'success': False,
                'message': f'Update failed: {e}',
                'alert_id': alert_id,
                'old_status': current_status,
                'new_status': new_status,
            }

        if affected == 0:
            return {
                'success': False,
                'message': 'Update affected 0 rows — check alert ID or DB',
                'alert_id': alert_id,
                'old_status': current_status,
                'new_status': new_status,
            }

        # ---- Audit log (best-effort) ----
        self._write_audit(
            alert_id=alert_id,
            old_status=current_status,
            new_status=new_status,
            user=user,
            notes=notes,
        )

        logger.info(f"✅ Alert {alert_id}: {current_status} → {new_status} by {user}")

        return {
            'success': True,
            'message': f'Alert updated: {current_status} → {new_status}',
            'alert_id': alert_id,
            'old_status': current_status,
            'new_status': new_status,
        }

    def _write_audit(self, alert_id, old_status, new_status, user, notes):
        """Write audit log entry (best-effort, never raises)"""
        try:
            self.crud.insert_audit_log(
                user_id=None,
                action=f'alert_status:{new_status}',
                table_affected='alerts',
                record_id=alert_id,
                old_values=json.dumps({'status': old_status}),
                new_values=json.dumps({
                    'status': new_status,
                    'user': user,
                    'notes': notes,
                }),
                ip_address=None,
            )
        except Exception as e:
            logger.debug(f"Audit log skipped: {e}")

    # ============================================
    # BULK OPERATIONS
    # ============================================

    def bulk_update(self, alert_ids, new_status, user='analyst', notes=None):
        """
        Update multiple alerts at once.

        Returns: {
            'success': int,
            'failed': int,
            'details': list of individual results
        }
        """
        results = {'success': 0, 'failed': 0, 'details': []}

        for aid in alert_ids:
            r = self.update_alert_status(aid, new_status, user=user, notes=notes)
            if r['success']:
                results['success'] += 1
            else:
                results['failed'] += 1
            results['details'].append(r)

        logger.info(
            f"Bulk update: {results['success']} success, "
            f"{results['failed']} failed → {new_status}"
        )
        return results

    def bulk_acknowledge_by_severity(self, severity, user='analyst'):
        """Acknowledge all active alerts of a given severity"""
        try:
            matches = db_manager.execute_query("""
                SELECT alert_id FROM alerts
                WHERE severity = %s
                  AND status IN ('new', 'acknowledged', 'investigating')
            """, (severity,))
        except Exception as e:
            logger.error(f"bulk_acknowledge_by_severity failed: {e}")
            return {'success': 0, 'failed': 0, 'details': []}

        ids = [m['alert_id'] for m in matches]
        if not ids:
            return {'success': 0, 'failed': 0, 'details': []}

        return self.bulk_update(
            ids, 'acknowledged', user=user,
            notes=f'Bulk acknowledge for {severity} severity'
        )

    # ============================================
    # READS
    # ============================================

    def get_alert_by_id(self, alert_id):
        """Fetch a single alert"""
        return self.crud.get_alert_by_id(alert_id)

    def get_active_alerts(self, limit=50):
        """Get active (unresolved) alerts, sorted by severity then time"""
        return db_manager.execute_query("""
            SELECT * FROM alerts
            WHERE status IN ('new', 'acknowledged', 'investigating')
            ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low'),
                     timestamp DESC
            LIMIT %s
        """, (limit,))

    def get_alerts_by_severity(self, severity, limit=50):
        """Get active alerts of a specific severity"""
        return db_manager.execute_query("""
            SELECT * FROM alerts
            WHERE severity = %s
              AND status IN ('new', 'acknowledged', 'investigating')
            ORDER BY timestamp DESC
            LIMIT %s
        """, (severity, limit))

    def get_alerts_by_status(self, status, limit=50):
        """Get alerts with a specific status"""
        return db_manager.execute_query("""
            SELECT * FROM alerts
            WHERE status = %s
            ORDER BY timestamp DESC
            LIMIT %s
        """, (status, limit))

    def get_resolved_alerts(self, limit=50):
        """Get resolved/false-positive alerts (archive)"""
        return db_manager.execute_query("""
            SELECT * FROM alerts
            WHERE status IN ('resolved', 'false_positive')
            ORDER BY resolved_at DESC
            LIMIT %s
        """, (limit,))

    def get_alerts_by_ip(self, ip_address, limit=50):
        """Get all alerts for a given source IP"""
        return db_manager.execute_query("""
            SELECT * FROM alerts
            WHERE source_ip = %s
            ORDER BY timestamp DESC
            LIMIT %s
        """, (ip_address, limit))

    def search_alerts(self, term, limit=100):
        """Search alerts by description or IP"""
        like = f"%{term}%"
        return db_manager.execute_query("""
            SELECT * FROM alerts
            WHERE description LIKE %s
               OR source_ip LIKE %s
               OR alert_type LIKE %s
            ORDER BY timestamp DESC
            LIMIT %s
        """, (like, like, like, limit))

    # ============================================
    # STATISTICS
    # ============================================

    def get_alert_stats(self):
        """7-day aggregate stats"""
        return db_manager.execute_query("""
            SELECT severity, status, COUNT(*) as count
            FROM alerts
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY severity, status
        """)

    def get_today_summary(self):
        """Today's alert summary"""
        r = db_manager.execute_query("""
            SELECT
                COUNT(*) as total_alerts,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'high'     THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity = 'medium'   THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity = 'low'      THEN 1 ELSE 0 END) as low,
                SUM(CASE WHEN status = 'new'            THEN 1 ELSE 0 END) as new_alerts,
                SUM(CASE WHEN status = 'acknowledged'   THEN 1 ELSE 0 END) as acknowledged,
                SUM(CASE WHEN status = 'investigating'  THEN 1 ELSE 0 END) as investigating,
                SUM(CASE WHEN status = 'resolved'       THEN 1 ELSE 0 END) as resolved,
                SUM(CASE WHEN status = 'false_positive' THEN 1 ELSE 0 END) as false_positive
            FROM alerts
            WHERE DATE(timestamp) = CURDATE()
        """)
        return r[0] if r else {
            'total_alerts': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
            'new_alerts': 0, 'acknowledged': 0, 'investigating': 0,
            'resolved': 0, 'false_positive': 0,
        }

    def get_alert_trends(self, days=7):
        """Daily alert counts by severity"""
        return db_manager.execute_query("""
            SELECT DATE(timestamp) as date, severity, COUNT(*) as count
            FROM alerts
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
            GROUP BY DATE(timestamp), severity
            ORDER BY date DESC
        """, (days,))

    def get_top_alerted_ips(self, limit=10):
        """IPs with the most alerts"""
        return db_manager.execute_query("""
            SELECT source_ip, COUNT(*) as alert_count,
                   MAX(timestamp) as last_alert,
                   GROUP_CONCAT(DISTINCT alert_type) as types
            FROM alerts
            GROUP BY source_ip
            ORDER BY alert_count DESC
            LIMIT %s
        """, (limit,))

    # ============================================
    # MAINTENANCE
    # ============================================

    def resolve_all_for_ip(self, ip_address, user='analyst',
                           notes='Bulk resolved'):
        """Resolve all active alerts for a given IP"""
        try:
            active = db_manager.execute_query("""
                SELECT alert_id FROM alerts
                WHERE source_ip = %s
                  AND status IN ('new', 'acknowledged', 'investigating')
            """, (ip_address,))
        except Exception as e:
            logger.error(f"resolve_all_for_ip query failed: {e}")
            return {'success': 0, 'failed': 0, 'details': []}

        ids = [a['alert_id'] for a in active]
        if not ids:
            return {'success': 0, 'failed': 0, 'details': []}

        return self.bulk_update(ids, 'resolved', user=user, notes=notes)

    def cleanup_old_resolved_alerts(self, days_to_keep=90):
        """Archive/delete resolved alerts older than N days"""
        try:
            return db_manager.execute_query("""
                DELETE FROM alerts
                WHERE status IN ('resolved', 'false_positive')
                  AND resolved_at < DATE_SUB(NOW(), INTERVAL %s DAY)
            """, (days_to_keep,), fetch=False)
        except Exception as e:
            logger.error(f"cleanup_old_resolved_alerts failed: {e}")
            return 0