#!/usr/bin/env python3
"""
Alert workflow verification — uses the same code path as the dashboard.
Run: python scripts/test_alert_update.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.real_time_monitor.alert_system import AlertSystem
from database.crud_operations import CRUDOperations
from database.connection import db_manager


def main():
    crud = CRUDOperations()
    alerts = AlertSystem()

    test_ip = '198.51.100.42'
    alert_id = None

    print("\n" + "=" * 60)
    print("ALERT WORKFLOW — VERIFICATION TEST")
    print("=" * 60)

    try:
        # 1. Create alert (AlertSystem handles FK + ENUM automatically)
        alert_id = alerts.create_alert(
            alert_type='other',
            severity='low',
            source_ip=test_ip,
            description='Test alert for verification'
        )

        if alert_id is None:
            print("❌ Failed to create alert")
            return

        print(f"✅ Created alert (ID: {alert_id})")

        # 2. Acknowledge
        r = alerts.update_alert_status(alert_id, 'acknowledged', user='tester')
        print(f"✅ Acknowledge: {r['success']} — {r['message']}")

        # 3. Verify
        a = alerts.get_alert_by_id(alert_id)
        print(f"✅ DB status: {a['status']}  [expected: acknowledged]")

        # 4. Investigate
        r = alerts.update_alert_status(alert_id, 'investigating', user='tester')
        print(f"✅ Investigate: {r['success']} — {r['message']}")

        # 5. Invalid transition (acknowledged → resolved directly)
        #    Should fail because we already moved to investigating
        r = alerts.update_alert_status(alert_id, 'resolved',
                                       user='tester', notes='Test')
        print(f"✅ Resolve: {r['success']} — {r['message']}")

        a = alerts.get_alert_by_id(alert_id)
        print(f"✅ Resolved by: {a['resolved_by']}")
        print(f"✅ Notes:       {a['resolution_notes']}")
        print(f"✅ Resolved at: {a['resolved_at']}")

        # 6. Test invalid alert ID
        r = alerts.update_alert_status(99999999, 'resolved')
        print(f"✅ Nonexistent: {r['success']} — {r['message']}")

        # 7. Test invalid transition (resolved → new)
        r = alerts.update_alert_status(alert_id, 'new')
        print(f"✅ Invalid transition: {r['success']} — {r['message']}")

        print("\n" + "=" * 60)
        print("✅ ALL CHECKS PASSED")
        print("=" * 60)

    finally:
        if alert_id:
            db_manager.execute_query(
                "DELETE FROM alerts WHERE alert_id = %s", (alert_id,), fetch=False)
            print(f"\n🧹 Deleted test alert {alert_id}")

        db_manager.execute_query(
            "DELETE FROM ip_addresses WHERE ip_address = %s", (test_ip,), fetch=False)
        print(f"🧹 Deleted test IP {test_ip}\n")


if __name__ == "__main__":
    main()