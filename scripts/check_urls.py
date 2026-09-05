#!/usr/bin/env python3
"""Check URLs in the database"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.connection import db_manager

print("\n" + "=" * 60)
print("📊 DATABASE URL INVENTORY")
print("=" * 60)

# Show URL sources summary
result = db_manager.execute_query(
    'SELECT source, COUNT(*) as cnt FROM urls GROUP BY source ORDER BY cnt DESC'
)

print("\n📋 URL Sources:")
print("-" * 50)
total = 0
for r in result:
    print(f"  {r['source']:<30}: {r['cnt']:>5} URLs")
    total += r['cnt']
print("-" * 50)
print(f"  {'TOTAL':<30}: {total:>5} URLs")

# Show latest URLs
print("\n📋 Latest 15 URLs:")
print("-" * 80)
urls = db_manager.execute_query(
    'SELECT url_id, domain, source, is_malicious, submission_date FROM urls ORDER BY submission_date DESC LIMIT 15'
)
for u in urls:
    malicious = "⚠️" if u['is_malicious'] else "✅" if u['is_malicious'] is False else "❓"
    date_str = str(u['submission_date'])[:19] if u['submission_date'] else 'N/A'
    print(f"  {malicious} {u['domain'][:35]:<35} | {u['source'][:20]:<20} | {date_str}")

# Show traffic_capture URLs specifically
traffic = db_manager.execute_query(
    "SELECT COUNT(*) as cnt FROM urls WHERE source='traffic_capture'"
)
print(f"\n📡 Traffic Capture URLs: {traffic[0]['cnt'] if traffic else 0}")

# Show alert count
alerts = db_manager.execute_query("SELECT COUNT(*) as cnt FROM alerts")
print(f"🚨 Total Alerts: {alerts[0]['cnt'] if alerts else 0}")

# Show prediction count
preds = db_manager.execute_query("SELECT COUNT(*) as cnt FROM model_predictions")
print(f"🤖 ML Predictions: {preds[0]['cnt'] if preds else 0}")

print("\n" + "=" * 60)