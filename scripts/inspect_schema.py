import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.connection import db_manager

# alert_type ENUM values
r = db_manager.execute_query("SHOW COLUMNS FROM alerts LIKE 'alert_type'")
print("\n=== alerts.alert_type ===")
for row in r:
    print(f"  Type: {row['Type']}")

# severity ENUM values
r = db_manager.execute_query("SHOW COLUMNS FROM alerts LIKE 'severity'")
print("\n=== alerts.severity ===")
for row in r:
    print(f"  Type: {row['Type']}")

# status ENUM values
r = db_manager.execute_query("SHOW COLUMNS FROM alerts LIKE 'status'")
print("\n=== alerts.status ===")
for row in r:
    print(f"  Type: {row['Type']}")

# Foreign keys
r = db_manager.execute_query("""
    SELECT COLUMN_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME
    FROM information_schema.KEY_COLUMN_USAGE
    WHERE TABLE_SCHEMA = 'url_threat_analysis'
      AND TABLE_NAME = 'alerts'
      AND REFERENCED_TABLE_NAME IS NOT NULL
""")
print("\n=== Foreign Keys on alerts ===")
for row in r:
    print(f"  {row['COLUMN_NAME']} → {row['REFERENCED_TABLE_NAME']}.{row['REFERENCED_COLUMN_NAME']}")