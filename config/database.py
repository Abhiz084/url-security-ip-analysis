from config.settings import settings

# MySQL Database Configuration
DB_CONFIG = {
    'host': settings.DB_HOST,
    'port': settings.DB_PORT,
    'user': settings.DB_USER,
    'password': settings.DB_PASSWORD,
    'database': settings.DB_NAME,
    'charset': 'utf8mb4',
    'autocommit': False,
    'use_pure': True,
    'raise_on_warnings': True
}

# Connection pool configuration
POOL_CONFIG = {
    'pool_name': 'url_security_pool',
    'pool_size': settings.DB_POOL_SIZE,
    'pool_reset_session': True
}