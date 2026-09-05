import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Settings:
    """Application Settings"""
    
    # Project Info
    PROJECT_NAME = "URL Security Using IP-Based Threat Analysis"
    VERSION = "1.0.0"
    
    # Database
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PORT = int(os.getenv('DB_PORT', 3306))
    DB_USER = os.getenv('DB_USER', 'root')
    DB_PASSWORD = os.getenv('DB_PASSWORD', '')
    DB_NAME = os.getenv('DB_NAME', 'url_threat_analysis')
    DB_POOL_SIZE = int(os.getenv('DB_POOL_SIZE', 10))
    
    # API
    API_HOST = os.getenv('API_HOST', '0.0.0.0')
    API_PORT = int(os.getenv('API_PORT', 8000))
    API_DEBUG = os.getenv('API_DEBUG', 'True').lower() == 'true'
    
    # Dashboard
    DASHBOARD_PORT = int(os.getenv('DASHBOARD_PORT', 8501))
    
    # External APIs
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', 'logs/app.log')
    
    # Paths
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATA_DIR = os.path.join(BASE_DIR, 'data')
    MODELS_DIR = os.path.join(BASE_DIR, 'models', 'model_versions')
    LOGS_DIR = os.path.join(BASE_DIR, 'logs')

settings = Settings()