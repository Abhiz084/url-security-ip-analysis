import mysql.connector
from mysql.connector import pooling, Error
from config.database import DB_CONFIG, POOL_CONFIG
from loguru import logger
import time

class MySQLConnection:
    """MySQL Connection Manager using Connection Pooling"""
    
    _instance = None
    _pool = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._pool is None:
            self._create_pool()
    
    def _create_pool(self):
        """Create MySQL connection pool"""
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                self._pool = mysql.connector.pooling.MySQLConnectionPool(
                    pool_name=POOL_CONFIG['pool_name'],
                    pool_size=POOL_CONFIG['pool_size'],
                    pool_reset_session=POOL_CONFIG['pool_reset_session'],
                    **DB_CONFIG
                )
                logger.info(f"MySQL connection pool created successfully (size: {POOL_CONFIG['pool_size']})")
                return
            except Error as e:
                retry_count += 1
                logger.error(f"Attempt {retry_count}: Failed to create connection pool: {e}")
                if retry_count < max_retries:
                    time.sleep(2)
                else:
                    logger.error("Max retries reached. Could not create connection pool.")
                    raise
    
    def get_connection(self):
        """Get connection from pool with retry"""
        max_retries = 2
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                connection = self._pool.get_connection()
                return connection
            except Error as e:
                retry_count += 1
                logger.error(f"Attempt {retry_count}: Failed to get connection: {e}")
                if retry_count < max_retries:
                    time.sleep(1)
                else:
                    raise
    
    def execute_query(self, query, params=None, fetch=True):
        """Execute a query and return results"""
        connection = None
        cursor = None
        try:
            connection = self.get_connection()
            cursor = connection.cursor(dictionary=True)
            cursor.execute(query, params or ())
            
            if fetch:
                result = cursor.fetchall()
            else:
                connection.commit()
                result = cursor.lastrowid
            
            return result
        except Error as e:
            if connection:
                connection.rollback()
            logger.error(f"Query execution failed: {e}")
            raise
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
    
    def execute_many(self, query, params_list):
        """Execute a query with multiple parameter sets"""
        connection = None
        cursor = None
        try:
            connection = self.get_connection()
            cursor = connection.cursor()
            cursor.executemany(query, params_list)
            connection.commit()
            return cursor.rowcount
        except Error as e:
            if connection:
                connection.rollback()
            logger.error(f"Batch execution failed: {e}")
            raise
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
    
    def call_procedure(self, procedure_name, params=None):
        """Call a stored procedure"""
        connection = None
        cursor = None
        try:
            connection = self.get_connection()
            cursor = connection.cursor(dictionary=True)
            
            if params:
                cursor.callproc(procedure_name, params)
            else:
                cursor.callproc(procedure_name)
            
            results = []
            for result in cursor.stored_results():
                results.extend(result.fetchall())
            
            return results
        except Error as e:
            logger.error(f"Procedure call failed: {e}")
            raise
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
    
    def test_connection(self):
        """Test database connection"""
        try:
            connection = self.get_connection()
            cursor = connection.cursor()
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            cursor.close()
            connection.close()
            logger.info("Database connection test successful")
            return True
        except Error as e:
            logger.error(f"Database connection test failed: {e}")
            return False

# Singleton instance
db_manager = MySQLConnection()