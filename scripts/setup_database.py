#!/usr/bin/env python3
"""
Database Setup Script
Creates database schema, stored procedures, and seed data
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mysql.connector
from mysql.connector import Error
from config.settings import settings
from loguru import logger
import re

# Configure logger
logger.remove()  # Remove default handler
logger.add(sys.stdout, level="INFO", format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>")
logger.add("logs/database_setup.log", rotation="1 MB", level="INFO")

class DatabaseSetup:
    """Database setup and migration handler"""
    
    def __init__(self):
        self.connection = None
    
    def _create_connection(self, database=None):
        """Create a new database connection"""
        config = {
            'host': settings.DB_HOST,
            'port': settings.DB_PORT,
            'user': settings.DB_USER,
            'password': settings.DB_PASSWORD,
            'charset': 'utf8mb4',
            'autocommit': True,
            'use_pure': True
        }
        
        if database:
            config['database'] = database
        
        try:
            conn = mysql.connector.connect(**config)
            return conn
        except Error as e:
            logger.error(f"Failed to connect: {e}")
            raise
    
    def create_database(self):
        """Create database if not exists"""
        try:
            conn = self._create_connection()
            cursor = conn.cursor()
            
            cursor.execute(f"""
                CREATE DATABASE IF NOT EXISTS {settings.DB_NAME}
                CHARACTER SET utf8mb4
                COLLATE utf8mb4_unicode_ci
            """)
            
            cursor.close()
            conn.close()
            logger.info(f"Database '{settings.DB_NAME}' created/verified")
            return True
        except Error as e:
            logger.error(f"Failed to create database: {e}")
            return False
    
    def _execute_and_consume(self, cursor, query, params=None):
        """Execute query and consume all results"""
        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            # Consume ALL result sets
            while True:
                try:
                    if cursor.with_rows:
                        cursor.fetchall()
                except:
                    pass
                
                try:
                    if not cursor.nextset():
                        break
                except:
                    break
                    
        except Error as e:
            raise e
    
    def _execute_sql_content(self, cursor, sql_content, filename):
        """Execute SQL content handling both regular SQL and stored procedures"""
        
        # Check if file has DELIMITER statements
        if 'DELIMITER' in sql_content.upper():
            self._execute_with_delimiters(cursor, sql_content, filename)
        else:
            self._execute_regular(cursor, sql_content, filename)
    
    def _execute_regular(self, cursor, sql_content, filename):
        """Execute regular SQL statements"""
        # Remove single-line comments
        lines = []
        for line in sql_content.split('\n'):
            line = line.strip()
            if line and not line.startswith('--'):
                lines.append(line)
        
        clean_sql = ' '.join(lines)
        
        # Split by semicolons (but not inside quotes)
        statements = []
        current = []
        in_string = False
        for char in clean_sql:
            if char == "'":
                in_string = not in_string
            if char == ';' and not in_string:
                stmt = ''.join(current).strip()
                if stmt:
                    statements.append(stmt)
                current = []
            else:
                current.append(char)
        
        # Add last statement if any
        stmt = ''.join(current).strip()
        if stmt:
            statements.append(stmt)
        
        for stmt in statements:
            if not stmt:
                continue
            try:
                self._execute_and_consume(cursor, stmt)
            except Error as e:
                err_str = str(e)
                # Ignore common non-critical errors
                if any(x in err_str.lower() for x in ['duplicate', 'already exists']):
                    logger.debug(f"Skipping existing object in {filename}")
                elif 'unknown table' in err_str.lower():
                    logger.debug(f"Table reference in {filename}: {err_str[:80]}")
                else:
                    logger.warning(f"Statement in {filename}: {err_str[:120]}")
    
    def _execute_with_delimiters(self, cursor, sql_content, filename):
        """Execute SQL with DELIMITER statements for stored procedures"""
        # Process each DELIMITER section
        # Reset to default delimiter first
        current_delimiter = ';'
        
        # Remove DELIMITER commands and process
        lines = sql_content.split('\n')
        current_statement = []
        
        for line in lines:
            stripped = line.strip()
            
            # Check for DELIMITER change
            if stripped.upper().startswith('DELIMITER'):
                # Execute any accumulated statement first
                if current_statement:
                    stmt = '\n'.join(current_statement).strip()
                    if stmt and stmt != ';':
                        try:
                            self._execute_and_consume(cursor, stmt)
                        except Error as e:
                            err_str = str(e)
                            if not any(x in err_str.lower() for x in ['duplicate', 'already exists']):
                                logger.warning(f"Statement in {filename}: {err_str[:120]}")
                    current_statement = []
                
                # Change delimiter
                parts = stripped.split()
                if len(parts) == 2:
                    current_delimiter = parts[1]
                continue
            
            # Check if line ends with current delimiter
            if stripped.endswith(current_delimiter):
                # Add line without delimiter
                stmt_line = stripped[:-len(current_delimiter)].strip()
                if stmt_line:
                    current_statement.append(stmt_line)
                
                # Execute complete statement
                if current_statement:
                    stmt = '\n'.join(current_statement).strip()
                    if stmt:
                        try:
                            self._execute_and_consume(cursor, stmt)
                        except Error as e:
                            err_str = str(e)
                            if not any(x in err_str.lower() for x in ['duplicate', 'already exists']):
                                logger.warning(f"Statement in {filename}: {err_str[:120]}")
                    current_statement = []
            else:
                # Add line to current statement
                current_statement.append(line)
    
    def run_migration_file(self, filepath):
        """Execute a single migration file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                sql_content = file.read()
            
            conn = self._create_connection(settings.DB_NAME)
            cursor = conn.cursor()
            
            self._execute_sql_content(cursor, sql_content, os.path.basename(filepath))
            
            cursor.close()
            conn.close()
            
            logger.info(f"✓ Executed: {os.path.basename(filepath)}")
            return True
            
        except Error as e:
            logger.error(f"✗ Failed to execute {os.path.basename(filepath)}: {e}")
            return False
    
    def run_migrations(self):
        """Run all migration files in order"""
        migrations_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'database', 'migrations'
        )
        
        if not os.path.exists(migrations_dir):
            logger.error(f"Migrations directory not found: {migrations_dir}")
            return False
        
        # Get all SQL files sorted by name
        migration_files = sorted([
            f for f in os.listdir(migrations_dir) 
            if f.endswith('.sql')
        ])
        
        logger.info(f"Found {len(migration_files)} migration files")
        
        for migration_file in migration_files:
            filepath = os.path.join(migrations_dir, migration_file)
            
            if not self.run_migration_file(filepath):
                logger.error(f"Migration failed: {migration_file}")
                return False
        
        logger.info("All migrations completed successfully")
        return True
    
    def verify_setup(self):
        """Verify database setup"""
        try:
            conn = self._create_connection(settings.DB_NAME)
            cursor = conn.cursor()
            
            # Check tables
            cursor.execute("SHOW TABLES")
            tables = cursor.fetchall()
            
            logger.info(f"\n📊 Database contains {len(tables)} tables:")
            for table in tables:
                logger.info(f"   └─ {table[0]}")
            
            # Check stored procedures
            cursor.execute("""
                SELECT ROUTINE_NAME, ROUTINE_TYPE 
                FROM information_schema.ROUTINES 
                WHERE ROUTINE_SCHEMA = %s
            """, (settings.DB_NAME,))
            procedures = cursor.fetchall()
            
            if procedures:
                logger.info(f"\n📦 Stored procedures/functions ({len(procedures)}):")
                for proc in procedures:
                    logger.info(f"   └─ {proc[0]} ({proc[1]})")
            
            # Check views
            cursor.execute("""
                SELECT TABLE_NAME 
                FROM information_schema.VIEWS 
                WHERE TABLE_SCHEMA = %s
            """, (settings.DB_NAME,))
            views = cursor.fetchall()
            
            if views:
                logger.info(f"\n👁  Views ({len(views)}):")
                for view in views:
                    logger.info(f"   └─ {view[0]}")
            
            # Check row counts
            logger.info(f"\n📈 Row counts:")
            for table in tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) as cnt FROM `{table[0]}`")
                    count = cursor.fetchone()[0]
                    if count > 0:
                        logger.info(f"   └─ {table[0]}: {count} rows")
                except:
                    pass
            
            cursor.close()
            conn.close()
            
            logger.info(f"\n✅ Verification completed successfully!")
            return True
            
        except Error as e:
            logger.error(f"❌ Verification failed: {e}")
            return False
    
    def run(self):
        """Run complete database setup"""
        logger.info("=" * 60)
        logger.info("🚀 URL Security - Database Setup")
        logger.info("=" * 60)
        
        try:
            # Step 1: Create database
            logger.info("\n📝 Step 1: Creating database...")
            if not self.create_database():
                return False
            
            # Step 2: Run migrations
            logger.info("\n📝 Step 2: Running migrations...")
            if not self.run_migrations():
                return False
            
            # Step 3: Verify setup
            logger.info("\n📝 Step 3: Verifying setup...")
            if not self.verify_setup():
                return False
            
            logger.info("\n" + "=" * 60)
            logger.info("✅ Database setup completed successfully!")
            logger.info("=" * 60)
            return True
            
        except Exception as e:
            logger.error(f"\n❌ Setup failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False

if __name__ == "__main__":
    setup = DatabaseSetup()
    try:
        success = setup.run()
        sys.exit(0 if success else 1)
    except Exception as e:
        logger.error(f"Setup failed with error: {e}")
        sys.exit(1)