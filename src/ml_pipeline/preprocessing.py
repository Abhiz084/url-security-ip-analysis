"""
Data Preprocessing Module
Handles data loading from MySQL, cleaning, normalization, and train/test split
"""

import json
import numpy as np
import pandas as pd
from loguru import logger
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from database.crud_operations import CRUDOperations
from database.connection import db_manager

class DataPreprocessor:
    """Load and preprocess data from MySQL for ML training"""
    
    def __init__(self):
        self.crud = CRUDOperations()
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns = None
        
    def load_data_from_mysql(self, limit=500):
        """Load URLs and features from MySQL database"""
        logger.info("Loading data from MySQL...")
        
        query = """
        SELECT 
            u.url_id,
            u.full_url,
            u.domain,
            u.is_malicious,
            fc.feature_vector
        FROM urls u
        LEFT JOIN feature_cache fc ON u.url_id = fc.url_id
        WHERE u.is_malicious IS NOT NULL
        ORDER BY u.submission_date DESC
        LIMIT %s
        """
        
        results = db_manager.execute_query(query, (limit,))
        logger.info(f"Loaded {len(results)} records from database")
        
        return results
    
    def parse_features(self, data):
        """Parse JSON feature vectors into DataFrame"""
        records = []
        labels = []
        
        for row in data:
            try:
                is_malicious = row['is_malicious']
                if is_malicious is None:
                    continue
                    
                labels.append(1 if is_malicious else 0)
                
                feature_vector = row.get('feature_vector')
                if feature_vector:
                    if isinstance(feature_vector, str):
                        features = json.loads(feature_vector)
                    else:
                        features = feature_vector
                else:
                    features = {}
                
                features['url_id'] = row['url_id']
                records.append(features)
                
            except Exception as e:
                logger.debug(f"Failed to parse record {row.get('url_id')}: {e}")
                continue
        
        df = pd.DataFrame(records)
        logger.info(f"Parsed {len(df)} records with {len(df.columns)} features")
        
        return df, np.array(labels)
    
    def clean_data(self, df, labels):
        """Clean data: handle missing values, remove constant columns"""
        logger.info("Cleaning data...")
        
        exclude_cols = ['url_id']
        feature_cols = [col for col in df.columns if col not in exclude_cols]
        X = df[feature_cols].copy()
        
        # Handle missing values
        X = X.fillna(0)
        
        # Handle infinite values
        X = X.replace([np.inf, -np.inf], 0)
        
        # Remove constant columns
        constant_cols = [col for col in X.columns if X[col].nunique() <= 1]
        if constant_cols:
            logger.info(f"Removing {len(constant_cols)} constant columns")
            X = X.drop(columns=constant_cols)
        
        # Ensure all columns are numeric
        for col in X.columns:
            X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)
        
        self.feature_columns = X.columns.tolist()
        
        logger.info(f"Cleaned data: {X.shape[0]} samples, {X.shape[1]} features")
        logger.info(f"Class distribution - Malicious: {labels.sum()}, Benign: {len(labels) - labels.sum()}")
        
        return X, labels
    
    def normalize_features(self, X_train, X_test):
        """Normalize features using StandardScaler"""
        logger.info("Normalizing features...")
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        return X_train_scaled, X_test_scaled
    
    def balance_classes(self, X, y):
        """Skip SMOTE - use class_weight in models instead"""
        logger.info("Skipping SMOTE - using class_weight='balanced' in models")
        unique, counts = np.unique(y, return_counts=True)
        logger.info(f"Class distribution: {dict(zip(unique, counts))}")
        return X, y
    
    def prepare_data(self, test_size=0.2, random_state=42):
        """Complete data preparation pipeline"""
        logger.info("=" * 50)
        logger.info("Starting Data Preparation")
        logger.info("=" * 50)
        
        data = self.load_data_from_mysql()
        
        if len(data) < 10:
            logger.error(f"Insufficient data: only {len(data)} records")
            return None, None, None, None
        
        df, labels = self.parse_features(data)
        
        if len(df) < 10:
            logger.error("Insufficient parsed records")
            return None, None, None, None
        
        X, y = self.clean_data(df, labels)
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        logger.info(f"Train set: {X_train.shape[0]} samples")
        logger.info(f"Test set: {X_test.shape[0]} samples")
        
        X_train_scaled, X_test_scaled = self.normalize_features(X_train, X_test)
        X_train_balanced, y_train_balanced = self.balance_classes(X_train_scaled, y_train)
        
        logger.info("Data preparation complete!")
        
        return X_train_balanced, X_test_scaled, y_train_balanced, y_test
    
    def get_feature_names(self):
        """Return list of feature names"""
        return self.feature_columns