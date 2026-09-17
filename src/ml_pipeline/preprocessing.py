"""
Data Preprocessing Module - With Domain-Aware Splitting
Fixes data leakage by ensuring all URLs from a domain stay in one split.
"""

import json
import numpy as np
import pandas as pd
from loguru import logger
from urllib.parse import urlparse
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler, LabelEncoder
from database.crud_operations import CRUDOperations
from database.connection import db_manager


class DataPreprocessor:
    """Load and preprocess data from MySQL with domain-aware splitting"""

    def __init__(self):
        self.crud = CRUDOperations()
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns = None

    # ============================================
    # HELPERS
    # ============================================

    @staticmethod
    def extract_domain(url):
        """Extract base domain from URL"""
        try:
            parsed = urlparse(url if url.startswith('http') else 'http://' + url)
            domain = parsed.netloc.lower()
            # Strip www.
            if domain.startswith('www.'):
                domain = domain[4:]
            # Strip port
            domain = domain.split(':')[0]
            return domain
        except:
            return "unknown"

    # ============================================
    # DATA LOADING
    # ============================================

    def load_data_from_mysql(self, limit=1000):
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
        domains = []

        for row in data:
            try:
                is_malicious = row['is_malicious']
                if is_malicious is None:
                    continue

                labels.append(1 if is_malicious else 0)

                # Get domain (use database value, fallback to parse)
                domain = row.get('domain') or self.extract_domain(row['full_url'])
                if domain.startswith('www.'):
                    domain = domain[4:]
                domains.append(domain.lower())

                feature_vector = row.get('feature_vector')
                if feature_vector:
                    features = json.loads(feature_vector) if isinstance(feature_vector, str) else feature_vector
                else:
                    features = {}

                features['url_id'] = row['url_id']
                records.append(features)

            except Exception as e:
                logger.debug(f"Failed to parse record {row.get('url_id')}: {e}")
                continue

        df = pd.DataFrame(records)
        logger.info(f"Parsed {len(df)} records with {len(df.columns)} features")
        return df, np.array(labels), np.array(domains)

    def clean_data(self, df, labels):
        """Clean data: handle missing values, remove constant columns"""
        logger.info("Cleaning data...")
        exclude_cols = ['url_id']
        feature_cols = [col for col in df.columns if col not in exclude_cols]
        X = df[feature_cols].copy()

        X = X.fillna(0)
        X = X.replace([np.inf, -np.inf], 0)

        constant_cols = [col for col in X.columns if X[col].nunique() <= 1]
        if constant_cols:
            logger.info(f"Removing {len(constant_cols)} constant columns")
            X = X.drop(columns=constant_cols)

        for col in X.columns:
            X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)

        self.feature_columns = X.columns.tolist()
        logger.info(f"Cleaned data: {X.shape[0]} samples, {X.shape[1]} features")
        logger.info(f"Class distribution - Malicious: {labels.sum()}, Benign: {len(labels) - labels.sum()}")
        return X, labels

    def normalize_features(self, X_train, X_test):
        """Normalize features"""
        logger.info("Normalizing features...")
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        return X_train_scaled, X_test_scaled

    def balance_classes(self, X, y):
        """Skip SMOTE - use class_weight in models instead"""
        logger.info("Using class_weight instead of SMOTE")
        unique, counts = np.unique(y, return_counts=True)
        logger.info(f"Class distribution: {dict(zip(unique, counts))}")
        return X, y

    # ============================================
    # MAIN PIPELINE WITH DOMAIN-AWARE SPLIT
    # ============================================

    def prepare_data(self, test_size=0.2, random_state=42):
        """
        Complete data preparation pipeline with DOMAIN-AWARE splitting.

        Uses GroupShuffleSplit to ensure all URLs from a given domain
        appear in exactly one of (train, test). This prevents the model
        from memorizing domain-level patterns and gives a realistic
        evaluation of generalization.
        """
        logger.info("=" * 60)
        logger.info("Starting Data Preparation (Domain-Aware Split)")
        logger.info("=" * 60)

        # Load
        data = self.load_data_from_mysql()
        if len(data) < 10:
            logger.error(f"Insufficient data: {len(data)} records")
            return None, None, None, None

        # Parse
        df, labels, domains = self.parse_features(data)
        if len(df) < 10:
            logger.error("Insufficient parsed records")
            return None, None, None, None

        # Clean
        X, y = self.clean_data(df, labels)

        # Check: how many unique domains?
        unique_domains = len(set(domains))
        logger.info(f"Unique domains in dataset: {unique_domains}")

        if unique_domains < 5:
            logger.warning(
                f"Only {unique_domains} unique domains — GroupShuffleSplit may fail. "
                "Falling back to random split."
            )
            from sklearn.model_selection import train_test_split
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=random_state, stratify=y
            )
        else:
            # ============================================
            # DOMAIN-AWARE SPLIT (Fixes Data Leakage)
            # ============================================
            logger.info("Using GroupShuffleSplit by domain...")
            splitter = GroupShuffleSplit(
                n_splits=1,
                test_size=test_size,
                random_state=random_state
            )

            train_idx, test_idx = next(
                splitter.split(X, y, groups=domains)
            )

            X_train = X.iloc[train_idx]
            X_test = X.iloc[test_idx]
            y_train = y[train_idx]
            y_test = y[test_idx]

            # Verify no domain overlap
            train_domains = set(domains[train_idx])
            test_domains = set(domains[test_idx])
            overlap = train_domains & test_domains

            if overlap:
                logger.warning(f"⚠️ Domain overlap detected: {len(overlap)} domains")
            else:
                logger.info("✅ No domain overlap between train/test sets")
                logger.info(f"   Train domains: {len(train_domains)} | Test domains: {len(test_domains)}")

        # Shape info
        logger.info(f"Train set: {len(X_train)} samples")
        logger.info(f"Test set: {len(X_test)} samples")
        logger.info(f"Train class split: Malicious={int(y_train.sum())}, Benign={int(len(y_train) - y_train.sum())}")
        logger.info(f"Test class split: Malicious={int(y_test.sum())}, Benign={int(len(y_test) - y_test.sum())}")

        # Normalize
        X_train_scaled, X_test_scaled = self.normalize_features(X_train, X_test)

        # Balance (no-op if disabled)
        X_train_balanced, y_train_balanced = self.balance_classes(X_train_scaled, y_train)

        logger.info("Data preparation complete!")
        return X_train_balanced, X_test_scaled, y_train_balanced, y_test

    def get_feature_names(self):
        return self.feature_columns