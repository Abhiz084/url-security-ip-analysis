"""
Model Training Module
Trains multiple ML models for URL threat detection
"""

import os
import json
import numpy as np
import pickle
from datetime import datetime
from loguru import logger

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier

try:
    from lightgbm import LGBMClassifier
    LIGHTGBM_AVAILABLE = True
except ImportError:
    LIGHTGBM_AVAILABLE = False

try:
    import tensorflow as tf
    from tensorflow.keras import models, layers, callbacks
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

from database.crud_operations import CRUDOperations

class ModelTrainer:
    """Train and save ML models for URL classification"""
    
    def __init__(self):
        self.crud = CRUDOperations()
        self.models = {}
        self.model_metrics = {}
        self.model_dir = 'models/model_versions'
        os.makedirs(self.model_dir, exist_ok=True)
        
    def train_random_forest(self, X_train, y_train, X_test=None, y_test=None):
        """Train Random Forest with class balancing"""
        logger.info("Training Random Forest...")
        
        model = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=10,
            min_samples_leaf=4,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced_subsample'
        )
        
        model.fit(X_train, y_train)
        
        train_score = model.score(X_train, y_train)
        test_score = model.score(X_test, y_test) if X_test is not None else None
        
        if test_score:
            logger.info(f"Random Forest - Train: {train_score:.4f}, Test: {test_score:.4f}")
        else:
            logger.info(f"Random Forest - Train: {train_score:.4f}")
        
        self.models['random_forest'] = model
        return model
    
    def train_xgboost(self, X_train, y_train, X_test=None, y_test=None):
        """Train XGBoost classifier"""
        logger.info("Training XGBoost...")
        
        n_neg = np.sum(y_train == 0)
        n_pos = np.sum(y_train == 1)
        scale_pos_weight = n_neg / n_pos if n_pos > 0 else 1
        
        model = XGBClassifier(
            n_estimators=200,
            max_depth=10,
            learning_rate=0.1,
            scale_pos_weight=scale_pos_weight,
            random_state=42,
            eval_metric='logloss',
            n_jobs=-1
        )
        
        model.fit(X_train, y_train)
        
        train_score = model.score(X_train, y_train)
        test_score = model.score(X_test, y_test) if X_test is not None else None
        
        if test_score:
            logger.info(f"XGBoost - Train: {train_score:.4f}, Test: {test_score:.4f}")
        else:
            logger.info(f"XGBoost - Train: {train_score:.4f}")
        
        self.models['xgboost'] = model
        return model
    
    def train_lightgbm(self, X_train, y_train, X_test=None, y_test=None):
        """Train LightGBM classifier"""
        if not LIGHTGBM_AVAILABLE:
            logger.warning("LightGBM not available. Skipping.")
            return None
        
        logger.info("Training LightGBM...")
        try:
            model = LGBMClassifier(
                n_estimators=200, max_depth=15, learning_rate=0.1,
                random_state=42, n_jobs=-1, class_weight='balanced',
                verbose=-1
            )
            model.fit(X_train, y_train)
            
            train_score = model.score(X_train, y_train)
            test_score = model.score(X_test, y_test) if X_test is not None else None
            
            if test_score:
                logger.info(f"LightGBM - Train: {train_score:.4f}, Test: {test_score:.4f}")
            else:
                logger.info(f"LightGBM - Train: {train_score:.4f}")
            
            self.models['lightgbm'] = model
            return model
        except Exception as e:
            logger.error(f"LightGBM training failed: {e}")
            return None
    
    def train_gradient_boosting(self, X_train, y_train, X_test=None, y_test=None):
        """Train Gradient Boosting classifier"""
        logger.info("Training Gradient Boosting...")
        
        model = GradientBoostingClassifier(
            n_estimators=200, max_depth=8, learning_rate=0.1, random_state=42
        )
        model.fit(X_train, y_train)
        
        train_score = model.score(X_train, y_train)
        test_score = model.score(X_test, y_test) if X_test is not None else None
        
        if test_score:
            logger.info(f"Gradient Boosting - Train: {train_score:.4f}, Test: {test_score:.4f}")
        else:
            logger.info(f"Gradient Boosting - Train: {train_score:.4f}")
        
        self.models['gradient_boosting'] = model
        return model
    
    def train_logistic_regression(self, X_train, y_train, X_test=None, y_test=None):
        """Train Logistic Regression"""
        logger.info("Training Logistic Regression...")
        
        model = LogisticRegression(max_iter=1000, random_state=42, class_weight='balanced')
        model.fit(X_train, y_train)
        
        train_score = model.score(X_train, y_train)
        test_score = model.score(X_test, y_test) if X_test is not None else None
        
        if test_score:
            logger.info(f"Logistic Regression - Train: {train_score:.4f}, Test: {test_score:.4f}")
        else:
            logger.info(f"Logistic Regression - Train: {train_score:.4f}")
        
        self.models['logistic_regression'] = model
        return model
    
    def train_neural_network(self, X_train, y_train, X_test=None, y_test=None):
        """Train Deep Neural Network"""
        if not TF_AVAILABLE:
            logger.warning("TensorFlow not available. Skipping.")
            return None
        
        logger.info("Training Neural Network...")
        try:
            input_dim = X_train.shape[1]
            
            model = models.Sequential([
                layers.Input(shape=(input_dim,)),
                layers.Dense(128, activation='relu'),
                layers.BatchNormalization(),
                layers.Dropout(0.3),
                layers.Dense(64, activation='relu'),
                layers.BatchNormalization(),
                layers.Dropout(0.3),
                layers.Dense(32, activation='relu'),
                layers.Dense(1, activation='sigmoid')
            ])
            
            model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
            
            early_stop = callbacks.EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True, verbose=0)
            reduce_lr = callbacks.ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=5, min_lr=0.0001, verbose=0)
            
            validation_split = 0.2 if X_test is None else None
            validation_data = (X_test, y_test) if X_test is not None else None
            
            model.fit(
                X_train, y_train, epochs=100, batch_size=32,
                validation_split=validation_split, validation_data=validation_data,
                callbacks=[early_stop, reduce_lr], verbose=0
            )
            
            train_score = model.evaluate(X_train, y_train, verbose=0)[1]
            test_score = model.evaluate(X_test, y_test, verbose=0)[1] if X_test is not None else None
            
            if test_score:
                logger.info(f"Neural Network - Train: {train_score:.4f}, Test: {test_score:.4f}")
            else:
                logger.info(f"Neural Network - Train: {train_score:.4f}")
            
            self.models['neural_network'] = model
            return model
        except Exception as e:
            logger.error(f"Neural network training failed: {e}")
            return None
    
    def train_voting_ensemble(self, X_train, y_train, X_test=None, y_test=None):
        """Train Voting Ensemble"""
        logger.info("Training Voting Ensemble...")
        
        estimators = []
        for name, model in self.models.items():
            if name != 'neural_network' and hasattr(model, 'predict_proba'):
                estimators.append((name, model))
        
        if len(estimators) < 2:
            logger.warning(f"Need 2+ models for ensemble, got {len(estimators)}")
            return None
        
        try:
            ensemble = VotingClassifier(estimators=estimators, voting='soft')
            ensemble.fit(X_train, y_train)
            
            train_score = ensemble.score(X_train, y_train)
            test_score = ensemble.score(X_test, y_test) if X_test is not None else None
            
            if test_score:
                logger.info(f"Voting Ensemble - Train: {train_score:.4f}, Test: {test_score:.4f}")
            else:
                logger.info(f"Voting Ensemble - Train: {train_score:.4f}")
            
            self.models['voting_ensemble'] = ensemble
            return ensemble
        except Exception as e:
            logger.error(f"Voting ensemble failed: {e}")
            return None
    
    def train_all_models(self, X_train, y_train, X_test=None, y_test=None):
        """Train all available models"""
        logger.info("=" * 50)
        logger.info("Training All Models")
        logger.info("=" * 50)
        
        models_to_train = [
            ('logistic_regression', self.train_logistic_regression, True),
            ('random_forest', self.train_random_forest, True),
            ('xgboost', self.train_xgboost, True),
            ('gradient_boosting', self.train_gradient_boosting, True),
            ('lightgbm', self.train_lightgbm, False),
            ('neural_network', self.train_neural_network, False),
        ]
        
        for name, train_func, required in models_to_train:
            try:
                result = train_func(X_train, y_train, X_test, y_test)
                if result is None and required:
                    logger.warning(f"Required model {name} failed to train")
            except Exception as e:
                if required:
                    logger.error(f"Failed to train {name}: {e}")
                else:
                    logger.warning(f"Optional model {name} skipped: {e}")
        
        try:
            self.train_voting_ensemble(X_train, y_train, X_test, y_test)
        except Exception as e:
            logger.warning(f"Ensemble skipped: {e}")
        
        logger.info(f"Trained {len(self.models)} models successfully")
        return self.models
    
    def save_models(self, version=None):
        """Save all trained models to disk"""
        if version is None:
            version = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        version_dir = os.path.join(self.model_dir, f"v_{version}")
        os.makedirs(version_dir, exist_ok=True)
        
        for name, model in self.models.items():
            try:
                if name == 'neural_network' and TF_AVAILABLE:
                    model_path = os.path.join(version_dir, f"{name}.keras")
                    model.save(model_path)
                    logger.info(f"Saved: {model_path}")
                elif hasattr(model, 'predict'):
                    model_path = os.path.join(version_dir, f"{name}.pkl")
                    with open(model_path, 'wb') as f:
                        pickle.dump(model, f)
                    logger.info(f"Saved: {model_path}")
            except Exception as e:
                logger.error(f"Failed to save {name}: {e}")
        
        version_info = {
            'version': version,
            'timestamp': datetime.now().isoformat(),
            'models': list(self.models.keys()),
        }
        
        with open(os.path.join(version_dir, 'version_info.json'), 'w') as f:
            json.dump(version_info, f, indent=2, default=str)
        
        logger.info(f"All models saved to {version_dir}")
        return version_dir