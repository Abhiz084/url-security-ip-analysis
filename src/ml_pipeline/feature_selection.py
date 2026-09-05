"""
Feature Selection Module
Identifies most important features for URL threat detection
"""

import numpy as np
import pandas as pd
from loguru import logger
from sklearn.feature_selection import (
    SelectKBest, f_classif, mutual_info_classif,
    RFE, SelectFromModel
)
from sklearn.ensemble import RandomForestClassifier
import matplotlib.pyplot as plt
import json

class FeatureSelector:
    """Select most relevant features for model training"""
    
    def __init__(self):
        self.selected_features = None
        self.feature_importance = {}
        
    def select_k_best(self, X, y, feature_names, k=30):
        """Select K best features using ANOVA F-value"""
        logger.info(f"Selecting top {k} features using ANOVA F-test...")
        
        selector = SelectKBest(score_func=f_classif, k=min(k, X.shape[1]))
        selector.fit(X, y)
        
        # Get scores
        scores = selector.scores_
        feature_scores = list(zip(feature_names, scores))
        feature_scores.sort(key=lambda x: x[1], reverse=True)
        
        # Store top features
        selected_indices = selector.get_support(indices=True)
        self.selected_features = [feature_names[i] for i in selected_indices]
        
        logger.info(f"Selected {len(self.selected_features)} features")
        
        return selector.transform(X), self.selected_features
    
    def mutual_information_selection(self, X, y, feature_names, k=30):
        """Select features using mutual information"""
        logger.info(f"Selecting top {k} features using Mutual Information...")
        
        mi_scores = mutual_info_classif(X, y, random_state=42)
        feature_scores = list(zip(feature_names, mi_scores))
        feature_scores.sort(key=lambda x: x[1], reverse=True)
        
        # Get top k
        top_features = [f[0] for f in feature_scores[:k]]
        indices = [feature_names.index(f) for f in top_features]
        
        self.selected_features = top_features
        self.feature_importance['mutual_info'] = feature_scores
        
        logger.info(f"Top 10 features by Mutual Information:")
        for name, score in feature_scores[:10]:
            logger.info(f"  {name}: {score:.4f}")
        
        return X[:, indices], self.selected_features
    
    def rfe_selection(self, X, y, feature_names, n_features=30):
        """Recursive Feature Elimination"""
        logger.info(f"Selecting {n_features} features using RFE...")
        
        estimator = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        selector = RFE(estimator, n_features_to_select=min(n_features, X.shape[1]), step=5)
        selector.fit(X, y)
        
        selected_indices = selector.get_support(indices=True)
        self.selected_features = [feature_names[i] for i in selected_indices]
        
        logger.info(f"Selected {len(self.selected_features)} features via RFE")
        
        return selector.transform(X), self.selected_features
    
    def random_forest_importance(self, X, y, feature_names, threshold=0.01):
        """Select features based on Random Forest importance"""
        logger.info("Selecting features using Random Forest importance...")
        
        rf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
        rf.fit(X, y)
        
        importances = rf.feature_importances_
        feature_importance = list(zip(feature_names, importances))
        feature_importance.sort(key=lambda x: x[1], reverse=True)
        
        self.feature_importance['random_forest'] = feature_importance
        
        # Select features above threshold
        selected = [(name, imp) for name, imp in feature_importance if imp >= threshold]
        self.selected_features = [s[0] for s in selected]
        
        logger.info(f"Selected {len(self.selected_features)} features (threshold={threshold})")
        logger.info(f"Top 10 features by RF importance:")
        for name, imp in feature_importance[:10]:
            logger.info(f"  {name}: {imp:.4f}")
        
        # Transform data
        selected_indices = [feature_names.index(f) for f in self.selected_features]
        
        return X[:, selected_indices], self.selected_features
    
    def run_feature_selection(self, X, y, feature_names, method='rf', k=30):
        """Run feature selection with specified method"""
        logger.info("=" * 50)
        logger.info(f"Running Feature Selection (method: {method})")
        logger.info("=" * 50)
        
        if method == 'k_best':
            return self.select_k_best(X, y, feature_names, k)
        elif method == 'mutual_info':
            return self.mutual_information_selection(X, y, feature_names, k)
        elif method == 'rfe':
            return self.rfe_selection(X, y, feature_names, k)
        elif method == 'rf':
            return self.random_forest_importance(X, y, feature_names)
        else:
            logger.warning(f"Unknown method: {method}. Using all features.")
            return X, feature_names
    
    def save_feature_importance(self, filepath='models/feature_importance.json'):
        """Save feature importance to file"""
        import os
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        # Convert numpy types to native Python
        importance_dict = {}
        for method, scores in self.feature_importance.items():
            importance_dict[method] = [
                (name, float(score)) for name, score in scores
            ]
        
        with open(filepath, 'w') as f:
            json.dump(importance_dict, f, indent=2)
        
        logger.info(f"Feature importance saved to {filepath}")