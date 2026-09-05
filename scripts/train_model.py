#!/usr/bin/env python3
"""
Model Training Script
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import pickle
import numpy as np
from datetime import datetime
from loguru import logger
from sklearn.preprocessing import StandardScaler

from src.ml_pipeline.preprocessing import DataPreprocessor
from src.ml_pipeline.feature_selection import FeatureSelector
from src.ml_pipeline.model_training import ModelTrainer
from src.ml_pipeline.model_evaluation import ModelEvaluator

logger.add("logs/training.log", rotation="1 MB", level="INFO")

def main():
    logger.info("=" * 60)
    logger.info("WEEK 3: Machine Learning Pipeline")
    logger.info("=" * 60)
    
    # STEP 1: Data Preparation
    logger.info("\nSTEP 1: Data Preparation")
    preprocessor = DataPreprocessor()
    X_train, X_test, y_train, y_test = preprocessor.prepare_data(test_size=0.2)
    
    if X_train is None:
        logger.error("Data preparation failed")
        return None
    
    all_feature_names = preprocessor.get_feature_names()
    logger.info(f"Features available: {len(all_feature_names)}")
    
    # STEP 2: Feature Selection
    logger.info("\nSTEP 2: Feature Selection")
    selector = FeatureSelector()
    X_train_selected, selected_features = selector.run_feature_selection(
        X_train, y_train, all_feature_names, method='rf', k=30
    )
    
    test_indices = [all_feature_names.index(f) for f in selected_features if f in all_feature_names]
    X_test_selected = X_test[:, test_indices]
    
    logger.info(f"Selected {len(selected_features)} features")
    selector.save_feature_importance()
    
    # STEP 3: Train Models
    logger.info("\nSTEP 3: Model Training")
    trainer = ModelTrainer()
    models = trainer.train_all_models(X_train_selected, y_train, X_test_selected, y_test)
    
    # STEP 4: Evaluate Models
    logger.info("\nSTEP 4: Model Evaluation")
    evaluator = ModelEvaluator()
    results = evaluator.evaluate_all(models, X_test_selected, y_test)
    
    try:
        evaluator.plot_confusion_matrices()
        evaluator.plot_roc_curves()
    except Exception as e:
        logger.warning(f"Plots failed: {e}")
    
    evaluator.save_results()
    
    # STEP 5: Save Everything
    logger.info("\nSTEP 5: Saving Models")
    version = datetime.now().strftime("%Y%m%d_%H%M%S")
    model_dir = trainer.save_models(version)
    
    features_info = {
        'selected_features': selected_features,
        'all_features': all_feature_names,
        'n_selected': len(selected_features),
        'n_total': len(all_feature_names),
        'version': version,
        'timestamp': datetime.now().isoformat()
    }
    
    features_path = os.path.join(model_dir, 'selected_features.json')
    with open(features_path, 'w') as f:
        json.dump(features_info, f, indent=2)
    logger.info(f"Features saved: {features_path}")
    
    selected_scaler = StandardScaler()
    selected_scaler.fit(X_train_selected)
    
    scaler_path = os.path.join(model_dir, 'scaler.pkl')
    with open(scaler_path, 'wb') as f:
        pickle.dump(selected_scaler, f)
    logger.info(f"Scaler saved: {scaler_path}")
    
    # STEP 6: Test Predictions
    logger.info("\nSTEP 6: Test Predictions")
    
    if results:
        # Use random_forest for prediction test
        rf_path = os.path.join(model_dir, "random_forest.pkl")
        if not os.path.exists(rf_path):
            best_name = max(results.items(), key=lambda x: x[1]['metrics']['f1_score'])[0]
            rf_path = os.path.join(model_dir, f"{best_name}.pkl")
        
        if os.path.exists(rf_path):
            from src.ml_pipeline.prediction import URLPredictor
            predictor = URLPredictor(model_path=rf_path)
            
            test_urls = [
                ("https://www.google.com", "benign"),
                ("https://www.github.com", "benign"),
                ("http://suspicious-login.xyz/verify/account.php", "malicious"),
                ("http://paypal-secure.verify-account.ml/login", "malicious"),
            ]
            
            correct = 0
            for url, expected in test_urls:
                result = predictor.predict_url(url, save_to_db=False)
                ok = "✅" if result['prediction'] == expected else "❌"
                if result['prediction'] == expected:
                    correct += 1
                logger.info(f"  {ok} {url[:50]:<50} -> {result['prediction']}")
            
            logger.info(f"  Test accuracy: {correct}/{len(test_urls)}")
    
    logger.info("\n" + "=" * 60)
    logger.info("Training Complete!")
    logger.info(f"Models: {model_dir}")
    logger.info(f"Features: {len(selected_features)}")
    if results:
        best = max(results.items(), key=lambda x: x[1]['metrics']['f1_score'])
        logger.info(f"Best: {best[0]} (F1: {best[1]['metrics']['f1_score']:.4f})")
    logger.info("=" * 60)
    
    return model_dir

if __name__ == "__main__":
    main()