"""
Model Evaluation Module
Evaluates model performance with multiple metrics
"""

import numpy as np
from loguru import logger
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, roc_curve
)
import matplotlib.pyplot as plt
import seaborn as sns
import json
import os

class ModelEvaluator:
    """Evaluate ML model performance"""
    
    def __init__(self):
        self.results = {}
        
    def evaluate_model(self, model, X_test, y_test, model_name):
        """Evaluate a single model"""
        logger.info(f"Evaluating {model_name}...")
        
        try:
            # Get predictions
            if hasattr(model, 'predict_proba'):
                # Sklearn models
                y_pred = model.predict(X_test)
                y_pred_proba = model.predict_proba(X_test)[:, 1]
            elif hasattr(model, 'predict'):
                # Keras/TensorFlow models
                y_pred_proba = model.predict(X_test, verbose=0).flatten()
                y_pred = (y_pred_proba > 0.5).astype(int)
            else:
                logger.warning(f"Model {model_name} has no predict method")
                return None
            
            # Calculate metrics
            metrics = {
                'accuracy': accuracy_score(y_test, y_pred),
                'precision': precision_score(y_test, y_pred, zero_division=0),
                'recall': recall_score(y_test, y_pred, zero_division=0),
                'f1_score': f1_score(y_test, y_pred, zero_division=0),
                'roc_auc': roc_auc_score(y_test, y_pred_proba) if len(np.unique(y_test)) > 1 else 0.5
            }
            
            # Confusion matrix
            cm = confusion_matrix(y_test, y_pred)
            
            logger.info(f"  Accuracy:  {metrics['accuracy']:.4f}")
            logger.info(f"  Precision: {metrics['precision']:.4f}")
            logger.info(f"  Recall:    {metrics['recall']:.4f}")
            logger.info(f"  F1 Score:  {metrics['f1_score']:.4f}")
            logger.info(f"  ROC AUC:   {metrics['roc_auc']:.4f}")
            
            self.results[model_name] = {
                'metrics': metrics,
                'confusion_matrix': cm.tolist(),
                'y_test': y_test.tolist() if isinstance(y_test, np.ndarray) else y_test,
                'y_pred': y_pred.tolist() if isinstance(y_pred, np.ndarray) else y_pred,
                'y_pred_proba': y_pred_proba.tolist() if isinstance(y_pred_proba, np.ndarray) else y_pred_proba
            }
            
            return metrics
            
        except Exception as e:
            logger.error(f"Evaluation failed for {model_name}: {e}")
            return None
    
    def evaluate_all(self, models, X_test, y_test):
        """Evaluate all trained models"""
        logger.info("=" * 50)
        logger.info("Evaluating All Models")
        logger.info("=" * 50)
        
        for name, model in models.items():
            try:
                self.evaluate_model(model, X_test, y_test, name)
            except Exception as e:
                logger.error(f"Failed to evaluate {name}: {e}")
        
        # Find best model
        if self.results:
            best_model = max(self.results.items(), key=lambda x: x[1]['metrics']['f1_score'])
            logger.info(f"\n🏆 Best Model: {best_model[0]} (F1: {best_model[1]['metrics']['f1_score']:.4f})")
        
        return self.results
    
    def plot_confusion_matrices(self, save_path='models/confusion_matrices.png'):
        """Plot confusion matrices for all models"""
        n_models = len(self.results)
        if n_models == 0:
            return
        
        # Calculate grid layout
        cols = min(3, n_models)
        rows = (n_models + cols - 1) // cols
        
        fig, axes = plt.subplots(rows, cols, figsize=(5*cols, 4*rows))
        
        # Flatten axes for easy iteration
        if rows == 1 and cols == 1:
            axes = np.array([axes])
        axes = axes.flatten() if hasattr(axes, 'flatten') else np.array([axes])
        
        for ax, (name, result) in zip(axes, self.results.items()):
            cm = np.array(result['confusion_matrix'])
            sns.heatmap(cm, annot=True, fmt='d', ax=ax, cmap='Blues', 
                       xticklabels=['Benign', 'Malicious'],
                       yticklabels=['Benign', 'Malicious'])
            ax.set_title(f'{name}\nF1: {result["metrics"]["f1_score"]:.4f}')
            ax.set_xlabel('Predicted')
            ax.set_ylabel('Actual')
        
        # Hide unused subplots
        for ax in axes[n_models:]:
            ax.set_visible(False)
        
        plt.tight_layout()
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        plt.savefig(save_path, dpi=100, bbox_inches='tight')
        plt.close()
        logger.info(f"Confusion matrices saved to {save_path}")
    
    def plot_roc_curves(self, save_path='models/roc_curves.png'):
        """Plot ROC curves for all models"""
        plt.figure(figsize=(10, 8))
        
        for name, result in self.results.items():
            y_test = result['y_test']
            y_pred_proba = result['y_pred_proba']
            
            fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
            auc = result['metrics']['roc_auc']
            plt.plot(fpr, tpr, linewidth=2, label=f'{name} (AUC={auc:.4f})')
        
        plt.plot([0, 1], [0, 1], 'k--', linewidth=1, label='Random')
        plt.xlabel('False Positive Rate', fontsize=12)
        plt.ylabel('True Positive Rate', fontsize=12)
        plt.title('ROC Curves - URL Threat Detection Models', fontsize=14)
        plt.legend(loc='lower right', fontsize=10)
        plt.grid(True, alpha=0.3)
        
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        plt.savefig(save_path, dpi=100, bbox_inches='tight')
        plt.close()
        logger.info(f"ROC curves saved to {save_path}")
    
    def save_results(self, filepath='models/evaluation_results.json'):
        """Save evaluation results"""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        # Convert to serializable format
        results_copy = {}
        for name, result in self.results.items():
            results_copy[name] = {
                'metrics': {k: float(v) if isinstance(v, (np.floating, np.integer)) else v 
                           for k, v in result['metrics'].items()},
                'confusion_matrix': result['confusion_matrix']
            }
        
        with open(filepath, 'w') as f:
            json.dump(results_copy, f, indent=2)
        
        logger.info(f"Evaluation results saved to {filepath}")