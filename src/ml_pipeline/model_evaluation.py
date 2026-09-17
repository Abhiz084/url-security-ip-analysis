"""
Model Evaluation Module - With Comprehensive Metrics
"""

import numpy as np
import pandas as pd
from loguru import logger
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)
import matplotlib.pyplot as plt
import seaborn as sns
import json
import os


class ModelEvaluator:
    """Evaluate ML model performance with realistic metrics"""

    def __init__(self):
        self.results = {}
        self.comparison_table = None

    def evaluate_model(self, model, X_test, y_test, model_name):
        """Evaluate a single model with full metrics"""
        logger.info(f"Evaluating {model_name}...")

        try:
            # Predictions
            if hasattr(model, 'predict_proba'):
                y_pred = model.predict(X_test)
                y_pred_proba = model.predict_proba(X_test)[:, 1]
            else:
                y_pred_proba = model.predict(X_test, verbose=0).flatten()
                y_pred = (y_pred_proba > 0.5).astype(int)

            # Metrics (using zero_division=0 to handle edge cases)
            metrics = {
                'accuracy': float(accuracy_score(y_test, y_pred)),
                'precision': float(precision_score(y_test, y_pred, zero_division=0)),
                'recall': float(recall_score(y_test, y_pred, zero_division=0)),
                'f1_score': float(f1_score(y_test, y_pred, zero_division=0)),
                'roc_auc': float(roc_auc_score(y_test, y_pred_proba)) if len(np.unique(y_test)) > 1 else 0.5
            }

            cm = confusion_matrix(y_test, y_pred)

            # Print to log
            logger.info(f"  Accuracy:  {metrics['accuracy']:.4f}")
            logger.info(f"  Precision: {metrics['precision']:.4f}")
            logger.info(f"  Recall:    {metrics['recall']:.4f}")
            logger.info(f"  F1 Score:  {metrics['f1_score']:.4f}")
            logger.info(f"  ROC AUC:   {metrics['roc_auc']:.4f}")
            logger.info(f"  Confusion Matrix:")
            logger.info(f"    TN={cm[0][0]}  FP={cm[0][1] if cm.shape[1] > 1 else 0}")
            logger.info(f"    FN={cm[1][0] if cm.shape[0] > 1 else 0}  TP={cm[1][1] if cm.shape[0] > 1 and cm.shape[1] > 1 else 0}")

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
            import traceback
            logger.debug(traceback.format_exc())
            return None

    def evaluate_all(self, models, X_test, y_test):
        """Evaluate all trained models"""
        logger.info("=" * 60)
        logger.info("Model Evaluation (Domain-Aware Split)")
        logger.info("=" * 60)

        for name, model in models.items():
            try:
                self.evaluate_model(model, X_test, y_test, name)
            except Exception as e:
                logger.error(f"Failed to evaluate {name}: {e}")

        # Build comparison table
        if self.results:
            rows = []
            for name, result in self.results.items():
                m = result['metrics']
                rows.append({
                    'Model': name,
                    'Accuracy': m['accuracy'],
                    'Precision': m['precision'],
                    'Recall': m['recall'],
                    'F1 Score': m['f1_score'],
                    'ROC AUC': m['roc_auc']
                })

            self.comparison_table = pd.DataFrame(rows).sort_values('F1 Score', ascending=False)

            # Print table
            logger.info("")
            logger.info("=" * 75)
            logger.info("MODEL COMPARISON TABLE")
            logger.info("=" * 75)
            logger.info(f"\n{self.comparison_table.to_string(index=False)}")
            logger.info("=" * 75)

            best = self.comparison_table.iloc[0]
            logger.info(f"\n🏆 Best Model: {best['Model']}")
            logger.info(f"   F1 Score:  {best['F1 Score']:.4f}")
            logger.info(f"   Precision: {best['Precision']:.4f}")
            logger.info(f"   Recall:    {best['Recall']:.4f}")

        return self.results

    def plot_confusion_matrices(self, save_path='models/confusion_matrices.png'):
        """Plot confusion matrices"""
        n = len(self.results)
        if n == 0:
            return

        cols = min(3, n)
        rows = (n + cols - 1) // cols
        fig, axes = plt.subplots(rows, cols, figsize=(5 * cols, 4 * rows))

        if rows == 1 and cols == 1:
            axes = [axes]
        else:
            axes = axes.flatten() if hasattr(axes, 'flatten') else [axes]

        for ax, (name, result) in zip(axes, self.results.items()):
            cm = np.array(result['confusion_matrix'])
            sns.heatmap(cm, annot=True, fmt='d', ax=ax, cmap='Blues',
                        xticklabels=['Benign', 'Malicious'],
                        yticklabels=['Benign', 'Malicious'])
            ax.set_title(f'{name}\nF1: {result["metrics"]["f1_score"]:.3f}')
            ax.set_xlabel('Predicted')
            ax.set_ylabel('Actual')

        for ax in axes[n:]:
            ax.set_visible(False)

        plt.tight_layout()
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        plt.savefig(save_path, dpi=100, bbox_inches='tight')
        plt.close()
        logger.info(f"Confusion matrices saved: {save_path}")

    def plot_roc_curves(self, save_path='models/roc_curves.png'):
        """Plot ROC curves"""
        from sklearn.metrics import roc_curve
        plt.figure(figsize=(10, 8))

        for name, result in self.results.items():
            fpr, tpr, _ = roc_curve(result['y_test'], result['y_pred_proba'])
            auc = result['metrics']['roc_auc']
            plt.plot(fpr, tpr, linewidth=2, label=f'{name} (AUC={auc:.3f})')

        plt.plot([0, 1], [0, 1], 'k--', linewidth=1, label='Random')
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('ROC Curves - URL Threat Detection')
        plt.legend(loc='lower right')
        plt.grid(True, alpha=0.3)

        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        plt.savefig(save_path, dpi=100, bbox_inches='tight')
        plt.close()
        logger.info(f"ROC curves saved: {save_path}")

    def save_results(self, filepath='models/evaluation_results.json'):
        """Save results including comparison table"""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        output = {
            'comparison_table': self.comparison_table.to_dict(orient='records') if self.comparison_table is not None else [],
            'detailed_results': {
                name: {
                    'metrics': r['metrics'],
                    'confusion_matrix': r['confusion_matrix']
                }
                for name, r in self.results.items()
            }
        }

        with open(filepath, 'w') as f:
            json.dump(output, f, indent=2)

        logger.info(f"Results saved: {filepath}")