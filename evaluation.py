"""
evaluation.py
=============
Comprehensive model evaluation and performance analysis.
Generates detailed evaluation metrics and visualizations.
"""

import pickle
import json
import pandas as pd
import logging
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score,
    precision_recall_curve, roc_curve
)
from features_enhanced import extract_all_features, get_feature_names

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ModelEvaluator:
    """Comprehensive model evaluation and analysis."""
    
    def __init__(self, model_path='url_model_enhanced.pkl', metrics_path='model_metrics.json'):
        """Load model and existing metrics."""
        try:
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            logger.info(f"Model loaded from {model_path}")
        except FileNotFoundError:
            logger.error(f"Model not found: {model_path}")
            self.model = None
        
        try:
            with open(metrics_path, 'r') as f:
                self.metrics = json.load(f)
            logger.info(f"Metrics loaded from {metrics_path}")
        except FileNotFoundError:
            logger.warning(f"Metrics file not found: {metrics_path}")
            self.metrics = {}
    
    def generate_evaluation_report(self) -> str:
        """Generate comprehensive evaluation report."""
        report = []
        report.append("\n" + "=" * 80)
        report.append("COMPREHENSIVE MODEL EVALUATION REPORT")
        report.append("=" * 80)
        
        if not self.metrics:
            report.append("\nNo metrics available. Please train the model first.")
            return "\n".join(report)
        
        # Performance metrics
        report.append("\n1. OVERALL PERFORMANCE METRICS")
        report.append("-" * 80)
        report.append(f"Accuracy:  {self.metrics['accuracy']:.4f} ({self.metrics['accuracy']*100:.2f}%)")
        report.append(f"Precision: {self.metrics['precision']:.4f}")
        report.append(f"Recall:    {self.metrics['recall']:.4f}")
        report.append(f"F1-Score:  {self.metrics['f1_score']:.4f}")
        
        # Dataset information
        report.append("\n2. DATASET INFORMATION")
        report.append("-" * 80)
        report.append(f"Training samples:  {self.metrics['training_samples']}")
        report.append(f"Testing samples:   {self.metrics['testing_samples']}")
        report.append(f"Total features:    {self.metrics['total_features']}")
        
        # Confusion matrix
        report.append("\n3. CONFUSION MATRIX ANALYSIS")
        report.append("-" * 80)
        cm = self.metrics['confusion_matrix']
        tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
        
        report.append(f"True Negatives:  {tn:>6} (Correct safe predictions)")
        report.append(f"False Positives: {fp:>6} (Safe URLs incorrectly flagged)")
        report.append(f"False Negatives: {fn:>6} (Missed malicious URLs)")
        report.append(f"True Positives:  {tp:>6} (Correct malicious predictions)")
        
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
        sensitivity = tp / (tp + fn) if (tp + fn) > 0 else 0
        
        report.append(f"\nSensitivity (Recall):  {sensitivity:.4f}")
        report.append(f"Specificity:           {specificity:.4f}")
        
        # Interpretation
        report.append("\n4. MODEL INTERPRETATION")
        report.append("-" * 80)
        
        if self.metrics['f1_score'] >= 0.9:
            report.append("[EXCELLENT] Excellent performance on both safe and malicious URLs")
        elif self.metrics['f1_score'] >= 0.8:
            report.append("[GOOD] Good performance - suitable for production use")
        elif self.metrics['f1_score'] >= 0.7:
            report.append("[ACCEPTABLE] Acceptable performance - monitor for improvements")
        else:
            report.append("[NEEDS IMPROVEMENT] Model performance needs improvement")
        
        # False positive analysis
        if fp > 0:
            fp_rate = fp / (fp + tn) * 100
            report.append(f"\nFalse Positive Rate: {fp_rate:.2f}%")
            report.append("  (Safe URLs incorrectly flagged as malicious)")
        
        # False negative analysis
        if fn > 0:
            fn_rate = fn / (fn + tp) * 100
            report.append(f"False Negative Rate: {fn_rate:.2f}%")
            report.append("  (Malicious URLs not detected)")
        
        # Feature importance
        if 'feature_importance' in self.metrics:
            report.append("\n5. TOP 15 MOST IMPORTANT FEATURES")
            report.append("-" * 80)
            
            features = self.metrics['feature_importance']
            # Sort by importance descending
            features_sorted = sorted(features, key=lambda x: x['importance'], reverse=True)
            
            for idx, item in enumerate(features_sorted[:15], 1):
                report.append(f"{idx:2d}. {item['feature']:.<40} {item['importance']:.6f}")
        
        # Recommendations
        report.append("\n6. RECOMMENDATIONS")
        report.append("-" * 80)
        
        recommendations = []
        
        if fn > 0 and fn > (tp * 0.1):
            recommendations.append("- High false negative rate - consider adjusting decision threshold")
        
        if fp > 0 and fp > (tn * 0.1):
            recommendations.append("- High false positive rate - may need more balanced training")
        
        if self.metrics['accuracy'] < 0.9:
            recommendations.append("- Collect more training data to improve accuracy")
        
        if not recommendations:
            recommendations.append("- Model performs well - continue monitoring in production")
            recommendations.append("- Retrain periodically with new data")
        
        for rec in recommendations:
            report.append(rec)
        
        report.append("\n" + "=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        return "\n".join(report)


def main():
    """Generate evaluation report."""
    evaluator = ModelEvaluator()
    report = evaluator.generate_evaluation_report()
    print(report)
    
    # Save report with UTF-8 encoding to avoid Unicode errors
    with open('evaluation_report.txt', 'w', encoding='utf-8') as f:
        f.write(report)
    
    logger.info("\nEvaluation report saved to evaluation_report.txt")


if __name__ == "__main__":
    try:
        main()
        logger.info("\nEvaluation completed successfully")
    except Exception as e:
        logger.error(f"Error during evaluation: {e}")
        import traceback
        # Log traceback to logger but don't print to stdout
        logger.debug(traceback.format_exc())
