"""
train_enhanced.py
=================
Enhanced training script using URL features + HTML features + NLP features.
Trains a Random Forest classifier on comprehensive feature set.
"""

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    precision_score, recall_score, f1_score, roc_auc_score, roc_curve
)
from sklearn.preprocessing import StandardScaler
import pickle
import logging
import json
from features_enhanced import extract_all_features, get_feature_names

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def train_model(csv_file='malicious_phish.csv', sample_size=50000):
    """
    Train the malicious URL detection model.
    
    Args:
        csv_file: Path to the dataset CSV file
        sample_size: Number of samples to use for training
    """
    
    logger.info("=" * 70)
    logger.info("STARTING MODEL TRAINING - ENHANCED VERSION")
    logger.info("=" * 70)
    
    # Load dataset
    logger.info(f"Loading dataset from {csv_file}...")
    try:
        df = pd.read_csv(csv_file)
        logger.info(f"Loaded {len(df)} total samples")
    except FileNotFoundError:
        logger.error(f"Dataset file not found: {csv_file}")
        logger.info("Please download from: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset")
        return False
    
    # Sample dataset
    logger.info(f"Sampling {sample_size} rows...")
    df = df.sample(min(sample_size, len(df)), random_state=42)
    
    # Convert labels to binary
    logger.info("Converting labels to binary format (benign=0, malicious=1)...")
    df['label_bin'] = df['type'].apply(lambda x: 0 if x == 'benign' else 1)
    
    logger.info(f"Label distribution:\n{df['label_bin'].value_counts()}")
    
    # Extract features
    logger.info("Extracting features (this may take 2-3 minutes)...")
    feature_list = []
    
    for idx, url in enumerate(df['url'], 1):
        if idx % 5000 == 0:
            logger.info(f"  Processed {idx}/{len(df)} URLs...")
        
        # Extract only URL features (HTML/text features would require crawling each URL)
        features = extract_all_features(url, html_content=None, text_content=None)
        feature_list.append(features)
    
    X = pd.DataFrame(feature_list)
    y = df['label_bin']
    
    feature_names = get_feature_names()
    logger.info(f"Total features extracted: {len(feature_names)}")
    logger.info(f"Feature names: {feature_names}")
    
    # Split data
    logger.info("Splitting data into train/test (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    logger.info(f"Training samples: {len(X_train)}")
    logger.info(f"Testing samples: {len(X_test)}")
    
    # Train model
    logger.info("Training Random Forest classifier...")
    logger.info("  (100 trees, this will take ~30-60 seconds)")
    
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    )
    model.fit(X_train, y_train)
    
    # Evaluate model
    logger.info("\n" + "=" * 70)
    logger.info("MODEL EVALUATION RESULTS")
    logger.info("=" * 70)
    
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    logger.info(f"\nAccuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    logger.info(f"Precision: {precision:.4f}")
    logger.info(f"Recall:    {recall:.4f}")
    logger.info(f"F1-Score:  {f1:.4f}")
    
    try:
        auc = roc_auc_score(y_test, y_pred_proba)
        logger.info(f"ROC-AUC:   {auc:.4f}")
    except Exception as e:
        logger.warning(f"Could not calculate ROC-AUC: {e}")
    
    logger.info("\n" + "-" * 70)
    logger.info("DETAILED CLASSIFICATION REPORT")
    logger.info("-" * 70)
    logger.info("\n" + classification_report(y_test, y_pred, target_names=['SAFE', 'MALICIOUS']))
    
    logger.info("\nCONFUSION MATRIX")
    logger.info("-" * 70)
    cm = confusion_matrix(y_test, y_pred)
    logger.info(f"True Negatives:  {cm[0][0]}")
    logger.info(f"False Positives: {cm[0][1]}")
    logger.info(f"False Negatives: {cm[1][0]}")
    logger.info(f"True Positives:  {cm[1][1]}")
    
    # Feature importance
    logger.info("\n" + "=" * 70)
    logger.info("TOP 15 MOST IMPORTANT FEATURES")
    logger.info("=" * 70)
    
    feature_importance = pd.DataFrame({
        'feature': feature_names,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    for idx, row in feature_importance.head(15).iterrows():
        logger.info(f"  {row['feature']:.<40} {row['importance']:.4f}")
    
    # Save model
    logger.info("\n" + "=" * 70)
    logger.info("SAVING MODEL AND METADATA")
    logger.info("=" * 70)
    
    with open('url_model_enhanced.pkl', 'wb') as f:
        pickle.dump(model, f)
    logger.info("Model saved to: url_model_enhanced.pkl")
    
    # Save feature names
    with open('feature_names.json', 'w') as f:
        json.dump(feature_names, f, indent=2)
    logger.info("Feature names saved to: feature_names.json")
    
    # Save evaluation metrics
    metrics = {
        'accuracy': float(accuracy),
        'precision': float(precision),
        'recall': float(recall),
        'f1_score': float(f1),
        'training_samples': len(X_train),
        'testing_samples': len(X_test),
        'total_features': len(feature_names),
        'confusion_matrix': cm.tolist(),
        'feature_importance': feature_importance.to_dict('records')
    }
    
    with open('model_metrics.json', 'w') as f:
        json.dump(metrics, f, indent=2)
    logger.info("Evaluation metrics saved to: model_metrics.json")
    
    logger.info("\n" + "=" * 70)
    logger.info("TRAINING COMPLETED SUCCESSFULLY!")
    logger.info("=" * 70)
    
    return True


if __name__ == "__main__":
    try:
        success = train_model()
        if not success:
            exit(1)
    except Exception as e:
        logger.error(f"Error during training: {e}")
        import traceback
        # Log traceback to logger but don't print to stdout
        logger.debug(traceback.format_exc())
        exit(1)
