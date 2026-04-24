import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix
import joblib
import os
from .feature_extractor import FeatureExtractor

class ModelTrainer:
    """
    Trains and evaluates machine learning models for classifying attack types.
    Supports Random Forest, Logistic Regression, and Naive Bayes models.
    """

    def __init__(self, model_type: str = 'random_forest'):
        self.model_type = model_type
        if model_type == 'random_forest':
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        elif model_type == 'logistic_regression':
            self.model = LogisticRegression(max_iter=1000, random_state=42)
        elif model_type == 'naive_bayes':
            self.model = GaussianNB()
        else:
            raise ValueError("Unsupported model type. Choose 'random_forest', 'logistic_regression', or 'naive_bayes'.")
        
        self.feature_extractor = FeatureExtractor()

    def train(self, df: pd.DataFrame, target_column: str = 'attack_type', save_path: str = 'model.pkl'):
        """
        Train the selected model on the provided dataset.
        Assumes 'df' has been preprocessed to have text features and an 'attack_type' target.
        """
        if df.empty or target_column not in df.columns:
            raise ValueError(f"Dataset is empty or '{target_column}' is missing.")

        print(f"Training {self.model_type} model on {len(df)} samples...")

        # Feature extraction
        X = df[['payload', 'endpoint', 'ip']] if 'ip' in df.columns else df[['payload', 'endpoint']]
        X_features = self.feature_extractor.transform(X)
        y = df[target_column]

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X_features, y, test_size=0.2, random_state=42)

        # Train model
        self.model.fit(X_train, y_train)

        # Evaluate model
        predictions = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, predictions)
        
        # We use weighted metrics since classes might be imbalanced
        precision = precision_score(y_test, predictions, average='weighted', zero_division=0)
        recall = recall_score(y_test, predictions, average='weighted', zero_division=0)
        cm = confusion_matrix(y_test, predictions)

        metrics = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'confusion_matrix': cm.tolist()
        }

        print(f"Metrics: Accuracy={accuracy:.4f}, Precision={precision:.4f}, Recall={recall:.4f}")

        # Save model and extractor together for inference
        pipeline = {
            'extractor': self.feature_extractor,
            'model': self.model
        }
        joblib.dump(pipeline, save_path)
        print(f"Model saved to {save_path}")

        return metrics


