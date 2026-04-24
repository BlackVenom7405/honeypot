import joblib
import pandas as pd
from typing import Dict, Union, List

class AttackClassifier:
    """
    Loads a trained model pipeline to classify new honeypot logs.
    """

    def __init__(self, model_path: str = 'model.pkl'):
        try:
            self.pipeline = joblib.load(model_path)
            self.feature_extractor = self.pipeline['extractor']
            self.model = self.pipeline['model']
        except FileNotFoundError:
            raise FileNotFoundError(f"Model file {model_path} not found. Train the model first.")

    def classify(self, request_data: Union[Dict, List[Dict], pd.DataFrame]) -> pd.DataFrame:
        """
        Classifies incoming request(s).
        Returns a DataFrame with the original data and the predicted 'attack_type'.
        """
        if isinstance(request_data, dict):
            df = pd.DataFrame([request_data])
        elif isinstance(request_data, list):
            df = pd.DataFrame(request_data)
        elif isinstance(request_data, pd.DataFrame):
            df = request_data.copy()
        else:
            raise TypeError("Unsupported data type for classification.")

        # Ensure necessary columns are present for feature extraction
        for col in ['payload', 'endpoint']:
            if col not in df.columns:
                df[col] = ''

        # Extract features
        X = df[['payload', 'endpoint', 'ip']] if 'ip' in df.columns else df[['payload', 'endpoint']]
        X_features = self.feature_extractor.transform(X)

        # Predict
        predictions = self.model.predict(X_features)
        
        # We can also get probabilities if the user wants an explainable confidence score
        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(X_features)
            confidence = probabilities.max(axis=1)
            df['confidence'] = confidence
            
        df['predicted_attack_type'] = predictions

        return df

    def classify_log(self, ip: str, endpoint: str, payload: str = '', method: str = 'GET') -> Dict:
        """
        Classify a single log entry formatted as standard arguments.
        """
        data = {
            'ip': ip,
            'endpoint': endpoint,
            'payload': payload,
            'method': method
        }
        result_df = self.classify(data)
        return result_df.to_dict(orient='records')[0]


