# Machine Learning Analysis Module for Honeypot

This module enhances your existing web-based honeypot by bringing machine learning to log analysis. It can automatically categorize incoming traffic and detected attacks into various categories rather than relying solely on static rules.

## Features
- **Data Loading**: Parse SQLite or JSON databases of captured requests.
- **Feature Extraction**: Converts raw requests (payloads, endpoints) into numerical features like keyword counts and payload lengths.
- **Model Training**: Train machine learning models (Random Forest, Logistic Regression, Naive Bayes) using labeled attack data.
- **Inference Pipeline**: Classify newly captured requests on-the-fly or in batches.
- **Report Generation**: Automatically aggregates attack statistics into JSON, CSV, or human-readable text formats, easily pluggable into existing visualization dashboards.

## Project Structure
- `data_loader.py`: Connects to your logs storage.
- `feature_extractor.py`: Extracts ML-friendly features from web payloads.
- `model_training.py`: Handles dataset splitting, model fitting, and evaluation.
- `attack_classifier.py`: Loads the trained pipeline for fast attack classification.
- `report_generator.py`: Summarizes findings and exports them.
- `requirements.txt`: Python dependencies (`pandas`, `scikit-learn`, etc.)

## Usage & Integration Guide
### 1. Install Dependencies
```bash
pip install -r ml_analysis/requirements.txt
```

### 2. Train the Model
You can start by defining a dataset containing past logs and labeling them, or building a script that uses your static rules to bootstrap the labels.

```python
import pandas as pd
from ml_analysis.model_training import ModelTrainer

# Load your labeled dataset
df = pd.read_csv('historical_logs_labeled.csv')

# Train and save the model
trainer = ModelTrainer(model_type='random_forest')
metrics = trainer.train(df, target_column='attack_type', save_path='ml_analysis/model.pkl')
print(metrics)
```

### 3. Integrate with the Honeypot (Real-Time Classification)
Whenever your honeypot captures a request, you can use the `AttackClassifier` to flag it immediately.

```python
from ml_analysis.attack_classifier import AttackClassifier

classifier = AttackClassifier(model_path='ml_analysis/model.pkl')

def on_request_captured(ip, path, data):
    analysis_result = classifier.classify_log(ip=ip, endpoint=path, payload=data)
    print(f"Detected Attack Type: {analysis_result['predicted_attack_type']}")
    # You can now save this prediction to your DB alongside the raw log
```

### 4. Create Scheduled Reports for Visualization
You can run a nightly/weekly cron job to generate updated reports for your dashboard.

```python
from ml_analysis.data_loader import DataLoader
from ml_analysis.attack_classifier import AttackClassifier
from ml_analysis.report_generator import ReportGenerator

# Load recent logs
df = DataLoader.load_from_sqlite('honeypot.db', table_name='logs')

# Classify them all
classifier = AttackClassifier(model_path='ml_analysis/model.pkl')
classified_df = classifier.classify(df)

# Generate reports for the dashboard
reporter = ReportGenerator(classified_df)
reporter.export_json('dashboard_data/attack_summary.json')
```

## Explanation of Workflow
The machine learning pipeline takes advantage of static feature engineering prior to modeling. Rather than using heavy deep learning models (which are a black box and compute-heavy), we take raw HTTP text and extract key structural properties such as:
1. Occurrence of SQLi markers (`UNION`, `SELECT`, etc.)
2. Presence of command execution symbols (`;`, `|`, etc.)
3. The overall length of payloads (usually attacks have longer payloads like buffer overflows or complex queries).

These numbers are then fed to a *Random Forest Classifier* which effectively builds multiple decision trees based on these features. Random Forests are robust to overfitting and provide excellent interpretability and fast inference, making them perfect for this university research project.
