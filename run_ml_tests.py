import pandas as pd
import os
from ml_analysis.feature_extractor import FeatureExtractor
from ml_analysis.model_training import ModelTrainer
from ml_analysis.attack_classifier import AttackClassifier
from ml_analysis.report_generator import ReportGenerator

def generate_mock_data():
    data = [
        # Normal Traffic
        {"ip": "192.168.1.5", "endpoint": "/login", "payload": "username=admin&password=123", "attack_type": "Normal Traffic"},
        {"ip": "192.168.1.10", "endpoint": "/home", "payload": "", "attack_type": "Normal Traffic"},
        
        # SQL Injection
        {"ip": "10.0.0.1", "endpoint": "/search", "payload": "q=admin' UNION SELECT * FROM users--", "attack_type": "SQL Injection"},
        {"ip": "10.0.0.1", "endpoint": "/login", "payload": "username=admin' OR 1=1--", "attack_type": "SQL Injection"},
        
        # XSS
        {"ip": "172.16.0.4", "endpoint": "/comment", "payload": "text=<script>alert('xss')</script>", "attack_type": "Cross-Site Scripting (XSS)"},
        {"ip": "172.16.0.5", "endpoint": "/profile", "payload": "name=javascript:alert(1)", "attack_type": "Cross-Site Scripting (XSS)"},
        
        # Command Injection
        {"ip": "10.0.0.2", "endpoint": "/ping", "payload": "host=127.0.0.1; cat /etc/passwd", "attack_type": "Command Injection"},
        {"ip": "10.0.0.3", "endpoint": "/status", "payload": "target=localhost && ls -la", "attack_type": "Command Injection"},
        
        # Directory Traversal
        {"ip": "192.168.1.100", "endpoint": "/download", "payload": "file=../../../../etc/passwd", "attack_type": "Directory Traversal"},
        {"ip": "192.168.1.101", "endpoint": "/static", "payload": "file=..\\..\\windows\\win.ini", "attack_type": "Directory Traversal"},
        
        # Brute Force Login
        {"ip": "203.0.113.1", "endpoint": "/login", "payload": "username=admin&password=admin", "attack_type": "Brute Force Login"},
        {"ip": "203.0.113.1", "endpoint": "/login", "payload": "username=admin&password=root", "attack_type": "Brute Force Login"},
        {"ip": "203.0.113.1", "endpoint": "/login", "payload": "username=admin&password=123456", "attack_type": "Brute Force Login"},
    ]
    return pd.DataFrame(data)

def test_pipeline():
    print("--- Mocking Data ---")
    df = generate_mock_data()
    
    print("\\n--- Training Model ---")
    trainer = ModelTrainer(model_type='random_forest')
    metrics = trainer.train(df, target_column='attack_type', save_path='ml_analysis/model.pkl')
    
    print("\\n--- Testing Classifier ---")
    classifier = AttackClassifier(model_path='ml_analysis/model.pkl')
    
    # Classify a single test log
    res = classifier.classify_log(ip="10.0.0.5", endpoint="/search", payload="username=admin' OR 1=1--")
    print(f"Single classification result: {res['predicted_attack_type']}")

    # Classify the whole df
    print("\\n--- Generating Report ---")
    classified_df = classifier.classify(df.drop(columns=['attack_type']))
    
    # We substitute predicted_attack_type as the real type just to test report generation
    reporter = ReportGenerator(classified_df)
    reporter.export_json('ml_analysis/report.json')
    reporter.export_csv('ml_analysis/report.csv')
    reporter.export_pdf('ml_analysis/report.txt')
    
    print("\\nTest completed successfully.")

if __name__ == "__main__":
    test_pipeline()


