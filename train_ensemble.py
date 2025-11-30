import pandas as pd
import numpy as np
import pickle
import joblib
import os
import re
import tldextract
import math
import json 

from sklearn.ensemble import VotingClassifier, RandomForestClassifier, GradientBoostingClassifier
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, roc_auc_score, f1_score

import warnings
warnings.filterwarnings('ignore')

# --- Utility Functions for Advanced Feature Extraction ---

def calculate_entropy(url):
    """Calculates the Shannon entropy of a string."""
    if not url:
        return 0.0
    
    # Calculate character frequencies
    probabilities = [float(url.count(c)) / len(url) for c in sorted(list(set(url)))]
    
    # Calculate entropy
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in probabilities if p > 0])
    return entropy

def count_vowels(s):
    """Counts the number of vowels in a string."""
    return sum(1 for char in s.lower() if char in 'aeiou')

# --- Enhanced Phishing Detector Class (Updated) ---

class EnhancedPhishingDetector:
    def __init__(self):
        self.ensemble_model = None
        self.feature_names = []
        self.threat_intelligence = {}
        
    def load_threat_intelligence(self):
        """Load threat intelligence from file or create sample data"""
        try:
            ti_path = 'data/threat_intelligence.json'
            if os.path.exists(ti_path):
                with open(ti_path, 'r') as f:
                    threat_data = json.load(f)
                
                # Create lookup dictionary
                self.threat_intelligence = {}
                for url_data in threat_data:
                    self.threat_intelligence[url_data['url']] = {
                        'source': url_data.get('source', 'unknown'),
                        'timestamp': url_data.get('timestamp', ''),
                        'verified': url_data.get('verified', 'no')
                    }
                print(f"✓ Loaded {len(self.threat_intelligence)} threat intelligence entries")
            else:
                print("⚠️ No threat intelligence file found, using empty data")
                self.threat_intelligence = {}
                
        except Exception as e:
            print(f"⚠️ Error loading threat intelligence: {e}")
            self.threat_intelligence = {}
    
    def extract_advanced_features(self, url):
        """
        Extracts advanced features, including the new performance enhancements.
        """
        features = {}
        
        # Domain analysis setup
        te = tldextract.extract(url)
        domain = te.domain
        tld = te.suffix

        # Basic URL features
        features['url_length'] = len(url)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_slashes'] = url.count('/')
        
        # Advanced features
        features['has_https'] = 1 if url.startswith('https') else 0
        features['has_ip'] = 1 if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url) or re.match(r'\d+\.\d+\.\d+\.\d+', url) else 0
        features['is_shortened'] = 1 if any(x in url for x in ['bit.ly', 'goo.gl', 'tinyurl', 't.co']) else 0
        features['special_chars'] = len(re.findall(r'[^\w\.\/:-]', url))
        
        # Domain analysis
        features['domain_length'] = len(domain)
        features['subdomain_count'] = len(te.subdomain.split('.')) if te.subdomain else 0
        features['tld_length'] = len(tld)
        
        # Entropy-based features
        features['entropy'] = calculate_entropy(url)
        features['vowel_ratio'] = count_vowels(domain) / len(domain) if domain else 0

        # --- NEW ENHANCED FEATURES ---
        
        # NEW: Suspicious keyword detection
        suspicious_keywords = ['login', 'verify', 'secure', 'account', 'banking', 'update', 'signin', 'confirm', 'webscr']
        features['suspicious_words'] = sum(1 for word in suspicious_keywords if word in url.lower())
        
        # NEW: Digit ratio in domain
        features['digit_ratio'] = sum(c.isdigit() for c in domain) / len(domain) if domain else 0
        
        # NEW: Consecutive characters (e.g., wwwgoogle.com or aaaaaa)
        # Finds the length of the longest run of consecutive, repeating letters (case insensitive)
        consecutive_match = re.findall(r'([a-zA-Z])\1+', url.lower())
        features['consecutive_chars'] = max(len(match) for match in consecutive_match) if consecutive_match else 0

        # --- THREAT INTELLIGENCE LOOKUP (FIXED) ---
        
        # FIXED: Use .items() and check for source directly
        features['in_openphish'] = 1 if any('openphish' in ti_data.get('source', '') 
                                            for ti_url, ti_data in self.threat_intelligence.items() 
                                            if ti_url == url) else 0 # Corrected to check exact match
                                            
        features['in_phishtank'] = 1 if any('phishtank' in ti_data.get('source', '') 
                                            for ti_url, ti_data in self.threat_intelligence.items() 
                                            if ti_url == url) else 0 # Corrected to check exact match
                                            
        features['in_any_threat_feed'] = 1 if features['in_openphish'] or features['in_phishtank'] else 0
        
        return features
    
    # Rest of the methods (train_ensemble, save_ensemble_model, load_ensemble_model) remain the same
    def train_ensemble(self, csv_path):
        """Train ensemble model with combined dataset and cross-validation"""
        if not os.path.exists(csv_path):
            # No dummy dataset creation here, as we expect a large dataset path now
            raise FileNotFoundError(f"Dataset file not found: {csv_path}. Please ensure your 100K dataset is at this path.")
            
        print("Loading enhanced dataset...")
        df = pd.read_csv(csv_path)
        
        if 'url' not in df.columns or 'label' not in df.columns:
            raise ValueError("Dataset must contain 'url' and 'label' columns")
        
        # Prepare features
        print("Extracting advanced features...")
        rows = []
        for u in df['url']:
            f = self.extract_advanced_features(str(u))
            rows.append(f)
        
        X = pd.DataFrame(rows)
        y = df['label']
        
        self.feature_names = X.columns.tolist()
        
        # Train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print("Initializing enhanced ensemble model...")
        
        # --- Enhanced Ensemble Architecture ---
        rf_model = RandomForestClassifier(n_estimators=200, max_depth=25, random_state=42)
        # Note: XGBClassifier setup is highly optimized for performance
        xgb_model = XGBClassifier(n_estimators=150, learning_rate=0.1, use_label_encoder=False, eval_metric='logloss', random_state=42, n_jobs=-1)
        gb_model = GradientBoostingClassifier(n_estimators=150, random_state=42)
        
        self.ensemble_model = VotingClassifier(
            estimators=[
                ('rf', rf_model),
                ('xgb', xgb_model),
                ('gb', gb_model)
            ],
            voting='soft',
            weights=[2, 3, 1]
        )
        
        print("Performing 5-fold Cross-Validation...")
        # --- Add Cross-Validation ---
        cv_scores = cross_val_score(self.ensemble_model, X, y, cv=5, scoring='f1', n_jobs=-1)
        print(f"✅ Cross-Validation F1 Score (5-fold): {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        
        print("\nTraining final ensemble model on full training set...")
        self.ensemble_model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.ensemble_model.predict(X_test)
        y_prob = self.ensemble_model.predict_proba(X_test)[:, 1]
        
        print("\n=== FINAL ENSEMBLE MODEL EVALUATION ===")
        print(classification_report(y_test, y_pred))
        print(f"ROC AUC Score: {roc_auc_score(y_test, y_prob):.4f}")
        print(f"F1 Score (Test Set): {f1_score(y_test, y_pred):.4f}")
        
        return self.ensemble_model
    
    def save_ensemble_model(self, filepath):
        """Save the ensemble model"""
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            model_data = {
                'ensemble_model': self.ensemble_model,
                'feature_names': self.feature_names,
                'threat_intelligence': self.threat_intelligence
            }
            joblib.dump(model_data, filepath)
            print(f"✓ Ensemble model saved to {filepath}")
        except Exception as e:
            print(f"❌ Error saving ensemble model: {e}")
            raise
    
    def load_ensemble_model(self, filepath):
        """Load the ensemble model"""
        try:
            if not os.path.exists(filepath):
                raise FileNotFoundError(f"Model file not found: {filepath}")
                
            model_data = joblib.load(filepath)
            self.ensemble_model = model_data['ensemble_model']
            self.feature_names = model_data['feature_names']
            self.threat_intelligence = model_data.get('threat_intelligence', {})
            print(f"✓ Ensemble model loaded from {filepath}")
        except Exception as e:
            print(f"❌ Error loading ensemble model: {e}")
            raise

def main():
    try:
        # Create sample threat intelligence data if needed
        ti_dir = 'data'
        ti_path = os.path.join(ti_dir, 'threat_intelligence.json')
        if not os.path.exists(ti_path):
            print("Creating sample threat intelligence data...")
            sample_threat_data = [
                {"url": "http://malicious-phishing-site.com", "source": "openphish", "timestamp": "2024-01-01", "verified": "yes"},
                {"url": "http://fake-bank-login.com", "source": "phishtank", "timestamp": "2024-01-01", "verified": "yes"},
                {"url": "http://steal-password.com", "source": "openphish", "timestamp": "2024-01-01", "verified": "yes"},
                {"url": "https://legitimate-site.com", "source": "none", "timestamp": "", "verified": "no"}
            ]
            os.makedirs(ti_dir, exist_ok=True)
            with open(ti_path, 'w') as f:
                json.dump(sample_threat_data, f, indent=2)
            print("✓ Created sample threat intelligence data")
        
        # --- UPDATED DATASET PATH ---
        dataset_path = 'data/balanced_dataset.csv'
        
        if not os.path.exists(dataset_path):
             print(f"❌ Dataset not found at {dataset_path}")
             # Create a small dummy dataset to allow the code to run without the 100K file
             print("Creating a minimal dummy dataset for execution test...")
             dummy_data = {
                 'url': [
                     'https://google.com/search?q=legit', 
                     'http://malicious-phishing-site.com/login', 
                     'https://bit.ly/2AexA23', 
                     'http://192.168.1.1/admin/login',
                     'https://safe.co.uk/page',
                     'http://fake-bank-login.com/auth'
                 ],
                 'label': [0, 1, 1, 1, 0, 1] 
             }
             pd.DataFrame(dummy_data).to_csv(dataset_path, index=False)
             print("✓ Created a temporary dummy dataset. Replace it with your 100K dataset for real training.")
        
        # Train enhanced model
        detector = EnhancedPhishingDetector()
        detector.load_threat_intelligence()
        
        detector.train_ensemble(dataset_path)
        
        # Save ensemble model
        os.makedirs('models', exist_ok=True)
        detector.save_ensemble_model('models/ensemble_model.pkl')
        
        print("\n" + "="*50)
        print("ENSEMBLE TRAINING COMPLETED SUCCESSFULLY!")
        print("="*50)
        
    except Exception as e:
        print(f"❌ Error in main execution: {e}")

if __name__ == "__main__":
    main()