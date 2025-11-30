import pandas as pd
import numpy as np

import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, auc

from sklearn.metrics import classification_report, roc_auc_score
import warnings
warnings.filterwarnings('ignore')

class PhishingDetector:
    def __init__(self):
        self.model = None
        self.feature_names = []
        
    def train(self, csv_path):
        """Train the phishing detection model using the pre-computed features"""
        print("Loading dataset...")
        df = pd.read_csv(csv_path)
        
        # Display dataset info
        print(f"Dataset shape: {df.shape}")
        print(f"Columns: {df.columns.tolist()}")
        
        # Rename columns to standard names
        df.rename(columns={'status': 'label'}, inplace=True)
        
        # Map labels to 0 (legitimate) and 1 (phishing)
        df['label'] = df['label'].map({'legitimate': 0, 'phishing': 1})
        
        print(f"Label distribution:\n{df['label'].value_counts()}")
        
        # Prepare features - use all columns except url and label
        feature_columns = [col for col in df.columns if col not in ['url', 'label']]
        X = df[feature_columns]
        y = df['label']
        
        self.feature_names = X.columns.tolist()
        
        print(f"Using {len(feature_columns)} features for training")
        print(f"Feature names: {feature_columns[:10]}...")  # Show first 10 features
        
        # Handle missing values
        X = X.fillna(0)
        
        # Train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"Training set: {X_train.shape}")
        print(f"Test set: {X_test.shape}")
        
        print("Training Random Forest model...")
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        y_prob = self.model.predict_proba(X_test)[:, 1]
        
        print("\n" + "="*50)
        print("MODEL EVALUATION RESULTS")
        print("="*50)
        print(classification_report(y_test, y_pred))
        print(f"ROC AUC Score: {roc_auc_score(y_test, y_prob):.4f}")
        # Plot ROC Curve
        fpr, tpr, _ = roc_curve(y_test, y_prob)
        roc_auc = auc(fpr, tpr)
        plt.figure(figsize=(6,6))
        plt.plot(fpr, tpr, color="blue", lw=2, label=f"ROC curve (AUC = {roc_auc:.3f})")
        plt.plot([0, 1], [0, 1], color="red", lw=2, linestyle="--")
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel("False Positive Rate")
        plt.ylabel("True Positive Rate")
        plt.title("Receiver Operating Characteristic (ROC) Curve")
        plt.legend(loc="lower right")
        plt.show()

        # Plot ROC Curve


        # Feature importance
        feature_importance = pd.DataFrame({
            'feature': X.columns,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        print("\nTop 10 Most Important Features:")
        print(feature_importance.head(10))
        
        return self.model
    
    def predict_from_features(self, features_dict):
        """Predict using pre-computed features"""
        if self.model is None:
            raise ValueError("Model not trained. Please train the model first.")
        
        # Create feature vector in correct order
        feature_vector = []
        for feature_name in self.feature_names:
            feature_vector.append(features_dict.get(feature_name, 0))
        
        feature_array = np.array(feature_vector).reshape(1, -1)
        
        prediction = self.model.predict(feature_array)[0]
        probability = self.model.predict_proba(feature_array)[0][1]
        
        return {
            'is_phishing': bool(prediction),
            'probability': float(probability),
            'confidence': 'High' if probability > 0.8 else 'Medium' if probability > 0.6 else 'Low'
        }
    
    def save_model(self, filepath):
        """Save the trained model"""
        with open(filepath, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'feature_names': self.feature_names
            }, f)
        print(f"Model saved to {filepath}")
    
    def load_model(self, filepath):
        """Load a trained model"""
        with open(filepath, 'rb') as f:  # FIXED: was filefilepath
            data = pickle.load(f)
        self.model = data['model']
        self.feature_names = data['feature_names']
        print(f"Model loaded from {filepath}")

def main():
    # Initialize detector
    detector = PhishingDetector()
    
    # Train model
    csv_path = 'data/dataset_phishing.csv'
    detector.train(csv_path)
    
    # Save model
    import os
    os.makedirs('models', exist_ok=True)
    detector.save_model('models/phishing_model.pkl')
    
    print("\n" + "="*50)
    print("TRAINING COMPLETED SUCCESSFULLY!")
    print("="*50)
    print("Next steps:")
    print("1. Run: python app.py")
    print("2. Open http://localhost:5000 in your browser")
    print("3. Start scanning URLs!")

if __name__ == "__main__":
    main()