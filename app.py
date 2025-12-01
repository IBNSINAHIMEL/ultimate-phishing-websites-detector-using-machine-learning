from flask import Flask, render_template, request, jsonify
import pickle
import joblib
import os
import pandas as pd
import tldextract
import re
from urllib.parse import urlparse
import requests
import concurrent.futures
import ssl
import socket
import whois
from datetime import datetime
import time
import urllib3
import tensorflow as tf
import numpy as np
import uuid
from itertools import groupby  # Add this to your imports
from image_model import PhishingImageModel
from image_preprocessing import ImagePreprocessor
from PIL import Image  # Add this line
import io  # Add this too
from screenshot_capture import get_screenshot_data, cleanup_screenshot_capture
import os
import requests
import gdown 


# Disable SSL warnings for internal requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

atexit.register(cleanup_screenshot_capture)
# Google Safe Browsing API Configuration
GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY', '')

GOOGLE_SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"



# List of trusted subdomain providers
TRUSTED_SUBDOMAIN_PROVIDERS = {
    'blogspot.com': 'Google Blogger',
    'wordpress.com': 'WordPress',
    'github.io': 'GitHub Pages',
    'netlify.app': 'Netlify',
    'herokuapp.com': 'Heroku',
    'webflow.io': 'Webflow',
    'wixsite.com': 'Wix',
    'tumblr.com': 'Tumblr',
    'medium.com': 'Medium',
    'weebly.com': 'Weebly'
}


def is_valid_url(url):
    """
    Validate if the input is a proper URL
    """
    try:
        # Allow URLs without protocol for user convenience
        test_url = url
        if not re.match(r'^https?://', url):
            test_url = 'https://' + url
        
        parsed = urlparse(test_url)
        
        # Check if it has a valid domain
        if not parsed.netloc:
            return False
        
        # Check if domain has at least one dot (except localhost)
        if '.' not in parsed.netloc and parsed.netloc != 'localhost':
            return False
        
        # Check for minimum domain length
        domain_parts = parsed.netloc.split('.')
        if len(domain_parts) < 2:
            return False
        
        # Check if TLD is reasonable (at least 2 characters for real domains)
        tld = domain_parts[-1]
        if len(tld) < 2 and tld not in ['io', 'ai', 'tv']:  # Allow common short TLDs
            return False
            
        return True
    except:
        return False
def check_google_safe_browsing(url):
    """Check URL against Google Safe Browsing API - FIXED"""
    try:
        # Check if API credentials are available
        if not GOOGLE_SAFE_BROWSING_API_KEY:
            return {
                'error': 'Google Safe Browsing API key not configured',
                'is_threat': False,
                'success': False
            }
        
        # Extract domain for broader checking
        parsed = urlparse(url)
        domain = parsed.netloc
        
        payload = {
            "client": {
                "clientId": "phishing-detector",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url},
                    {"url": f"https://{domain}"}  # Also check domain
                ]
            }
        }
        
        response = requests.post(
            f"{GOOGLE_SAFE_BROWSING_URL}?key={GOOGLE_SAFE_BROWSING_API_KEY}",
            json=payload,
            timeout=5  # 5 second timeout
        )
        
        if response.status_code == 200:
            data = response.json()
            return {
                'safe_browsing_result': data,
                'is_threat': 'matches' in data and len(data['matches']) > 0,
                'threat_types': [match['threatType'] for match in data.get('matches', [])],
                'cacheDuration': data.get('cacheDuration', '300s'),
                'success': True
            }
        else:
            print(f"Google Safe Browsing API error: {response.status_code}")
            return {
                'error': f"API error: {response.status_code}", 
                'is_threat': False,
                'success': False
            }
            
    except requests.exceptions.Timeout:
        return {
            'error': 'Google Safe Browsing API timeout', 
            'is_threat': False,
            'success': False
        }
    except Exception as e:
        print(f"Google Safe Browsing failed: {e}")
        return {
            'error': str(e), 
            'is_threat': False,
            'success': False
        }
# Image Analysis Setup
phishing_model = None
preprocessor = None

def load_image_model():
    global phishing_model, preprocessor
    try:
        phishing_model = PhishingImageModel()
        phishing_model.model = tf.keras.models.load_model('models/phishing_detector.h5')
        preprocessor = ImagePreprocessor()
        print("✅ Phishing detection model loaded successfully!")
    except Exception as e:
        print(f"❌ Failed to load image model: {e}")

load_image_model()

def analyze_website_screenshot(image_path):
    global phishing_model, preprocessor
    try:
        if phishing_model is None or preprocessor is None:
            return {'error': 'Model not loaded'}
        
        test_image = preprocessor.load_and_preprocess_image(image_path)
        if test_image is not None:
            prediction = phishing_model.model.predict(np.expand_dims(test_image, axis=0))
            confidence = float(prediction[0][0])
            return {
                'is_phishing': confidence > 0.5,
                'confidence': confidence if confidence > 0.5 else 1 - confidence,
                'label': 'phishing' if confidence > 0.5 else 'legitimate'
            }
        return {'error': 'Failed to process image'}
    except Exception as e:
        return {'error': str(e)}
# Global variable for ML model (add at the top with other globals)
ml_model=None

def predict_with_ml(features, timeout=30):
    """Make prediction using ML model with fallback to rule-based"""
    try:
        # If no ML model is loaded, use rule-based fallback
        if ml_model is None:
            return rule_based_prediction(features)
        
        # Prepare features for ML model
        ml_features = prepare_ml_features(features)
        
        # Make prediction
        prediction = ml_model.predict(ml_features)[0]
        probability = ml_model.predict_proba(ml_features)[0]
        
        # For binary classification: [legit_prob, phishing_prob]
        if len(probability) == 2:
            phishing_confidence = probability[1] * 100  # Probability it's phishing
        else:
            phishing_confidence = probability[0] * 100
        
        return {
            'is_phishing': bool(prediction),
            'confidence': round(phishing_confidence, 2),
            'method': 'ml_model'
        }
        
    except Exception as e:
        print(f"❌ ML prediction error: {e}")
        # Fallback to rule-based prediction
        return rule_based_prediction(features)

def prepare_ml_features(features):
    """Prepare features for ML model prediction - SIMPLIFIED VERSION"""
    # If you don't have a trained model yet, return dummy features
    # This will work with the rule-based fallback
    return [[0]]  # Dummy array that will trigger the fallback

def rule_based_prediction(features):
    """Fallback rule-based prediction when ML fails"""
    score = 0
    reasons = []
    
    # Simple scoring based on features
    if features.get('has_ip', 0) == 1:
        score += 30
        reasons.append("IP address used as domain")
    
    if features.get('url_length', 0) > 75:
        score += 20
        reasons.append("Very long URL")
    
    if features.get('suspicious_words', 0) > 3:
        score += 25
        reasons.append("Multiple suspicious keywords")
    
    if features.get('num_subdomains', 0) > 3:
        score += 15
        reasons.append("Excessive subdomains")
    
    if features.get('has_https', 0) == 0:
        score += 10
        reasons.append("No HTTPS encryption")
    
    # Determine if phishing based on threshold
    is_phishing = score > 50
    confidence = min(score, 100)
    
    return {
        'is_phishing': is_phishing,
        'confidence': confidence,
        'method': 'rule_based_fallback',
        'reasons': reasons
    }    
import re
from urllib.parse import urlparse, parse_qs
import tldextract
import idna

def is_suspicious_heuristic(url):
    """Balanced heuristic detection for phishing patterns"""
    # Convert to lowercase for case-insensitive matching
    url_lower = url.lower()
    
    parsed = urlparse(url_lower)
    domain = parsed.netloc
    path = parsed.path
    
    # Extract domain components using tldextract for better accuracy
    ext = tldextract.extract(url_lower)
    domain_name = ext.domain
    subdomain = ext.subdomain
    suffix = ext.suffix
    
    full_domain = f"{domain_name}.{suffix}"
    
    # List of legitimate domains to WHITELIST
    legitimate_domains = [
        'paypal.com', 'facebook.com', 'google.com', 'microsoft.com',
        'apple.com', 'amazon.com', 'netflix.com', 'linkedin.com',
        'twitter.com', 'github.com', 'blogspot.com', 'wordpress.com',
        'yahoo.com', 'outlook.com', 'hotmail.com', 'gmail.com',
        'instagram.com', 'whatsapp.com', 'telegram.org',
        'ibnsinatrust.com'  # ADD THE SPECIFIC SITE THAT'S BEING FLAGGED
    ]
    
    # FIRST: Check if it's a legitimate domain - if yes, return False immediately
    if full_domain in legitimate_domains:
        return False
    
    # Check for legitimate subdomains of trusted services
    legitimate_patterns = [
        r'.*\.paypal\.com$', r'.*\.facebook\.com$', r'.*\.google\.com$',
        r'.*\.microsoft\.com$', r'.*\.apple\.com$', r'.*\.amazon\.com$',
        r'.*\.github\.io$', r'.*\.netlify\.app$', r'.*\.herokuapp\.com$',
        r'.*\.ibnsinatrust\.com$'  # ADD THIS TOO
    ]
    
    for pattern in legitimate_patterns:
        if re.match(pattern, domain):
            return False
    
    # FIXED: Only truly suspicious TLDs
    suspicious_tlds = [
        '.tk', '.ml', '.ga', '.cf', '.gq'  # Free TLDs known for abuse
    ]
    
    # FIXED: More specific phishing keywords (avoid common terms)
    phishing_keywords = [
        'login-secure', 'verify-account', 'banking-auth', 'password-reset',
        'wallet-access', 'payment-confirm', 'account-recover'
    ]
    
    # FIXED: Typosquatting patterns only for major brands
    typosquatting_patterns = [
        'paypa1', 'paypai', 'facebok', 'faceb00k', 'g00gle', 'go0gle',
        'micr0soft', 'app1e', 'amaz0n', 'netf1ix', 'linked1n', 'tw1tter'
    ]
    
    # URL shorteners (often used to hide phishing URLs)
    url_shorteners = [
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
        'buff.ly', 'tiny.cc', 'bit.do', 'shorte.st', 'adf.ly', 'bc.vc'
    ]
    
    # Check 1: Typosquatting in domain name
    if any(pattern in domain_name for pattern in typosquatting_patterns):
        return True
        
    # Check 2: Suspicious TLDs (only the risky ones)
    if any(suffix.endswith(tld.replace('.', '')) for tld in suspicious_tlds):
        return True
        
    # Check 3: URL shorteners
    if any(shortener in domain for shortener in url_shorteners):
        return True
        
    # Check 4: IP address instead of domain name
    ip_pattern = r'^\d+\.\d+\.\d+\.\d+$'
    if re.match(ip_pattern, domain):
        return True
        
    # Check 5: Excessive hyphens (more than 4 is suspicious)
    if domain.count('-') > 4:
        return True
        
    # Check 6: Brand impersonation with lookalike characters
    brand_patterns = [
        (r'paypal', r'paypa[0-9il]'),
        (r'facebook', r'facebo[0-9ok]'),
        (r'google', r'goo[0-9gl]e'),
    ]
    
    for brand, pattern in brand_patterns:
        if re.search(pattern, domain_name):
            # Only flag if it's NOT the real domain
            legitimate_domain = f"{brand}.com"
            if legitimate_domain not in domain:
                return True
    
    # Check 7: Very long domains (only flag extremely long ones)
    if len(domain) > 75:  # Increased from 50
        return True
    
    # Check 8: Excessive subdomains
    if subdomain.count('.') > 3:  # More than 4 subdomain levels
        return True
    
    return False



    
def enhanced_heuristic_check(url):
    """Enhanced check with scoring"""
    if is_suspicious_heuristic(url):
        score = calculate_phishing_score(url)
        return {
            'suspicious': True,
            'score': score,
            'risk_level': 'HIGH' if score > 70 else 'MEDIUM' if score > 40 else 'LOW'
        }
    else:
        return {
            'suspicious': False,
            'score': calculate_phishing_score(url),
            'risk_level': 'LOW'
        }


def combined_analysis_simple(url, ml_features):
    """ML primary with heuristic as confidence booster"""
    heuristic_result = enhanced_heuristic_check(url)  # Your function
    ml_result = predict_with_ml(ml_features)
    
    # Start with ML decision
    final_result = {
        'is_phishing': ml_result.get('is_phishing', False),
        'confidence': ml_result.get('confidence', 0),
        'heuristic': heuristic_result,  # Include full heuristic data
        'ml_prediction': ml_result
    }
    
    # Use heuristic to adjust confidence
    if heuristic_result['suspicious']:
        if heuristic_result['risk_level'] == 'HIGH':
            final_result['confidence'] = min(100, final_result['confidence'] + 15)
        elif heuristic_result['risk_level'] == 'MEDIUM':
            final_result['confidence'] = min(100, final_result['confidence'] + 8)
    
    return final_result
# Additional scoring function for more granular detection
def calculate_phishing_score(url):
    """Calculate a phishing probability score (0-100)"""
    score = 0
    url_lower = url.lower()
    
    # Various checks that add to the score
    checks = [
        (re.search(r'paypa[0-9il]', url_lower), 20),
        (re.search(r'facebo[0-9ok]', url_lower), 20),
        (re.search(r'goo[0-9gl]e', url_lower), 20),
        (re.search(r'login|verify|secure', url_lower), 15),
        (re.search(r'\.tk|\.ml|\.ga|\.cf', url_lower), 25),
        (re.search(r'bit\.ly|tinyurl\.com', url_lower), 20),
        (url_lower.count('-') > 3, 10),
        (len(url_lower) > 50, 10),
    ]
    
    for condition, points in checks:
        if condition:
            score += points
    
    return min(score, 100)


def extract_basic_url_features(url):
    """Extract EXACTLY 87 features that match the trained model"""
    features = {}
    
    # Extract domain components first
    try:
        te = tldextract.extract(url)
        domain = te.domain
        suffix = te.suffix
        subdomain = te.subdomain
        full_domain = f"{domain}.{suffix}"
    except:
        domain = suffix = subdomain = ""
        full_domain = ""
    
    # === EXACT 87 FEATURES FROM YOUR TRAINING LOG ===
    
    # 1. Basic URL features
    features['length_url'] = len(url)
    features['length_hostname'] = len(te.domain) + len(te.suffix) if te.domain and te.suffix else 0
    features['ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    features['nb_dots'] = url.count('.')
    features['nb_hyphens'] = url.count('-')
    features['nb_at'] = url.count('@')
    features['nb_qm'] = url.count('?')
    features['nb_and'] = url.count('&')
    features['nb_or'] = url.count('|')  # Added this missing feature
    features['nb_eq'] = url.count('=')
    features['nb_underscore'] = url.count('_')
    features['nb_tilde'] = url.count('~')
    features['nb_percent'] = url.count('%')
    features['nb_slash'] = url.count('/')
    features['nb_star'] = url.count('*')
    features['nb_colon'] = url.count(':')
    features['nb_comma'] = url.count(',')
    features['nb_semicolumn'] = url.count(';')
    features['nb_dollar'] = url.count('$')
    features['nb_space'] = url.count(' ')
    features['nb_www'] = 1 if 'www.' in url.lower() else 0
    features['nb_com'] = 1 if '.com' in url.lower() else 0
    features['nb_dslash'] = url.count('//')
    
    # 2. Path and protocol features
    features['http_in_path'] = 1 if 'http:' in url.lower() else 0
    features['https_token'] = 1 if 'https' in url.lower() else 0
    
    # 3. Digit ratios
    digits_in_url = len(re.findall(r'\d', url))
    features['ratio_digits_url'] = digits_in_url / len(url) if len(url) > 0 else 0
    
    digits_in_host = len(re.findall(r'\d', full_domain))
    features['ratio_digits_host'] = digits_in_host / len(full_domain) if len(full_domain) > 0 else 0
    
    # 4. Domain features
    features['punycode'] = 1 if 'xn--' in url.lower() else 0
    features['port'] = 1 if re.search(r':\d+', url) else 0
    features['tld_in_path'] = 1 if any(tld in url.lower().split('/')[-1] for tld in ['.com', '.org', '.net']) else 0
    features['tld_in_subdomain'] = 1 if any(tld in subdomain.lower() for tld in ['.com', '.org', '.net']) else 0
    features['abnormal_subdomain'] = 1 if len(subdomain) > 50 else 0
    features['nb_subdomains'] = len(subdomain.split('.')) if subdomain else 0
    features['prefix_suffix'] = 1 if re.search(r'-\w+\.\w+\.\w+', url) else 0  # e.g., example-com.domain.com
    
    # 5. Random domain and shortening
    features['random_domain'] = 1 if len(domain) < 4 or len(domain) > 15 else 0
    features['shortening_service'] = 1 if any(short in url.lower() for short in ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'ow.ly']) else 0
    features['path_extension'] = 1 if re.search(r'\.(exe|zip|rar|js|css)$', url.lower()) else 0
    
    # 6. Redirection features (simplified)
    features['nb_redirection'] = url.count('redirect') + url.count('url=')
    features['nb_external_redirection'] = url.count('http') - 1 if url.count('http') > 1 else 0
    
    # 7. Word-based features
    words = re.findall(r'[a-zA-Z]+', url)
    features['length_words_raw'] = len(words)
    features['char_repeat'] = max([len(list(g)) for k, g in groupby(url)]) if url else 0
    
    word_lengths = [len(word) for word in words]
    features['shortest_words_raw'] = min(word_lengths) if word_lengths else 0
    features['shortest_word_host'] = min([len(word) for word in re.findall(r'[a-zA-Z]+', full_domain)]) if full_domain else 0
    features['shortest_word_path'] = min([len(word) for word in re.findall(r'[a-zA-Z]+', url.split('/')[-1])]) if '/' in url else 0
    
    features['longest_words_raw'] = max(word_lengths) if word_lengths else 0
    features['longest_word_host'] = max([len(word) for word in re.findall(r'[a-zA-Z]+', full_domain)]) if full_domain else 0
    features['longest_word_path'] = max([len(word) for word in re.findall(r'[a-zA-Z]+', url.split('/')[-1])]) if '/' in url else 0
    
    features['avg_words_raw'] = sum(word_lengths) / len(word_lengths) if word_lengths else 0
    features['avg_word_host'] = sum([len(word) for word in re.findall(r'[a-zA-Z]+', full_domain)]) / len(re.findall(r'[a-zA-Z]+', full_domain)) if full_domain else 0
    features['avg_word_path'] = sum([len(word) for word in re.findall(r'[a-zA-Z]+', url.split('/')[-1])]) / len(re.findall(r'[a-zA-Z]+', url.split('/')[-1])) if '/' in url else 0
    
    # 8. Phishing hints and brand detection
    features['phish_hints'] = sum(1 for keyword in ['login', 'verify', 'secure', 'account', 'banking'] if keyword in url.lower())
    features['domain_in_brand'] = 1 if any(brand in url.lower() for brand in ['paypal', 'facebook', 'google', 'microsoft']) else 0
    features['brand_in_subdomain'] = 1 if any(brand in subdomain.lower() for brand in ['paypal', 'facebook', 'google', 'microsoft']) else 0
    features['brand_in_path'] = 1 if any(brand in url.lower().split('/')[-1] for brand in ['paypal', 'facebook', 'google', 'microsoft']) else 0
    features['suspecious_tld'] = 1 if any(tld in suffix.lower() for tld in ['.tk', '.ml', '.ga', '.cf']) else 0
    
    # 9. Statistical and HTML features (set defaults as these require full page analysis)
    features['statistical_report'] = 0
    features['nb_hyperlinks'] = 0
    features['ratio_intHyperlinks'] = 0
    features['ratio_extHyperlinks'] = 0
    features['ratio_nullHyperlinks'] = 0
    features['nb_extCSS'] = 0
    features['ratio_intRedirection'] = 0
    features['ratio_extRedirection'] = 0
    features['ratio_intErrors'] = 0
    features['ratio_extErrors'] = 0
    features['login_form'] = 0
    features['external_favicon'] = 0
    features['links_in_tags'] = 0
    features['submit_email'] = 0
    features['ratio_intMedia'] = 0
    features['ratio_extMedia'] = 0
    features['sfh'] = 0  # Server Form Handler
    features['iframe'] = 0
    features['popup_window'] = 0
    features['safe_anchor'] = 0
    features['onmouseover'] = 0
    features['right_clic'] = 0
    features['empty_title'] = 0
    features['domain_in_title'] = 0
    features['domain_with_copyright'] = 0
    
    # 10. WHOIS and reputation features (set defaults)
    features['whois_registered_domain'] = 0
    features['domain_registration_length'] = 0
    features['domain_age'] = 0
    features['web_traffic'] = 0
    features['dns_record'] = 0
    features['google_index'] = 0
    features['page_rank'] = 0
    
    print(f"🔍 Extracted {len(features)} features for ML model")
    return features


def is_trusted_subdomain(url):
    """Check if URL uses a trusted subdomain provider"""
    try:
        te = tldextract.extract(url)
        full_domain = f"{te.domain}.{te.suffix}"
        return full_domain in TRUSTED_SUBDOMAIN_PROVIDERS, TRUSTED_SUBDOMAIN_PROVIDERS.get(full_domain)
    except:
        return False, None

def get_confidence_label(probability, predicted_class):
    """Convert probability to meaningful confidence labels"""
    if predicted_class == "legitimate":
        if probability > 0.8:
            return "✅ HIGH CONFIDENCE - LEGITIMATE"
        elif probability > 0.6:
            return "✅ MODERATE CONFIDENCE - LEGITIMATE" 
        elif probability > 0.4:
            return "⚠️ LOW CONFIDENCE - LIKELY LEGITIMATE"
        else:
            return "🔶 VERY LOW CONFIDENCE - VERIFY MANUALLY"
    else:  # phishing
        if probability > 0.8:
            return "🚨 HIGH CONFIDENCE - PHISHING"
        elif probability > 0.6:
            return "⚠️ MODERATE CONFIDENCE - LIKELY PHISHING"
        else:
            return "🟡 SUSPICIOUS - FURTHER ANALYSIS NEEDED"

def hybrid_prediction(url, features):
    """Make prediction using both models with proper feature naming"""
    results = {}
    
    # Try ensemble model first
    if 'ensemble' in models_loaded:
        try:
            feature_vector = []
            expected_features = feature_names['ensemble']
            
            # Ensure we have all expected features in correct order
            for feature_name in expected_features:
                feature_vector.append(features.get(feature_name, 0))
            
            # Convert to DataFrame with proper feature names
            import pandas as pd
            X_pred = pd.DataFrame([feature_vector], columns=expected_features)
            
            # Now predict with properly named features
            prediction = models_loaded['ensemble'].predict(X_pred)[0]
            probabilities = models_loaded['ensemble'].predict_proba(X_pred)[0]
            
            probability = probabilities[prediction]
            
            # ✅ FIXED: Reverse the logic
            class_label = "legitimate" if prediction == 1 else "phishing"  # CHANGED THIS LINE
            confidence = get_confidence_label(probability, class_label)
                
            results['ensemble'] = {
                'prediction': prediction,
                'probability': float(probability),
                'confidence': confidence,
                'class_label': class_label
            }
            print(f"🔍 Ensemble model: {class_label} with probability {probability:.2%} -> {confidence}")
            
        except Exception as e:
            print(f"Ensemble model error: {e}")
    
    # Similar fix for original model
    if 'original' in models_loaded and not results.get('ensemble'):
        try:
            feature_vector = []
            expected_features = feature_names['original']
            
            for feature_name in expected_features:
                feature_vector.append(features.get(feature_name, 0))
            
            # Convert to DataFrame with proper feature names
            import pandas as pd
            X_pred = pd.DataFrame([feature_vector], columns=expected_features)
            
            prediction = models_loaded['original'].predict(X_pred)[0]
            probabilities = models_loaded['original'].predict_proba(X_pred)[0]
            
            probability = probabilities[prediction]
            
            # ✅ FIXED: Reverse the logic
            class_label = "legitimate" if prediction == 1 else "phishing"  # CHANGED THIS LINE
            confidence = get_confidence_label(probability, class_label)
                
            results['original'] = {
                'prediction': prediction,
                'probability': float(probability),
                'confidence': confidence,
                'class_label': class_label
            }
            print(f"🔍 Original model: {class_label} with probability {probability:.2%} -> {confidence}")
            
        except Exception as e:
            print(f"Original model error: {e}")
    
    return results
def debug_model_prediction(url):
    """Debug function to understand model predictions"""
    print(f"\n🔧 DEBUGGING PREDICTION FOR: {url}")
    
    features = extract_basic_url_features(url)
    print(f"📊 Features extracted: {len(features)} features")
    
    # Show some key features
    key_features = ['url_len', 'nb_dots', 'nb_hyphens', 'length_hostname', 'nb_subdomains']
    for kf in key_features:
        print(f"   {kf}: {features.get(kf, 'N/A')}")
    
    # Test both models if available
    if 'ensemble' in models_loaded:
        try:
            feature_vector = []
            for feature_name in feature_names['ensemble']:
                feature_vector.append(features.get(feature_name, 0))
            
            prediction = models_loaded['ensemble'].predict([feature_vector])[0]
            probabilities = models_loaded['ensemble'].predict_proba([feature_vector])[0]
            
            print(f"🎯 Ensemble Model:")
            print(f"   Prediction: {prediction} ({'phishing' if prediction == 1 else 'legitimate'})")
            print(f"   Probabilities: [legitimate: {probabilities[0]:.2%}, phishing: {probabilities[1]:.2%}]")
            
        except Exception as e:
            print(f"❌ Ensemble model debug error: {e}")
    
    if 'original' in models_loaded:
        try:
            feature_vector = []
            for feature_name in feature_names['original']:
                feature_vector.append(features.get(feature_name, 0))
            
            prediction = models_loaded['original'].predict([feature_vector])[0]
            probabilities = models_loaded['original'].predict_proba([feature_vector])[0]
            
            print(f"🎯 Original Model:")
            print(f"   Prediction: {prediction} ({'phishing' if prediction == 1 else 'legitimate'})")
            print(f"   Probabilities: [legitimate: {probabilities[0]:.2%}, phishing: {probabilities[1]:.2%}]")
            
        except Exception as e:
            print(f"❌ Original model debug error: {e}")
    
    print("🔧 DEBUG COMPLETE\n")

def hybrid_scan_url(url, features):
    """Hybrid scanning: Google Safe Browsing + ML fallback + Heuristic - ENHANCED"""
    print(f"🔍 Scanning: {url}")
    start_time = time.time()
    heuristic_result = is_suspicious_heuristic(url)
    heuristic_time = time.time() - start_time
    print(f"    Heuristic check took {heuristic_time:.3f}s - Result: {heuristic_result}")
    
    # STEP 1: Immediate heuristic detection
    if heuristic_result:
        print(f"🚨 IMMEDIATE HEURISTIC DETECTION: {url}")
        return {
            'final_verdict': True,
            'confidence': "🚨 HIGH CONFIDENCE - PHISHING (Heuristic)",
            'scan_method': 'heuristic',
            'probability': 0.85,
            'class_label': 'phishing',
            'special_message': "⚠️ Heuristic analysis detected suspicious patterns"
        }
    
    results = {
        'google_safe_browsing': None,
        'ml_prediction': None,
        'final_verdict': None,
        'confidence': None,
        'scan_method': None,
        'threat_types': [],
        'probability': None,
        'class_label': None,
        'special_message': None
    }
    
    # STEP 2: Check if it's a Blogger site and apply special logic
    is_trusted, provider = is_trusted_subdomain(url)
    if is_trusted and 'blogspot.com' in url.lower():
        print(f"🔍 Blogger site detected: {url}")
        
        # For Blogger sites, use ML model to determine trustworthiness
        ml_results = hybrid_prediction(url, features)
        
        if 'ensemble' in ml_results or 'original' in ml_results:
            ml_result = ml_results.get('ensemble') or ml_results.get('original')
            # ✅ FIX: Use class_label instead of prediction to determine if phishing
            is_phishing = ml_result['class_label'] == 'phishing'
            probability = ml_result['probability']
            
            if is_phishing and probability > 0.9:
                # Suspicious Blogger site
                results['final_verdict'] = True
                results['confidence'] = "⚠️ CAUTION ADVISED"
                results['scan_method'] = 'blogger_suspicious'
                results['probability'] = probability
                results['class_label'] = 'phishing'
                results['special_message'] = "This website uses Google Blogger service. While the platform is trusted, this specific site shows suspicious characteristics. Confidence: Low"
                results['trusted_subdomain'] = True
                results['subdomain_provider'] = provider
                print(f"🔍 Suspicious Blogger site detected with probability: {probability:.2%}")
                return results
            else:
                # Safe Blogger site
                results['final_verdict'] = False
                results['confidence'] = "✅ TRUSTED PLATFORM"
                results['scan_method'] = 'blogger_safe'
                results['probability'] = probability
                results['class_label'] = 'legitimate'
                results['special_message'] = "This website uses Google Blogger service. The platform is trusted. Confidence: High"
                results['trusted_subdomain'] = True
                results['subdomain_provider'] = provider
                print(f"🔍 Safe Blogger site detected with probability: {probability:.2%}")
                return results
    
    # STEP 3: Check other trusted subdomains (GitHub Pages, Netlify, etc.)
    if is_trusted and provider:
        print(f"🔍 Trusted platform detected: {provider}")
        # For other trusted platforms, still run security checks but with platform context
        ml_results = hybrid_prediction(url, features)
        
        if 'ensemble' in ml_results or 'original' in ml_results:
            ml_result = ml_results.get('ensemble') or ml_results.get('original')
            # ✅ FIX: Use class_label instead of prediction to determine if phishing
            is_phishing = ml_result['class_label'] == 'phishing'
            probability = ml_result['probability']
            
            if is_phishing or probability > 0.7:
                # Suspicious content on trusted platform
                results['final_verdict'] = True
                results['confidence'] = "⚠️ CAUTION ADVISED"
                results['scan_method'] = 'trusted_platform_suspicious'
                results['probability'] = probability
                results['class_label'] = 'phishing'
                results['special_message'] = f"This website uses {provider} service. While the platform is trusted, this specific site shows suspicious characteristics."
                results['trusted_subdomain'] = True
                results['subdomain_provider'] = provider
                return results
            else:
                # Likely safe content on trusted platform
                results['final_verdict'] = False
                results['confidence'] = "✅ TRUSTED PLATFORM"
                results['scan_method'] = 'trusted_platform_safe'
                results['probability'] = probability
                results['class_label'] = 'legitimate'
                results['special_message'] = f"This website uses {provider} service. The platform is trusted."
                results['trusted_subdomain'] = True
                results['subdomain_provider'] = provider
                return results
    
    # STEP 4: Try Google Safe Browsing first (with timeout)
    try:
        google_result = check_google_safe_browsing(url)
        results['google_safe_browsing'] = google_result
        print(f"🔍 Google Safe Browsing result: {google_result}")
        if google_result.get('is_threat'):
            results['final_verdict'] = True  # Phishing
            results['confidence'] = "🚨 VERY HIGH CONFIDENCE - PHISHING (Google Safe Browsing)"
            results['scan_method'] = 'google_safe_browsing'
            results['threat_types'] = google_result.get('threat_types', [])
            results['probability'] = 0.95  # Very high confidence for Google
            results['class_label'] = 'phishing'
            results['special_message'] = f"⚠️ Confirmed threat by Google Safe Browsing: {', '.join(results['threat_types'])}"
            return results
            
    except Exception as e:
        print(f"Google Safe Browsing exception: {e}")
        results['google_safe_browsing'] = {'error': str(e), 'is_threat': False, 'success': False}
    
    # STEP 5: Fallback to ML model
    ml_results = hybrid_prediction(url, features)
    
    if 'ensemble' in ml_results:
        ml_result = ml_results['ensemble']
        results['ml_prediction'] = ml_result
        # ✅ FIX: Use class_label to determine final_verdict
        results['final_verdict'] = (ml_result['class_label'] == 'phishing')
        results['confidence'] = ml_result['confidence']
        results['scan_method'] = 'ml_model'
        results['probability'] = ml_result['probability']
        results['class_label'] = ml_result['class_label']
        results['model_used'] = 'ensemble'
        
        # Add appropriate message based on ML result
        if results['final_verdict']:
            results['special_message'] = "⚠️ ML model detected phishing patterns"
        else:
            results['special_message'] = "✅ ML model analysis shows legitimate website"
            
    elif 'original' in ml_results:
        ml_result = ml_results['original']
        results['ml_prediction'] = ml_result
        # ✅ FIX: Use class_label to determine final_verdict
        results['final_verdict'] = (ml_result['class_label'] == 'phishing')
        results['confidence'] = ml_result['confidence']
        results['scan_method'] = 'ml_model'
        results['probability'] = ml_result['probability']
        results['class_label'] = ml_result['class_label']
        results['model_used'] = 'original'
        
        # Add appropriate message based on ML result
        if results['final_verdict']:
            results['special_message'] = "⚠️ ML model detected phishing patterns"
        else:
            results['special_message'] = "✅ ML model analysis shows legitimate website"
            
    else:
        # STEP 6: If both ML models fail, use basic heuristic as final fallback
        fallback_heuristic = is_suspicious_heuristic(url)
        results['final_verdict'] = fallback_heuristic
        results['confidence'] = "🟡 MEDIUM CONFIDENCE - HEURISTIC FALLBACK"
        results['scan_method'] = 'heuristic_fallback'
        results['probability'] = 0.5
        results['class_label'] = 'phishing' if results['final_verdict'] else 'legitimate'
        results['special_message'] = "⚠️ Using basic heuristic analysis as final fallback"
    
    # STEP 7: Add trusted subdomain info if applicable (for non-Blogger trusted sites that passed all checks)
    if is_trusted and provider and not results.get('trusted_subdomain'):
        results['trusted_subdomain'] = True
        results['subdomain_provider'] = provider
        # Only add platform info if the site passed security checks
        if not results['final_verdict'] and results['special_message']:
            results['special_message'] += f" | Platform: {provider}"
    
    return results


# New functions for additional data extraction
def extract_contact_info(url):
    """Extract emails and phone numbers from the website"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, timeout=10, verify=False, headers=headers)
        content = response.text
        
        # Extract emails
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, content)
        
        # Extract phone numbers (international format)
        phone_pattern = r'(\+?\d{1,3}[-.\s]?)?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}'
        phones = re.findall(phone_pattern, content)
        phones = [phone[0] if isinstance(phone, tuple) else phone for phone in phones]
        phones = [p.strip() for p in phones if len(p.strip()) > 7]  # Filter out too short numbers
        
        # Find contact page URLs
        contact_patterns = [
            r'href=["\']([^"\']*contact[^"\']*)["\']',
            r'href=["\']([^"\']*about[^"\']*)["\']',
            r'href=["\']([^"\']*support[^"\']*)["\']'
        ]
        contact_urls = []
        for pattern in contact_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match.startswith('/'):
                    contact_urls.append(url.rstrip('/') + match)
                elif match.startswith('http'):
                    contact_urls.append(match)
        
        return {
            'emails': list(set(emails))[:10],  # Limit to 10 unique emails
            'phones': list(set(phones))[:10],  # Limit to 10 unique phones
            'contact_pages': list(set(contact_urls))[:5]  # Limit to 5 contact pages
        }
    except Exception as e:
        print(f"Error extracting contact info: {e}")
        return {'emails': [], 'phones': [], 'contact_pages': []}

def check_ssl_info(url):
    """Check SSL certificate information"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Check if SSL is valid
                ssl_status = cert is not None
                
                # Get expiry date
                ssl_expiry = None
                if cert and 'notAfter' in cert:
                    expiry_str = cert['notAfter']
                    expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                    ssl_expiry = expiry_date.isoformat()
                
                return {
                    'has_ssl': ssl_status,
                    'ssl_expiry': ssl_expiry
                }
    except Exception as e:
        print(f"Error checking SSL: {e}")
        return {'has_ssl': False, 'ssl_expiry': None}

# Use dnspython for comprehensive DNS checks

def get_domain_age(url):
    """Get domain registration age"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Remove www prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
            
        domain_info = whois.whois(domain)
        
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            return age_days
        else:
            return None
    except Exception as e:
        print(f"Error getting domain age: {e}")
        return None

def check_website_reachability(url):
    """Check if website is reachable and measure response time - IMPROVED"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Try multiple approaches
        start_time = time.time()
        
        # First try: HEAD request (faster)
        try:
            response = requests.head(url, timeout=10, verify=False, headers=headers, allow_redirects=True)
            end_time = time.time()
            response_time = round((end_time - start_time) * 1000, 2)
            
            if response.status_code < 400:
                return {
                    'reachable': True,
                    'status_code': response.status_code,
                    'response_time': response_time,
                    'method': 'HEAD'
                }
        except:
            pass
        
        # Second try: GET request with shorter timeout
        try:
            start_time = time.time()
            response = requests.get(url, timeout=8, verify=False, headers=headers, allow_redirects=True)
            end_time = time.time()
            response_time = round((end_time - start_time) * 1000, 2)
            
            return {
                'reachable': response.status_code < 400,
                'status_code': response.status_code,
                'response_time': response_time,
                'method': 'GET'
            }
        except requests.exceptions.Timeout:
            return {
                'reachable': False, 
                'status_code': None, 
                'response_time': None,
                'error': 'Request timeout'
            }
        except requests.exceptions.ConnectionError:
            return {
                'reachable': False, 
                'status_code': None, 
                'response_time': None,
                'error': 'Connection error'
            }
        except requests.exceptions.SSLError:
            # Try without SSL verification as fallback
            try:
                start_time = time.time()
                response = requests.get(url, timeout=8, verify=True, headers=headers, allow_redirects=True)
                end_time = time.time()
                response_time = round((end_time - start_time) * 1000, 2)
                
                return {
                    'reachable': response.status_code < 400,
                    'status_code': response.status_code,
                    'response_time': response_time,
                    'method': 'GET_SSL_FALLBACK'
                }
            except:
                return {
                    'reachable': False, 
                    'status_code': None, 
                    'response_time': None,
                    'error': 'SSL error'
                }
        except Exception as e:
            return {
                'reachable': False, 
                'status_code': None, 
                'response_time': None,
                'error': str(e)
            }
            
    except Exception as e:
        print(f"Error checking reachability: {e}")
        return {
            'reachable': False, 
            'status_code': None, 
            'response_time': None,
            'error': str(e)
        }
    
import dns.resolver  # Add this to your imports at the top

def get_dns_info(url):
    """Get comprehensive DNS information"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Remove www prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
        
        dns_results = {
            'A': [],
            'MX': [],
            'TXT': [],
            'NS': [],
            'resolved': False
        }
        
        # Check A records (IPv4)
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            dns_results['A'] = [str(record) for record in a_records]
            dns_results['resolved'] = True
        except:
            dns_results['A'] = []
        
        # Check MX records (Mail Exchange)
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            dns_results['MX'] = [str(record.exchange) for record in mx_records]
        except:
            dns_results['MX'] = []
        
        # Check TXT records
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            dns_results['TXT'] = [str(record) for record in txt_records]
        except:
            dns_results['TXT'] = []
        
        # Check NS records (Name Server)
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            dns_results['NS'] = [str(record) for record in ns_records]
        except:
            dns_results['NS'] = []
        
        return {'dns_records': dns_results}
        
    except Exception as e:
        print(f"Error getting DNS info: {e}")
        return {'dns_records': {'A': [], 'MX': [], 'TXT': [], 'NS': [], 'resolved': False}}

def get_threat_intelligence(url):
    """Get comprehensive threat intelligence data"""
    try:
        # First check if website is reachable
        reachability = check_website_reachability(url)
        if not reachability.get('reachable', False):
            # If website is unreachable, use heuristic as primary indicator
            is_heuristic_blacklisted = is_suspicious_heuristic(url)
            
            return {
                'safe_browsing': False,  # Can't check unreachable sites
                'blacklisted': is_heuristic_blacklisted,  # Use heuristic result
                'blacklist_score': 80 if is_heuristic_blacklisted else 0,
                'threat_types': [],
                'domain_age_days': None,
                'is_new_domain': False,
                'suspicious_tld': False,
                'heuristic_detected': is_heuristic_blacklisted,
                'website_reachable': False
            }
        
        # If website is reachable, proceed with normal checks
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Use Google Safe Browsing as primary threat intelligence
        safe_browsing_result = check_google_safe_browsing(url)
        
        # Enhanced blacklist checking using multiple heuristics
        is_heuristic_blacklisted = is_suspicious_heuristic(url)
        
        # Additional blacklist indicators
        domain_age = get_domain_age(url)
        is_new_domain = domain_age is not None and domain_age < 30  # Less than 30 days old
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        has_suspicious_tld = any(domain.endswith(tld) for tld in suspicious_tlds)
        
        # Combine threat indicators
        blacklist_score = 0
        if safe_browsing_result.get('is_threat', False):
            blacklist_score += 80
        if is_heuristic_blacklisted:
            blacklist_score += 40
        if is_new_domain:
            blacklist_score += 20
        if has_suspicious_tld:
            blacklist_score += 30
        
        # Determine if blacklisted based on score
        is_blacklisted = blacklist_score > 50
        
        return {
            'safe_browsing': safe_browsing_result.get('is_threat', False),
            'blacklisted': is_blacklisted,
            'blacklist_score': blacklist_score,
            'threat_types': safe_browsing_result.get('threat_types', []),
            'domain_age_days': domain_age,
            'is_new_domain': is_new_domain,
            'suspicious_tld': has_suspicious_tld,
            'heuristic_detected': is_heuristic_blacklisted,
            'website_reachable': True
        }
    except Exception as e:
        print(f"Error getting threat intelligence: {e}")
        # Fallback to heuristic check on error
        is_heuristic_blacklisted = is_suspicious_heuristic(url)
        return {
            'safe_browsing': False, 
            'blacklisted': is_heuristic_blacklisted,
            'blacklist_score': 80 if is_heuristic_blacklisted else 0,
            'threat_types': [],
            'domain_age_days': None,
            'is_new_domain': False,
            'suspicious_tld': False,
            'heuristic_detected': is_heuristic_blacklisted,
            'website_reachable': False
        }
# Add better error reporting
def check_google_safe_browsing_improved(url):
    result = check_google_safe_browsing(url)
    if not result.get('success'):
        return {'status': 'API Error', 'error': result.get('error')}
    return {'status': 'Threat' if result['is_threat'] else 'Clean'}    
def download_large_model():
    """Download large ML model from Google Drive if not exists"""
    model_path = 'models/ensemble_model.pkl'  # Adjust filename as needed
    google_drive_url = "https://drive.google.com/uc?id=1NM9GNh-qolCMTxk3B3ds-4zjGf8uqrex"
    
    if not os.path.exists(model_path):
        print("📥 Downloading large ML model from Google Drive...")
        try:
            # Create models directory if it doesn't exist
            os.makedirs('models', exist_ok=True)
            
            # Download using gdown (more reliable for Google Drive)
            gdown.download(google_drive_url, model_path, quiet=False)
            print("✅ Large model downloaded successfully!")
            
        except Exception as e:
            print(f"❌ Failed to download model: {e}")
            # Fallback to requests
            try:
                response = requests.get(f"https://drive.google.com/uc?export=download&id=1NM9GNh-qolCMTxk3Bds-4zjGf8uqrex")
                with open(model_path, 'wb') as f:
                    f.write(response.content)
                print("✅ Large model downloaded via fallback method!")
            except Exception as e2:
                print(f"❌ Fallback download also failed: {e2}")
    else:
        print("✅ Large model already exists!")

# Call this function before loading models
download_large_model()    
# Load both models
MODEL_PATHS = {
    'original': 'models/phishing_model.pkl',
    'ensemble': 'models/ensemble_model.pkl'
}

# Initialize global variables
models_loaded = {}
feature_names = {}
threat_intelligence = {}

# Load original model
if os.path.exists(MODEL_PATHS['original']):
    try:
        with open(MODEL_PATHS['original'], 'rb') as f:
            data = pickle.load(f)
        models_loaded['original'] = data['model']
        feature_names['original'] = data['feature_names']
        print("✓ Original model loaded")
    except Exception as e:
        print(f"❌ Error loading original model: {e}")

# Load ensemble model (if available)
if os.path.exists(MODEL_PATHS['ensemble']):
    try:
        model_data = joblib.load(MODEL_PATHS['ensemble'])
        models_loaded['ensemble'] = model_data['ensemble_model']
        feature_names['ensemble'] = model_data['feature_names']
        threat_intelligence = model_data.get('threat_intelligence', {})
        print("✓ Ensemble model loaded")
        print("✓ Threat intelligence loaded")
        print("Ensemble model ready - debug function available")
    except Exception as e:
        print(f"❌ Error loading ensemble model: {e}")
else:
    print("ℹ️  Ensemble model not found. Using original model only.")

# Add the missing index route
@app.route('/')
def index():
    """Main page - no authentication required"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_url():
    """Scan URL - no authentication required"""
    if not models_loaded:
        return jsonify({
            'error': 'No models loaded. Please train the model first.'
        }), 500

    data = request.get_json()
    url_input = data.get('url', '').strip()

    if not url_input:
        return jsonify({'error': 'URL is required'}), 400

    try:
        # Add protocol if missing for validation
        test_url = url_input
        if not url_input.startswith(('http://', 'https://')):
            test_url = 'https://' + url_input

        # Validate URL before processing
        if not is_valid_url(test_url):
            return jsonify({
                'error': 'Invalid URL format. Please enter a valid website address (e.g., example.com or https://example.com)'
            }), 400

        # Use the validated URL
        url = test_url

        # Check if it's a trusted subdomain first
        is_trusted, provider = is_trusted_subdomain(url)

        # Extract features for ML fallback
        features = extract_basic_url_features(url)

        # Perform hybrid scanning
        try:
            scan_results = hybrid_scan_url(url, features)
            print(f"🔍 SCAN RESULTS - Method: {scan_results.get('scan_method', 'unknown')}, Verdict: {scan_results.get('final_verdict', 'unknown')}")
        except Exception as scan_error:
            print(f"❌ Hybrid scan failed: {scan_error}")
            scan_results = {
                'final_verdict': False,
                'confidence': 0,
                'scan_method': 'fallback',
                'error': str(scan_error)
            }

        # Get screenshot data
        screenshot_response = {}
        image_analysis_result = {}

        try:
            screenshot_data = get_screenshot_data(url)
            print(f"🔍 DEBUG - Screenshot data received: {screenshot_data}")

            if screenshot_data.get('success') or screenshot_data.get('filename'):
                screenshot_filename = screenshot_data.get('filename')
                if screenshot_filename:
                    screenshot_response['url'] = f"/static/screenshots/{screenshot_filename}"
                    screenshot_response['success'] = True

                    # Image analysis
                    screenshot_path = os.path.join('static', 'screenshots', screenshot_filename)
                    try:
                        print(f"🖼️ Analyzing screenshot with image model: {screenshot_path}")
                        image_analysis = analyze_website_screenshot(screenshot_path)
                        image_analysis_result = image_analysis
                        print(f"🖼️ Image analysis result: {image_analysis}")
                    except Exception as img_error:
                        print(f"❌ Image analysis failed: {img_error}")
                        image_analysis_result = {'error': str(img_error)}
            else:
                if screenshot_data.get('filename'):
                    screenshot_filename = screenshot_data.get('filename')
                    screenshot_path = os.path.join('static', 'screenshots', screenshot_filename)
                    if os.path.exists(screenshot_path):
                        screenshot_response['url'] = f"/static/screenshots/{screenshot_filename}"
                        screenshot_response['success'] = True
                        print(f"✅ Using screenshot despite API error: {screenshot_filename}")
                    else:
                        screenshot_response['url'] = None
                        screenshot_response['error'] = screenshot_data.get('error', 'Unknown error')
                        screenshot_response['success'] = False
                else:
                    screenshot_response['url'] = None
                    screenshot_response['error'] = screenshot_data.get('error', 'Unknown error')
                    screenshot_response['success'] = False

        except Exception as screenshot_error:
            print(f"❌ Screenshot capture failed: {screenshot_error}")
            screenshot_response = {
                'url': None,
                'error': str(screenshot_error),
                'success': False
            }

        # Extract analysis data
        contact_info = extract_contact_info(url)
        ssl_info = check_ssl_info(url)
        dns_info = get_dns_info(url)
        domain_age = get_domain_age(url)
        reachability = check_website_reachability(url)
        threat_intel = get_threat_intelligence(url)

        # Prepare response
        final_verdict = scan_results.get('final_verdict', False)
        final_confidence = scan_results.get('confidence', 0)
        final_method = scan_results.get('scan_method', 'fallback')
        probability = scan_results.get('probability', 0)

        result = {
            'url': url_input,
            'is_phishing': final_verdict,
            'probability': probability,
            'confidence': final_confidence,
            'scan_method': final_method,
            'trusted_subdomain': is_trusted,
            'subdomain_provider': provider,
            'image_analysis': image_analysis_result,
            'contacts_found': {
                'emails': contact_info['emails'],
                'phones': contact_info['phones'],
                'contact_pages': contact_info['contact_pages']
            },
            'features': {
                'has_ssl': ssl_info['has_ssl'],
                'ssl_expiry': ssl_info['ssl_expiry'],
                'dns_records': dns_info['dns_records'],
                'domain_age': domain_age,
                'reachable': reachability['reachable'],
                'response_time': reachability['response_time'],
                'reachability_error': reachability.get('error'),
                'reachability_method': reachability.get('method')
            },
            'threat_intel': {
                'safe_browsing': threat_intel['safe_browsing'],
                'blacklisted': threat_intel['blacklisted']
            },
            'screenshot': screenshot_response
        }

        # Add method-specific messages
        if final_method == 'google_safe_browsing':
            result['special_message'] = "⚠️ Google Safe Browsing detected threats"
        elif final_method == 'ml_model':
            result['model_used'] = scan_results.get('model_used', 'unknown')
            if final_verdict:
                result['special_message'] = "⚠️ ML model detected phishing patterns"
            else:
                result['special_message'] = "✅ ML model analysis shows no phishing patterns"
        elif final_method == 'heuristic':
            if final_verdict:
                result['special_message'] = "⚠️ Heuristic analysis detected suspicious patterns"
            else:
                result['special_message'] = "✅ Heuristic analysis shows no obvious phishing patterns"
        else:
            result['special_message'] = "🔍 Basic analysis completed"

        print(f"🔍 FINAL RESULT - URL: {url_input}")
        print(f"🔍 FINAL RESULT - Method: {final_method}")
        print(f"🔍 FINAL RESULT - Verdict: {'PHISHING' if final_verdict else 'LEGITIMATE'}")

        return jsonify(result)

    except Exception as e:
        print(f"❌ CRITICAL ERROR: {e}")
        return jsonify({'error': f'Error processing URL: {str(e)}'}), 500

# [KEEP YOUR OTHER ROUTES - analyze-image, api/scan, serve_screenshot]

if __name__ == '__main__':
    print("🚀 Starting Flask Phishing Detector Server...")
    print("📍 Local: http://127.0.0.1:5000")
    try:
        app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        app.run(debug=True, host='0.0.0.0', port=5001, use_reloader=False)







