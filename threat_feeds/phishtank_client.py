import requests
import pandas as pd
import time
import os
from datetime import datetime, timedelta

class PhishTankClient:
    def __init__(self, api_key=None, cache_duration_hours=1):
        self.api_url = "http://data.phishtank.com/data/online-valid.json"
        self.api_key = api_key
        self.cache_file = "threat_feeds/phishtank_cache.json"
        self.cache_duration = timedelta(hours=cache_duration_hours)
        
    def fetch_phishing_urls(self):
        """Fetch phishing URLs from PhishTank"""
        try:
            # Check cache first
            if self._is_cache_valid():
                return self._load_from_cache()
            
            print("Fetching latest PhishTank data...")
            headers = {}
            if self.api_key:
                headers['Authorization'] = f'Bearer {self.api_key}'
            
            response = requests.get(self.api_url, headers=headers, timeout=15)
            response.raise_for_status()
            
            data = response.json()
            urls = []
            
            for item in data:
                urls.append({
                    'url': item.get('url', ''),
                    'phish_id': item.get('phish_id', ''),
                    'submission_time': item.get('submission_time', ''),
                    'verified': item.get('verified', 'no'),
                    'verification_time': item.get('verification_time', ''),
                    'online': item.get('online', 'no'),
                    'target': item.get('target', ''),
                    'source': 'phishtank',
                    'label': 1,  # phishing
                    'timestamp': datetime.now().isoformat()
                })
            
            # Filter only verified and online phishing URLs
            verified_urls = [u for u in urls if u.get('verified') == 'yes' and u.get('online') == 'yes']
            
            # Save to cache
            self._save_to_cache(verified_urls)
            print(f"Fetched {len(verified_urls)} verified URLs from PhishTank")
            return verified_urls
            
        except Exception as e:
            print(f"Error fetching PhishTank data: {e}")
            return self._load_from_cache()
    
    def _is_cache_valid(self):
        """Check if cache is still valid"""
        if not os.path.exists(self.cache_file):
            return False
        
        file_time = datetime.fromtimestamp(os.path.getmtime(self.cache_file))
        return datetime.now() - file_time < self.cache_duration
    
    def _load_from_cache(self):
        """Load data from cache"""
        try:
            df = pd.read_json(self.cache_file)
            print(f"Loaded {len(df)} URLs from PhishTank cache")
            return df.to_dict('records')
        except:
            return []
    
    def _save_to_cache(self, urls):
        """Save data to cache"""
        os.makedirs('threat_feeds', exist_ok=True)
        df = pd.DataFrame(urls)
        df.to_json(self.cache_file, orient='records')