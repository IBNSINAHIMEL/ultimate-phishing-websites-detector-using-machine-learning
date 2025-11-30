import requests
import pandas as pd
import time
import os
from datetime import datetime, timedelta

class OpenPhishClient:
    def __init__(self, cache_duration_hours=1):
        self.feed_url = "https://openphish.com/feed.txt"
        self.cache_file = "threat_feeds/openphish_cache.json"
        self.cache_duration = timedelta(hours=cache_duration_hours)
        
    def fetch_phishing_urls(self):
        """Fetch phishing URLs from OpenPhish feed"""
        try:
            # Check cache first
            if self._is_cache_valid():
                return self._load_from_cache()
            
            print("Fetching latest OpenPhish data...")
            response = requests.get(self.feed_url, timeout=10)
            response.raise_for_status()
            
            urls = []
            for line in response.text.strip().split('\n'):
                if line and not line.startswith('#'):
                    urls.append({
                        'url': line.strip(),
                        'source': 'openphish',
                        'label': 1,  # phishing
                        'timestamp': datetime.now().isoformat()
                    })
            
            # Save to cache
            self._save_to_cache(urls)
            print(f"Fetched {len(urls)} URLs from OpenPhish")
            return urls
            
        except Exception as e:
            print(f"Error fetching OpenPhish data: {e}")
            return self._load_from_cache()  # Return cached data if available
    
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
            print(f"Loaded {len(df)} URLs from OpenPhish cache")
            return df.to_dict('records')
        except:
            return []
    
    def _save_to_cache(self, urls):
        """Save data to cache"""
        os.makedirs('threat_feeds', exist_ok=True)
        df = pd.DataFrame(urls)
        df.to_json(self.cache_file, orient='records')