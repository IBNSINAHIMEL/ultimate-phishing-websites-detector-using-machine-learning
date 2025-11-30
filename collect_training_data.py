import os
import pandas as pd
import time
from screenshot_capture import capture_website_screenshot
import requests

def collect_phishing_samples(phishing_urls_file, output_dir, max_samples=500):
    """Collect phishing website screenshots"""
    os.makedirs(output_dir, exist_ok=True)
    
    # Example phishing URLs - you can expand this list
    phishing_urls = [
        "http://paypa1-security.com",
        "http://faceb00k-login.net", 
        "http://google-verify-account.com",
        "http://microsoft-security-update.com",
        "http://apple-id-verify.net",
        "http://amazon-account-security.com",
        "http://netflix-billing-update.com",
        "http://bankofamerica-secure-login.com",
        "http://wellsfargo-online-banking.com",
        "http://chase-account-alert.com"
    ]
    
    # Or load from file if you have one
    if os.path.exists(phishing_urls_file):
        df = pd.read_csv(phishing_urls_file)
        phishing_urls = df['url'].tolist()[:max_samples]
    
    collected = 0
    for i, url in enumerate(phishing_urls[:max_samples]):
        try:
            print(f"📸 Capturing phishing {i+1}/{len(phishing_urls)}: {url}")
            result = capture_website_screenshot(url)
            
            if result and 'filename' in result:
                # Move screenshot to phishing folder
                old_path = os.path.join('static/screenshots', result['filename'])
                new_filename = f"phishing_{i:04d}.png"
                new_path = os.path.join(output_dir, new_filename)
                
                if os.path.exists(old_path):
                    os.rename(old_path, new_path)
                    collected += 1
                    print(f"✅ Saved: {new_filename}")
                else:
                    print(f"❌ File not found: {old_path}")
            else:
                print(f"❌ Failed to capture: {url}")
            
            time.sleep(2)  # Be respectful
            
        except Exception as e:
            print(f"❌ Error with {url}: {e}")
    
    print(f"🎯 Collected {collected} phishing samples")
    return collected

def collect_legitimate_samples(legitimate_urls_file, output_dir, max_samples=500):
    """Collect legitimate website screenshots"""
    os.makedirs(output_dir, exist_ok=True)
    
    # Legitimate URLs
    legitimate_urls = [
        "https://www.paypal.com",
        "https://www.facebook.com",
        "https://www.google.com",
        "https://www.microsoft.com",
        "https://www.apple.com",
        "https://www.amazon.com",
        "https://www.netflix.com",
        "https://www.github.com",
        "https://www.stackoverflow.com",
        "https://www.wikipedia.org",
        "https://www.reddit.com",
        "https://www.twitter.com",
        "https://www.instagram.com",
        "https://www.linkedin.com",
        "https://www.youtube.com"
    ]
    
    # Expand with more legitimate sites
    more_legitimate = [
        "https://www.ebay.com", "https://www.etsy.com", "https://www.booking.com",
        "https://www.airbnb.com", "https://www.spotify.com", "https://www.dropbox.com",
        "https://www.slack.com", "https://www.notion.so", "https://www.figma.com",
        "https://www.adobe.com", "https://www.ibm.com", "https://www.intel.com"
    ]
    legitimate_urls.extend(more_legitimate)
    
    collected = 0
    for i, url in enumerate(legitimate_urls[:max_samples]):
        try:
            print(f"📸 Capturing legitimate {i+1}/{len(legitimate_urls)}: {url}")
            result = capture_website_screenshot(url)
            
            if result and 'filename' in result:
                # Move screenshot to legitimate folder
                old_path = os.path.join('static/screenshots', result['filename'])
                new_filename = f"legitimate_{i:04d}.png"
                new_path = os.path.join(output_dir, new_filename)
                
                if os.path.exists(old_path):
                    os.rename(old_path, new_path)
                    collected += 1
                    print(f"✅ Saved: {new_filename}")
                else:
                    print(f"❌ File not found: {old_path}")
            else:
                print(f"❌ Failed to capture: {url}")
            
            time.sleep(2)  # Be respectful
            
        except Exception as e:
            print(f"❌ Error with {url}: {e}")
    
    print(f"🎯 Collected {collected} legitimate samples")
    return collected

if __name__ == "__main__":
    # Create directories
    os.makedirs("data/images/phishing", exist_ok=True)
    os.makedirs("data/images/legitimate", exist_ok=True)
    
    print("🚀 Starting data collection...")
    
    # Collect samples
    phishing_count = collect_phishing_samples(
        "phishing_urls.csv", 
        "data/images/phishing", 
        max_samples=100  # Start with 100 each
    )
    
    legitimate_count = collect_legitimate_samples(
        "legitimate_urls.csv",
        "data/images/legitimate", 
        max_samples=100
    )
    
    print(f"\n📊 Collection Complete:")
    print(f"   Phishing samples: {phishing_count}")
    print(f"   Legitimate samples: {legitimate_count}")
    print(f"   Total: {phishing_count + legitimate_count}")