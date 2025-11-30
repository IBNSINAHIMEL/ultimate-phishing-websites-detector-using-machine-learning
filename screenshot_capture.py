import requests
import hashlib
import os
from datetime import datetime
from urllib.parse import urlparse
import logging
from PIL import Image  # ✅ ADD THIS IMPORT

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ScreenshotCapture:
    def __init__(self, api_key=None):
        """
        Initialize Screenshot Machine API capture
        """
        self.api_key = api_key or "469eb"  # Your API key
        self.base_url = "https://api.screenshotmachine.com"
        self.screenshot_dir = "static/screenshots"
        
        # Create screenshots directory if it doesn't exist
        os.makedirs(self.screenshot_dir, exist_ok=True)
    
    def capture_screenshot(self, url, dimension="1024x768", device="desktop", 
                          format="PNG", delay=5000, cache_limit=0):
        """
        Capture screenshot using Screenshot Machine API - IMPROVED
        
        Args:
            url (str): Website URL to capture
            dimension (str): Screenshot dimensions (default: 1024x768)
            device (str): Device type - desktop, tablet, mobile
            format (str): Image format - PNG, JPG
            delay (int): Page load delay in milliseconds (INCREASED for better rendering)
            cache_limit (int): Cache limit in seconds (0 = no cache)
        
        Returns:
            dict: Contains 'filename', 'url', or 'error'
        """
        try:
            # Validate and clean URL
            cleaned_url = self._clean_url(url)
            if not cleaned_url:
                logger.error(f"Invalid URL: {url}")
                return {'error': 'Invalid URL format'}
            
            # Generate unique filename
            filename = self._generate_filename(cleaned_url)
            screenshot_path = os.path.join(self.screenshot_dir, filename)
            
            # API parameters - WITH INCREASED DELAY FOR BETTER RENDERING
            params = {
                'key': self.api_key,
                'url': cleaned_url,
                'dimension': dimension,
                'delay': delay,  # Increased to 5 seconds for complex pages
                'cacheLimit': cache_limit
            }
            
            # Add device parameter if specified (for mobile/tablet views)
            if device != 'desktop':
                params['device'] = device
            
            logger.info(f"Capturing screenshot for: {cleaned_url} with {delay}ms delay")
            
            # Make API request with longer timeout
            response = requests.get(
                self.base_url, 
                params=params, 
                stream=True, 
                timeout=45  # Increased timeout for slow websites
            )
            
            if response.status_code == 200:
                # Save the screenshot
                with open(screenshot_path, 'wb') as f:
                    for chunk in response.iter_content(8192):  # Increased chunk size
                        f.write(chunk)
                
                # Verify the file was created successfully and is valid
                if self._validate_screenshot(screenshot_path):
                    logger.info(f"✓ Screenshot saved and validated: {screenshot_path}")
                    return {
                        'filename': filename,
                        'url': f"/static/screenshots/{filename}",
                        'success': True,
                        'file_size': os.path.getsize(screenshot_path)
                    }
                else:
                    logger.error("Screenshot file is corrupted or invalid")
                    # Clean up corrupted file
                    if os.path.exists(screenshot_path):
                        os.remove(screenshot_path)
                    return {'error': 'Screenshot file is corrupted or invalid'}
                    
            else:
                logger.error(f"API Error {response.status_code}: {response.text}")
                return {'error': f'API returned status {response.status_code}'}
                
        except requests.exceptions.Timeout:
            logger.error(f"Timeout capturing screenshot for {url}")
            return {'error': 'Screenshot capture timed out (45s)'}
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error capturing {url}: {e}")
            return {'error': f'Network error: {str(e)}'}
        except Exception as e:
            logger.error(f"Unexpected error capturing {url}: {e}")
            return {'error': f'Unexpected error: {str(e)}'}
    
    def capture_screenshot_retry(self, url, max_retries=2, initial_delay=3000):
        """
        Capture screenshot with retry logic for better reliability
        """
        delays = [initial_delay, 5000, 8000]  # Progressive delays: 3s, 5s, 8s
        
        for attempt in range(max_retries):
            try:
                delay = delays[attempt] if attempt < len(delays) else delays[-1]
                logger.info(f"Attempt {attempt + 1} with {delay}ms delay")
                
                result = self.capture_screenshot(url, delay=delay)
                
                if 'error' not in result:
                    return result
                else:
                    logger.warning(f"Attempt {attempt + 1} failed: {result['error']}")
                    
            except Exception as e:
                logger.warning(f"Attempt {attempt + 1} exception: {e}")
        
        # All attempts failed
        return {'error': f'All {max_retries} attempts failed to capture screenshot'}
    
    def _validate_screenshot(self, file_path):
        """
        Validate that the screenshot file is not corrupted
        """
        try:
            if not os.path.exists(file_path):
                return False
            
            file_size = os.path.getsize(file_path)
            if file_size < 1024:  # Less than 1KB is likely corrupted
                return False
            
            # Try to open with PIL to validate image integrity
            try:
                with Image.open(file_path) as img:  # ✅ Now Image is defined
                    img.verify()  # Verify it's a valid image
                
                # Reopen for format check
                with Image.open(file_path) as img:  # ✅ Now Image is defined
                    if img.size[0] < 100 or img.size[1] < 100:  # Too small
                        return False
                    
                    return True
            except Exception as e:
                logger.warning(f"Image validation failed: {e}")
                return False
                
        except Exception as e:
            logger.warning(f"Screenshot validation error: {e}")
            return False
    
    def _clean_url(self, url):
        """Clean and validate URL"""
        if not url:
            return None
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        try:
            # Validate URL format
            parsed = urlparse(url)
            if not parsed.netloc:
                return None
            return url
        except Exception:
            return None
    
    def _generate_filename(self, url):
        """Generate unique filename for screenshot"""
        url_hash = hashlib.md5(url.encode()).hexdigest()[:10]
        timestamp = int(datetime.now().timestamp())
        return f"screenshot_{url_hash}_{timestamp}.png"

# Singleton instance for easy import
screenshot_capturer = ScreenshotCapture()

def get_screenshot_data(url):
    """
    Main function to get screenshot data - IMPROVED with retry logic
    
    Args:
        url (str): URL to capture
        
    Returns:
        dict: Contains 'url', 'filename', or 'error'
    """
    # Use retry logic for better reliability
    result = screenshot_capturer.capture_screenshot_retry(url, max_retries=2)
    
    # Ensure the return format matches what your Flask app expects
    if 'error' in result:
        return {
            'error': result['error'],
            'note': 'Screenshot unavailable - website may be blocking screenshots or taking too long to load'
        }
    else:
        return {
            'filename': result['filename'],
            'url': result['url'],
            'file_size': result.get('file_size', 0)
        }

def cleanup_screenshot_capture():
    """Cleanup function for atexit registration"""
    try:
        # Clean up screenshots older than 24 hours
        current_time = datetime.now().timestamp()
        max_age_seconds = 24 * 3600
        
        for filename in os.listdir(screenshot_capturer.screenshot_dir):
            if filename.startswith("screenshot_") and filename.endswith(".png"):
                file_path = os.path.join(screenshot_capturer.screenshot_dir, filename)
                file_age = current_time - os.path.getctime(file_path)
                
                if file_age > max_age_seconds:
                    os.remove(file_path)
                    logger.info(f"Removed old screenshot: {filename}")
                        
    except Exception as e:
        logger.error(f"Screenshot cleanup error: {e}")

# Convenience function
def capture_website_screenshot(url, dimension="1024x768"):
    """Convenience function to capture single screenshot"""
    return screenshot_capturer.capture_screenshot(url, dimension=dimension)