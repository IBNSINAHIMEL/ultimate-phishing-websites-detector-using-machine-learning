from image_model import PhishingImageClassifier
from image_preprocessing import ImagePreprocessor

# Load trained model
classifier = PhishingImageClassifier()
classifier.load_model('models/phishing_image_model.h5')

preprocessor = ImagePreprocessor()

# Test on a new screenshot
result = classifier.predict_image('static/screenshots/your_screenshot.png', preprocessor)
print(f"Prediction: {result}")