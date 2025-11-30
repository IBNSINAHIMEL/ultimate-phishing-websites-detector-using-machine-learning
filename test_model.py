# test_model.py
import numpy as np
import tensorflow as tf
from image_model import PhishingImageModel
from image_preprocessing import ImagePreprocessor

def test_single_image(image_path):
    """Test the trained model on a single image"""
    try:
        # Load your trained model
        model = PhishingImageModel()
        model.model = tf.keras.models.load_model('models/phishing_detector.h5')
        
        # Create preprocessor and load image
        preprocessor = ImagePreprocessor()
        test_image = preprocessor.load_and_preprocess_image(image_path)
        
        if test_image is not None:
            # Make prediction
            prediction = model.model.predict(np.expand_dims(test_image, axis=0))
            confidence = prediction[0][0]
            
            if confidence > 0.5:
                print(f"🚨 Phishing detected! Confidence: {confidence:.2%}")
                return "phishing", confidence
            else:
                print(f"✅ Legitimate website. Confidence: {(1-confidence):.2%}")
                return "legitimate", (1-confidence)
        else:
            print("❌ Failed to load or preprocess the image")
            return "error", 0.0
            
    except Exception as e:
        print(f"❌ Error during prediction: {e}")
        return "error", 0.0

def test_multiple_images(image_folder):
    """Test the model on multiple images in a folder"""
    import os
    
    model = PhishingImageModel()
    model.model = tf.keras.models.load_model('models/phishing_detector.h5')
    preprocessor = ImagePreprocessor()
    
    results = []
    
    # Test on legitimate images
    legit_folder = os.path.join(image_folder, "legitimate")
    if os.path.exists(legit_folder):
        legit_files = [f for f in os.listdir(legit_folder) if f.endswith(('.png', '.jpg', '.jpeg'))]
        print(f"📁 Found {len(legit_files)} legitimate images")
        
        for image_file in legit_files[:3]:  # Test first 3
            image_path = os.path.join(legit_folder, image_file)
            test_image = preprocessor.load_and_preprocess_image(image_path)
            
            if test_image is not None:
                prediction = model.model.predict(np.expand_dims(test_image, axis=0))
                confidence = prediction[0][0]
                results.append(("legitimate", confidence, image_file))
                print(f"  - Tested: {image_file}")
    
    # Test on phishing images
    phishing_folder = os.path.join(image_folder, "phishing")
    if os.path.exists(phishing_folder):
        phishing_files = [f for f in os.listdir(phishing_folder) if f.endswith(('.png', '.jpg', '.jpeg'))]
        print(f"📁 Found {len(phishing_files)} phishing images")
        
        for image_file in phishing_files[:3]:  # Test first 3
            image_path = os.path.join(phishing_folder, image_file)
            test_image = preprocessor.load_and_preprocess_image(image_path)
            
            if test_image is not None:
                prediction = model.model.predict(np.expand_dims(test_image, axis=0))
                confidence = prediction[0][0]
                results.append(("phishing", confidence, image_file))
                print(f"  - Tested: {image_file}")
    
    # Print results
    print("\n📊 Model Test Results:")
    print("=" * 60)
    
    correct_predictions = 0
    total_predictions = len(results)
    
    for true_label, confidence, filename in results:
        predicted_label = "phishing" if confidence > 0.5 else "legitimate"
        is_correct = predicted_label == true_label
        correct_predictions += 1 if is_correct else 0
        
        status = "✅" if is_correct else "❌"
        print(f"{status} {filename}")
        print(f"    True: {true_label:12} | Predicted: {predicted_label:12} | Confidence: {confidence:.2%}")
        print()
    
    accuracy = correct_predictions / total_predictions if total_predictions > 0 else 0
    print(f"🎯 Overall Accuracy: {accuracy:.2%} ({correct_predictions}/{total_predictions} correct)")
    
    return results

if __name__ == "__main__":
    print("🧪 Testing Phishing Detection Model...")
    print("=" * 50)
    
    # Test multiple images from your dataset
    results = test_multiple_images("data/images")
    
    print("\n🎉 Testing completed!")