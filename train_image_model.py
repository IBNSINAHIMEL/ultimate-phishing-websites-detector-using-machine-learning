# train_image_model.py
import os
import tensorflow as tf
from image_preprocessing import ImagePreprocessor
from image_model import PhishingImageModel

def setup_directories():
    """Create necessary directories"""
    os.makedirs("models", exist_ok=True)
    os.makedirs("training_history", exist_ok=True)

def train_with_small_dataset():
    print("🚀 Starting phishing image classification training...")
    
    # Setup
    setup_directories()
    
    # Initialize preprocessor and model
    preprocessor = ImagePreprocessor(target_size=(224, 224))
    model = PhishingImageModel(input_shape=(224, 224, 3))
    
    # Load and prepare data
    print("📦 Loading and augmenting dataset...")
    train_generator, val_generator = preprocessor.load_dataset(
        "data/images", 
        batch_size=8
    )
    
    print(f"📊 Training samples: {train_generator.samples}")
    print(f"📊 Validation samples: {val_generator.samples}")
    
    # Create and compile model
    print("🧠 Building model...")
    model.create_small_dataset_model()
    model.compile_for_small_data(learning_rate=0.0001)
    
    # Show model architecture
    print("📋 Model summary:")
    model.model.summary()
    
    # Train model
    print("🎯 Training model...")
    history = model.train_with_early_stopping(
        train_generator, 
        val_generator, 
        epochs=50
    )
    
    # Save model (FIXED)
    model_save_path = "models/phishing_detector.h5"
    if hasattr(model, 'save_model'):
        model.save_model(model_save_path)
    else:
        # Fallback if save_model method doesn't exist
        model.model.save(model_save_path)
        print(f"✅ Model saved to {model_save_path}")
    
    # Evaluate final performance
    print("📊 Evaluating final model performance...")
    val_loss, val_accuracy, val_precision, val_recall = model.model.evaluate(val_generator)
    
    print("\n🎉 Training Completed!")
    print(f"✅ Final Validation Accuracy: {val_accuracy:.2%}")
    print(f"✅ Final Validation Precision: {val_precision:.2%}")
    print(f"✅ Final Validation Recall: {val_recall:.2%}")
    
    # Save training history
    try:
        import json
        history_path = "training_history/training_history.json"
        with open(history_path, 'w') as f:
            json.dump(history.history, f)
        print(f"📈 Training history saved to {history_path}")
    except Exception as e:
        print(f"⚠️ Could not save training history: {e}")
    
    return history

if __name__ == "__main__":
    # Set TensorFlow log level to reduce warnings
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
    tf.get_logger().setLevel('ERROR')
    
    train_with_small_dataset()