import tensorflow as tf
from tensorflow.keras import layers, models
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.applications import MobileNetV2
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau

class PhishingImageModel:
    def __init__(self, input_shape=(224, 224, 3)):
        self.input_shape = input_shape
        self.model = None
    
    def create_small_dataset_model(self):
        """Optimized model for small datasets"""
        # Use MobileNetV2 - lighter and better for small datasets
        base_model = MobileNetV2(
            weights='imagenet',
            include_top=False,
            input_shape=self.input_shape
        )
        
        # Freeze base model completely for small datasets
        base_model.trainable = False
        
        self.model = models.Sequential([
            base_model,
            layers.GlobalAveragePooling2D(),
            layers.Dropout(0.5),  # Higher dropout for small dataset
            layers.Dense(64, activation='relu'),  # Smaller dense layer
            layers.Dropout(0.3),
            layers.Dense(1, activation='sigmoid')
        ])
        
        return self.model
    
    def compile_for_small_data(self, learning_rate=0.0001):
        """Compile with settings optimized for small datasets"""
        self.model.compile(
            optimizer=Adam(learning_rate=learning_rate),
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
    
    def save_model(self, filepath):
        """Save the trained model"""
        if self.model:
            self.model.save(filepath)
            print(f"✅ Model saved to {filepath}")
        else:
            print("❌ No model to save")
    
    def train_with_early_stopping(self, train_generator, validation_generator, epochs=50):
        """Train with early stopping to prevent overfitting"""
        callbacks = [
            EarlyStopping(
                monitor='val_loss',
                patience=10,
                restore_best_weights=True
            ),
            ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=5,
                min_lr=0.00001
            )
        ]
        
        history = self.model.fit(
            train_generator,
            epochs=epochs,
            validation_data=validation_generator,
            callbacks=callbacks,
            verbose=1
        )
        
        return history