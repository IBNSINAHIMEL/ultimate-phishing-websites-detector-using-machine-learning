# image_preprocessing.py
import os
import cv2
import numpy as np
from PIL import Image  # ← ADD THIS IMPORT
import tensorflow as tf
from tensorflow.keras.preprocessing.image import ImageDataGenerator
import matplotlib.pyplot as plt

class ImagePreprocessor:
    def __init__(self, target_size=(224, 224)):
        self.target_size = target_size

    def load_and_preprocess_image(self, image_path):
        """Load and preprocess a single image of any size"""
        try:
            # Load image (can be any size)
            image = Image.open(image_path)

            # Convert to RGB if necessary
            if image.mode != 'RGB':
                image = image.convert('RGB')

            # Resize image to target size
            image = image.resize(self.target_size)
            
            # Convert to numpy array and normalize
            image_array = np.array(image) / 255.0
            
            return image_array
        except Exception as e:
            print(f"Error loading image {image_path}: {e}")
            return None

    def create_heavy_augmentation_generator(self):
        """Create heavy augmentation for small dataset"""
        return ImageDataGenerator(
            rescale=1./255,
            rotation_range=40,
            width_shift_range=0.3,
            height_shift_range=0.3,
            shear_range=0.3,
            zoom_range=0.3,
            horizontal_flip=True,
            vertical_flip=True,
            brightness_range=[0.7, 1.3],
            channel_shift_range=0.2,
            fill_mode='nearest',
            validation_split=0.2
        )
    
    def load_dataset(self, data_dir, batch_size=16):
        """Load and augment dataset"""
        datagen = self.create_heavy_augmentation_generator()
        
        train_generator = datagen.flow_from_directory(
            data_dir,
            target_size=self.target_size,
            batch_size=batch_size,
            class_mode='binary',
            subset='training',
            shuffle=True
        )
        
        validation_generator = datagen.flow_from_directory(
            data_dir,
            target_size=self.target_size,
            batch_size=batch_size,
            class_mode='binary',
            subset='validation',
            shuffle=True
        )
        
        return train_generator, validation_generator