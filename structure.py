import os

def check_data_structure(data_dir="data/images"):
    print("🔍 Checking data structure...")
    
    if not os.path.exists(data_dir):
        print(f"❌ Data directory not found: {data_dir}")
        return
    
    for class_name in ['phishing', 'legitimate']:
        class_path = os.path.join(data_dir, class_name)
        if os.path.exists(class_path):
            # Count all image files
            image_files = [f for f in os.listdir(class_path) 
                         if f.lower().endswith(('.png', '.jpg', '.jpeg'))]
            print(f"📁 {class_name}: {len(image_files)} images")
            
            # Show first few files
            if image_files:
                print(f"   Sample files: {image_files[:3]}")
        else:
            print(f"❌ Class folder not found: {class_path}")

# Run the check
check_data_structure()