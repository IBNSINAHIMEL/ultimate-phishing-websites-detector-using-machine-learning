import gdown
import os

url = "https://drive.google.com/uc?export=download&id=1NM9GNh-qolCMTxk3B3ds-4zjGf8uqrex"
path = "models/ensemble_model.pkl"

os.makedirs("models", exist_ok=True)
gdown.download(url, path, quiet=False)
print("Downloaded to:", os.path.abspath(path))
