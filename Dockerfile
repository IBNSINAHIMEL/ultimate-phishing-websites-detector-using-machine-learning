FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy all application code
COPY . .

# Create directories for models and outputs
RUN mkdir -p models static/screenshots static/uploads

# 🔥 DOWNLOAD LARGE MODEL DURING IMAGE BUILD
RUN python download_model.py

# Expose port
EXPOSE 5000

# Start the application
CMD ["python", "app.py"]
