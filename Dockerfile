FROM python:3.11-slim
WORKDIR /app

RUN apt-get update && apt-get install -y gcc g++ curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p models static/screenshots static/uploads

EXPOSE 5000

# Start app (model downloads if missing)
CMD ["python", "app.py"]

