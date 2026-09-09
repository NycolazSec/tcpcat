FROM python:3.11-alpine
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn
COPY . .
# Gunicorn écoutera sur le port 8000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8083", "app:app"]