# Container target: OS packages from an old base image
# plus the pip-installed (resolved, including transitive) Python dependencies.
FROM python:3.9-slim-bullseye
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
CMD ["python", "app.py"]
