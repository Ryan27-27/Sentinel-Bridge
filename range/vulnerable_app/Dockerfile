FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY vulnerable_app/ ./vulnerable_app/
EXPOSE 5060
CMD ["python", "vulnerable_app/app.py"]
