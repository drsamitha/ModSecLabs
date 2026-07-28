FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir requests urllib3
COPY generate.py .
CMD ["python", "generate.py"]
