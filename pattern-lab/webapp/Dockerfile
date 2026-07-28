FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir Flask numpy
COPY app.py .
COPY templates ./templates
# engine/ is mounted read-only at /app/engine by docker-compose.
EXPOSE 8050
CMD ["python", "app.py"]
