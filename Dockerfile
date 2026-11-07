FROM python:3.12-slim
RUN useradd -m honey
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p data logs && chown -R honey:honey /app
USER honey
EXPOSE 2222
CMD ["python", "-m", "phantomnet.server", "-c", "config.yaml"]
