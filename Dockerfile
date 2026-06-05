# AI SOC CoPilot — runtime image.
# The tool calls a local Ollama server; point it at the host with
#   docker run --rm -v "$PWD/logs:/app/logs" -v "$PWD/reports:/app/reports" \
#     ai-soc-copilot --ollama-url http://host.docker.internal:11434 \
#     --output report.html --format html
FROM python:3.11-slim

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application.
COPY . .

# Non-root user.
RUN useradd --create-home soc && chown -R soc:soc /app
USER soc

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
