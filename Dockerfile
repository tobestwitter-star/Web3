FROM python:3.11-slim
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN curl -L https://foundry.paradigm.xyz | bash \
    && export PATH="/root/.config/.foundry/bin:$PATH" \
    && foundryup
ENV PATH="/root/.config/.foundry/bin:${PATH}"
COPY . .
ENV PORT=8080
EXPOSE 8080
CMD exec gunicorn --bind :$PORT --workers 1 --threads 4 --timeout 120 main:app
