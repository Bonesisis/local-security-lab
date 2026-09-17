FROM python:3.12-slim

WORKDIR /lab

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/
COPY sample_data/ sample_data/

ENTRYPOINT ["python", "-m", "src.cli"]
CMD ["--help"]
