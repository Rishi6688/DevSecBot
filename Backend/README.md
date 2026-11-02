# DevSecBot AI Backend

FastAPI backend for AI-powered vulnerability analysis and remediation using Semgrep and Ollama.

## Requirements
- Python
- Ollama
- Qwen2.5-Coder 3B model

## Setup

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Ensure Ollama is running and the model is available:

```bash
ollama pull qwen2.5-coder:3b
```

## Run the backend

```bash
python -m uvicorn main:app --reload
```

## API documentation

Open:

http://127.0.0.1:8000/docs

## Endpoints

- `GET /health` - Check backend status
- `POST /analyze` - Analyze a Semgrep finding and return a proposed fix

## Important

The backend proposes fixes. It does not automatically modify source files or execute the proposed patches.
