# Log Analysis Helper Bot

This project provides a reproducible scaffold for building an LLM-powered log analysis assistant for security education and small SOCs.

Features:
- Parsers for text, JSON and CSV logs
- Simulated log generator with common security events
- LLM adapter for OpenAI (if API key provided) and HuggingFace fallback
- Analyzer that uses prompt templates to extract actionable events and generate plain-language summaries
- Evaluation harness for precision/recall/F1
- **NEW: Multi-language translator** - Translate log analysis results into Spanish, French, German, Chinese, Japanese, and more

Quickstart
1. Create and activate a Python 3.8+ virtual environment.
2. Install dependencies:

```bash
python -m pip install -r requirements.txt
```

3. (Optional) Configure an LLM provider key or use a local HuggingFace model:

```bash
# OpenAI key (if you have one):
export OPENAI_API_KEY="sk-..."
# Perplexity.ai keys are supported; set PERPLEXITY_API_KEY (keys often start with 'pplx-'):
export PERPLEXITY_API_KEY="pplx-..."
# or set HF_MODEL env var to use a local transformers model (defaults to gpt2)
export HF_MODEL="gpt2"
```

4. Generate a sample log and analyze it:

```bash
python -m src.cli generate --out samples --count 1
python -m src.cli analyze samples/sample_1.log
```

5. **NEW: Translate analysis results**:

```bash
# Translate to Spanish
python -m src.cli translate-analysis samples/sample_1.log --lang es

# Translate to French and save to file
python -m src.cli translate-analysis samples/sample_1.log --lang fr --output results_fr.json

# List all supported languages
python -m src.cli list-languages
```

See [docs/TRANSLATOR.md](docs/TRANSLATOR.md) for complete translation features documentation.

Run tests:

```bash
python -m pytest -q
```

Notes
 - Provider detection and precedence:
	 - If `PERPLEXITY_API_KEY` is set the adapter will attempt to call Perplexity's API.
	 - If `GEMINI_API_KEY` is set the adapter will attempt to call Gemini (best-effort wrapper).
	 - If `DEEPSEEK_API_KEY` is set the adapter will attempt to call Deepseek (best-effort wrapper).
	 - If `OPENAI_API_KEY` is set and looks like an OpenAI key the adapter will use OpenAI.
	 - If `OPENAI_API_KEY` accidentally contains a Perplexity key (starts with `pplx-`) the adapter will not call OpenAI and will instead prefer Perplexity (if provided) or fall back to the local HF model.
	 - You can force a provider by setting `LLM_PROVIDER` to `openai`, `perplexity` or `transformers`.
- The analyzer includes deterministic heuristics so it can produce findings without an LLM; LLM enhances summaries when available.

Security and ethics
- Avoid uploading real sensitive logs to third-party APIs. Use synthetic or sanitized logs for experimentation.

