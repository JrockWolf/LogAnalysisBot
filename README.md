# Log Analysis Helper Bot

An LLM-powered log analysis assistant for security education and small SOCs, with built-in support for **all labeled intrusion detection datasets** and **MITRE ATT&CK** technique mapping.

## Features

- **Universal Dataset Support** — Load, parse, and analyze any labeled intrusion detection dataset (network flow CSVs with features and a Label column)
- **MITRE ATT&CK Mapping** — Automatically map detected attacks to MITRE ATT&CK techniques with IDs, tactics, and reference URLs
- **Network Attack Detection** — Heuristic-based detection for DDoS, DoS, brute force, port scanning, web attacks, bot activity, and infiltration
- **Evaluation Pipeline** — Binary and per-class metrics (precision, recall, F1, accuracy, FPR), confusion matrices, and formatted reports
- Parsers for text, JSON, CSV, and labeled network flow logs
- Simulated log generator with common security events
- LLM adapter for OpenAI, Perplexity, Gemini, Deepseek, and HuggingFace local models
- Analyzer with deterministic heuristics and optional LLM-enhanced summaries
- Multi-language translator for analysis results (Spanish, French, German, Chinese, Japanese, and more)
- Web UI (FastAPI) and CLI (Typer) interfaces

## Quickstart

1. Create and activate a Python 3.8+ virtual environment.
2. Install dependencies:

```bash
python -m pip install -r requirements.txt
```

3. (Optional) Configure an LLM provider key or use a local HuggingFace model:

```bash
export OPENAI_API_KEY="sk-..."
export PERPLEXITY_API_KEY="pplx-..."
export GEMINI_API_KEY="..."
export DEEPSEEK_API_KEY="..."
# or use a local transformers model (defaults to gpt2)
export HF_MODEL="gpt2"
```

## Usage

### Analyze a log file

```bash
python -m src.cli analyze samples/sample_1.log
```

### Analyze with MITRE ATT&CK mapping

```bash
python -m src.cli analyze samples/sample.csv --mitre
```

### Evaluate detection on a labeled dataset

```bash
python -m src.cli evaluate samples/dataset_sample.csv
python -m src.cli evaluate samples/dataset_sample.csv --output results.json
```

### Dataset info

```bash
python -m src.cli dataset-info samples/dataset_sample.csv
```

### Generate synthetic logs

```bash
python -m src.cli generate --out samples --count 5
```

### Translate analysis results

```bash
python -m src.cli translate-analysis samples/sample_1.log --lang es
python -m src.cli list-languages
```

### Web UI

```bash
python -m src.webapp
```

See [docs/TRANSLATOR.md](docs/TRANSLATOR.md) for translation documentation.

## Dataset Support

The project supports any labeled intrusion detection dataset in CSV format with a `Label` column and network flow features. Datasets are auto-detected by column headers (e.g., `Label`, `Flow Duration`, `Destination Port`). Compatible datasets include CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, and others with similar structure.

Supported attack categories:

| Category | Attack Types |
|---|---|
| Brute Force | FTP-Patator, SSH-Patator |
| DoS | Hulk, Slowloris, Slowhttptest, GoldenEye |
| DDoS | Distributed Denial of Service |
| Web Attacks | Brute Force, XSS, SQL Injection |
| Reconnaissance | Port Scanning |
| Botnet | Bot traffic |
| Infiltration | Infiltration attacks |

Sample extracts can be placed in `samples/` for testing.

## Architecture

```
src/
├── cli.py              # Typer CLI (analyze, evaluate, dataset-info, generate, translate)
├── webapp.py           # FastAPI web interface
├── parsers.py          # Log parsers (text, JSON, CSV, labeled datasets)
├── analyzer.py         # Heuristic + LLM analysis pipeline
├── dataset_loader.py   # Dataset CSV loader and label normalization
├── mitre_mapping.py    # MITRE ATT&CK technique mapping
├── eval.py             # Evaluation metrics (binary, per-class, confusion matrix)
├── llm_adapter.py      # Multi-provider LLM interface
├── generator.py        # Synthetic log generator
└── translator.py       # Multi-language translation
```

## Running Tests

```bash
python -m pytest -q
```

64 tests covering dataset loading, parsing, MITRE mapping, network attack detection, evaluation metrics, translation, and integration.

## Notes

- Provider detection precedence: Perplexity → Gemini → Deepseek → OpenAI → HuggingFace local. Force a provider with `LLM_PROVIDER=openai|perplexity|transformers`.
- The analyzer produces findings via deterministic heuristics without an LLM; LLM enhances summaries when available.
- Labeled dataset CSV files are auto-detected by column headers — no special flags needed.

## Security and Ethics

- Avoid uploading real sensitive logs to third-party APIs. Use synthetic or sanitized logs for experimentation.

