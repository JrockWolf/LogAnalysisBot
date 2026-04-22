# LogAnalysisBot

An AI-powered security log analysis platform for SOC teams and security researchers. Combines rule-based heuristics, 6 ML anomaly detection models, and multi-provider LLM enrichment with automatic MITRE ATT&CK mapping.

## Features

### 🛡️ Threat Detection
- **Heuristic Detection** — Rules-based alerts for DDoS, DoS, brute force, port scanning, web attacks, bot activity, infiltration, and more
- **PCAP Parsing** — Wireshark capture analysis via Scapy for network-level threat detection
- **Syslog / Text Log Parsing** — Multi-format log ingestion with automatic format detection

### 🤖 LLM Enrichment (5 Providers)
- **OpenAI** (GPT-3.5, GPT-4, etc.)
- **Perplexity** (sonar-pro)
- **Google Gemini** (gemini-2.0-flash, configurable)
- **DeepSeek**
- **HuggingFace Transformers** (local inference, no API key required)
- All providers use timeout protection (default 30s, configurable via `LLM_TIMEOUT_SECONDS`)

### ⚡ ML Anomaly Detection (6 Models)
| Model | Type | Notes |
|---|---|---|
| **Isolation Forest** | Ensemble / Tree | Fast, unsupervised, robust to outliers |
| **Local Outlier Factor** | Density-based | Detects local anomalies, k=20 neighbors |
| **One-Class SVM** | Kernel / Novelty | RBF kernel, capped at 5000 samples |
| **DBSCAN** | Clustering | Noise points = anomalies, returns cluster count |
| **Random Forest** | Supervised | Active when label columns present; 3-fold CV |
| **Ensemble Consensus** | Majority Vote | Flags records where ≥2 models agree |

### 🗺️ MITRE ATT&CK Mapping
- Automatic technique enrichment from findings
- 200+ mapped techniques with tactic labels and direct ATT&CK URLs
- Displayed as clickable tags in results

### 📊 Statistical Analysis
- Dataset overview: record counts, feature distributions, category breakdown
- Mann-Whitney U tests, independent t-tests
- Baseline z-score anomaly comparison
- Model performance metrics: accuracy, precision, recall, F1, FPR
- Hypothesis testing with evidence summary

### 🌐 Web UI
- Drag-and-drop file upload
- Multi-model comparison table in results
- Interactive charts via matplotlib
- Dark professional theme

### 📁 Supported File Formats
| Format | Description |
|---|---|
| `.pcap` / `.pcapng` / `.cap` | Wireshark network captures |
| `.csv` | Labeled flow datasets, any schema |
| `.json` / `.jsonl` | Structured log entries |
| `.log` / `.txt` | Raw text / syslog lines |
| `.gz` / `.zip` | Compressed archives (auto-extracted) |

### 🔧 Additional Tools
- **CLI** (`src/cli.py`) via Typer — analyze, eval, generate subcommands
- **Multi-language Translator** — translate findings to Spanish, French, German, Chinese, Japanese, and more
- **Simulated Log Generator** — generates realistic security events for testing
- **Dataset Loader** — auto-detects and normalizes popular IDS datasets (CIC-IDS2017, UNSW-NB15, etc.)

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

