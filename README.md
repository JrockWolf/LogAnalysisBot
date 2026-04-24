# LogAnalysisBot

Drop a log file, get a triage report. LogAnalysisBot runs a four-stage pipeline — **parse → normalize → detect → summarize** — and produces structured findings with MITRE ATT&CK links and confidence scores. PII and hostnames are redacted before anything leaves your machine.

## Core use case

A SOC analyst drops a firewall log, syslog bundle, PCAP capture, or labeled IDS dataset onto the tool. Within seconds they get:

1. **Structured findings** — severity-ranked list, each linked back to the exact log lines that triggered it.
2. **MITRE ATT&CK references** — technique ID, tactic, and direct URL automatically mapped to each finding.
3. **ML consensus score** — six anomaly models vote; only findings where ≥ 2 models agree are promoted.
4. **LLM triage narrative** — one-paragraph analyst-grade summary from whichever LLM provider is configured (optional; works fully offline without one).
5. **Redacted output** — IPs, emails, usernames, and custom patterns are masked before any data reaches an external API.

## Pipeline

```
Input file
    │
    ▼
┌─────────────┐    src/parsers.py
│   Parser    │    text · JSON · CSV · PCAP · .gz/.zip
└──────┬──────┘
       │ raw records
       ▼
┌─────────────┐    src/normalizer.py  (wraps structurizer)
│  Normalizer │    timestamp · severity · IPs · ports · method · action
└──────┬──────┘
       │ structured records
       ▼
┌─────────────┐    src/detector.py
│  Detector   │    heuristics + Isolation Forest + LOF + SVM + DBSCAN + RF + Ensemble
└──────┬──────┘
       │ raw findings
       ▼
┌─────────────┐    src/summarizer.py
│  Summarizer │    structured output · evidence links · LLM narrative
└──────┬──────┘
       │
       ▼
  AnalysisResult  (src/output_schema.py)
```

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Optional — configure an LLM provider (or skip for offline/heuristic-only mode):

```bash
export OPENAI_API_KEY="sk-..."
export GEMINI_API_KEY="..."
export PERPLEXITY_API_KEY="pplx-..."
export DEEPSEEK_API_KEY="..."
# offline alternative — local HuggingFace model:
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

### Redact PII before analysis

```bash
python -m src.cli analyze samples/sample_1.log --redact
# redact custom patterns too
python -m src.cli analyze samples/sample_1.log --redact --redact-pattern "corp\.example\.com"
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

### Benchmark against a public IDS dataset

```bash
python -m src.cli evaluate samples/cicids2017_sample.csv --benchmark
```

### Generate synthetic logs for testing

```bash
python -m src.cli generate --out samples --count 5
```

### Translate results

```bash
python -m src.cli translate-analysis samples/sample_1.log --lang es
python -m src.cli list-languages
```

### Web UI

```bash
python -m src.webapp
```

See [docs/TRANSLATOR.md](docs/TRANSLATOR.md) for translation documentation.

## Structured output format

Every analysis returns an `AnalysisResult` (defined in `src/output_schema.py`):

```json
{
  "file": "firewall.log",
  "analyzed_at": "2026-04-24T10:00:00Z",
  "record_count": 4200,
  "redacted": true,
  "findings": [
    {
      "id": "f-001",
      "severity": "high",
      "confidence": 0.91,
      "category": "Brute Force",
      "description": "Multiple failed SSH logins from [IP_0] (14 attempts)",
      "evidence": [
        {"line_number": 42, "raw": "Failed password for root from [IP_0] port 2222"},
        {"line_number": 43, "raw": "Failed password for admin from [IP_0] port 2222"}
      ],
      "mitre": [
        {
          "technique_id": "T1110.001",
          "name": "Password Guessing",
          "tactic": "Credential Access",
          "url": "https://attack.mitre.org/techniques/T1110/001/"
        }
      ]
    }
  ],
  "summary": "14 high-severity findings. Dominant threat: SSH brute-force from 3 unique sources..."
}
```

## Privacy and redaction

`src/redactor.py` runs before any LLM call. Redactions are applied to the text sent to external APIs; original records are kept in memory for evidence line reconstruction.

| Entity | Replacement |
|--------|-------------|
| IPv4 addresses | `[IP_0]`, `[IP_1]`, … |
| IPv6 addresses | `[IPv6_0]`, `[IPv6_1]`, … |
| Email addresses | `[EMAIL_0]`, `[EMAIL_1]`, … |
| Usernames (sudo/su/login) | `[USER_0]`, `[USER_1]`, … |
| Hostnames | `[HOST_0]`, `[HOST_1]`, … |
| Custom regex patterns | `[REDACTED_0]`, `[REDACTED_1]`, … |

Reversible replacement map is kept in `RedactionContext` for reconstructing display text when needed.

## Detection modules

| Module | Role |
|--------|------|
| `src/parsers.py` | Ingest any file format: syslog, JSON/JSONL, CSV, PCAP, `.gz`/`.zip` |
| `src/normalizer.py` | Map raw records → typed schema (timestamp, severity, IPs, ports, action) |
| `src/detector.py` | Heuristic rules + 6 ML anomaly models → raw `FindingCandidate` list |
| `src/summarizer.py` | Rank, deduplicate, attach evidence lines, call LLM narrative |
| `src/output_schema.py` | Pydantic `Finding` / `AnalysisResult` output contracts |
| `src/redactor.py` | PII / hostname scrubbing with reversible replacement map |

## Supported file formats

| Format | Description |
|--------|-------------|
| `.pcap` / `.pcapng` / `.cap` | Wireshark network captures |
| `.csv` | Labeled flow datasets (CIC-IDS2017, UNSW-NB15, …) or generic |
| `.json` / `.jsonl` | Structured log entries |
| `.log` / `.txt` | Raw text / syslog lines |
| `.gz` / `.zip` | Compressed archives (auto-extracted) |

## Benchmarks

Run the built-in benchmark suite against synthetic datasets:

```bash
python -m pytest tests/test_benchmark.py -v
```

The benchmark generates controlled synthetic log corpora (brute-force, DoS, port scan, web attack, benign mix) and measures precision / recall / F1 per attack category against ground-truth labels. Results are printed as a Markdown table to stdout.

## Running all tests

```bash
python -m pytest -q
```

## Notes

- Provider detection precedence: Perplexity → Gemini → Deepseek → OpenAI → HuggingFace local. Override with `LLM_PROVIDER=openai|perplexity|transformers`.
- Heuristic detection runs without any LLM key. LLM enriches the narrative only when available.
- Labeled dataset CSVs are auto-detected by column headers — no special flags needed.
- Redaction is enabled by default when an external LLM provider is active. Disable with `LOGBOT_REDACT=0`.

## Security and Ethics

- Redaction runs before any data reaches an external API. Still, treat output as potentially sensitive.
- Do not use this tool to analyze logs you are not authorized to access.

