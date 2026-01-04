# Translator Feature

## Overview

The LogAnalysisBot now includes a powerful translation feature that allows you to translate log analysis results into multiple languages. This is useful for international teams, security reports, and multi-lingual documentation.

## Features

- **Dictionary-based translation**: Works out-of-the-box with common security terms in 5 languages
- **API-based translation** (optional): Use Google Translate API for more accurate translations
- **Multiple languages supported**: Spanish, French, German, Chinese, Japanese, and more
- **CLI commands**: Easy-to-use command-line interface for translations
- **Analysis translation**: Translate entire log analysis results with structure preserved

## Supported Languages

### Dictionary-based (default, no API required):
- **English (en)** - Default
- **Spanish (es)** - Español
- **French (fr)** - Français  
- **German (de)** - Deutsch
- **Chinese (zh)** - 中文
- **Japanese (ja)** - 日本語

### API-based (requires googletrans):
All of the above plus: Korean, Arabic, Russian, Portuguese, Italian, Dutch, Polish, Turkish, and more.

## Installation

The translator works with the base installation. For API-based translation:

```bash
pip install googletrans==4.0.0-rc1
```

## Usage

### 1. Translate Text

Translate any text to another language:

```bash
# Translate to Spanish (default)
python -m src.cli translate "Failed login detected"

# Translate to French
python -m src.cli translate "Security alert" --lang fr

# Translate to German
python -m src.cli translate "Critical error" --lang de

# Use API translation for better accuracy
python -m src.cli translate "Malicious activity detected" --lang es --api
```

### 2. Translate Log Analysis Results

Analyze a log file and get results in your preferred language:

```bash
# Analyze and translate to Spanish
python -m src.cli translate-analysis samples/sample_1.log --lang es

# Translate to French and save to file
python -m src.cli translate-analysis samples/sample_1.log --lang fr --output results_fr.json

# Use API translation
python -m src.cli translate-analysis samples/sample_1.log --lang de --api
```

### 3. List Supported Languages

View all available languages:

```bash
# List dictionary-based languages
python -m src.cli list-languages

# List all API-supported languages
python -m src.cli list-languages --api
```

## Python API

You can also use the translator directly in your Python code:

```python
from src.translator import Translator, translate_log_analysis

# Create a translator instance
translator = Translator(use_api=False)

# Translate simple text
translated = translator.translate_text("Failed login", target_language="es")
print(translated)  # "Inicio de sesión fallido"

# Translate analysis results
analysis = {
    "Summary": "3 critical security events detected",
    "Events": ["Failed login from 192.168.1.100", "Access denied"],
    "Severity": "High"
}

translated_analysis = translator.translate_analysis_result(analysis, "fr")
print(translated_analysis)

# Or use the helper function
result = translate_log_analysis(analysis, language="de", use_api=False)
```

## Examples

### Example 1: Basic Translation

```bash
$ python -m src.cli translate "Authentication failed" --lang es
Original (English):
Authentication failed

Translated (Spanish):
Autenticación fallido
```

### Example 2: Log Analysis with Translation

```bash
$ python -m src.cli translate-analysis samples/sample_1.log --lang ja

============================================================
Log Analysis Results (Japanese)
============================================================

要約: 6 イベント found in log file
イベント:
  - CRITICAL: Auth failure for user admin at 2025-01-01T10:23:45
  - WARNING: Multiple failed login attempts detected
  - INFO: セキュリティ警告 from firewall
File: samples/sample_1.log
```

### Example 3: Save Translated Results

```bash
$ python -m src.cli translate-analysis samples/sample_1.log --lang fr --output results_french.json

✓ Results saved to: results_french.json
```

## Language Coverage

The dictionary-based translator includes translations for common security terms:

- **Authentication terms**: login, password, authentication, access
- **Severity levels**: critical, warning, error, info, high, medium, low
- **Security events**: failed login, suspicious activity, malicious, attack
- **System terms**: firewall, timestamp, events, summary

## Tips

1. **For quick translations**: Use dictionary-based mode (default) - no API key needed
2. **For better accuracy**: Install googletrans and use `--api` flag
3. **For reports**: Use `--output` to save translated results as JSON
4. **Multi-language teams**: Generate reports in multiple languages simultaneously

## Troubleshooting

**Issue**: Translation seems incomplete  
**Solution**: The dictionary-based mode only translates known security terms. Use `--api` for full translation.

**Issue**: API translation fails  
**Solution**: Install googletrans: `pip install googletrans==4.0.0-rc1`

**Issue**: Language not supported  
**Solution**: Run `python -m src.cli list-languages` to see all supported languages

## Future Enhancements

- Add more languages to dictionary
- Support for right-to-left languages (Arabic, Hebrew)
- Batch translation of multiple files
- Custom translation dictionaries
- Integration with DeepL and other translation services
