import typer
from pathlib import Path
from dotenv import load_dotenv
from .generator import generate_samples
from .analyzer import analyze_logs, analyze_dataset
from .translator import Translator
from .mitre_mapping import enrich_findings_with_mitre
import json

# load .env from project root automatically when CLI runs
load_dotenv()

app = typer.Typer()


@app.command()
def generate(out: Path = typer.Option(Path("./samples"), help="Output folder for generated logs"), count: int = 1):
    """Generate simulated log files."""
    out.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        path = out / f"sample_{i+1}.log"
        generate_samples(path)
        typer.echo(f"Wrote {path}")


@app.command()
def analyze(
    path: Path = typer.Argument(..., help="Path to log file"),
    mitre: bool = typer.Option(False, "--mitre", "-m", help="Include MITRE ATT&CK mappings"),
):
    """Analyze a log file and print findings."""
    findings = analyze_logs(path)
    for f in findings:
        typer.echo(f"- {f}")

    if mitre:
        enriched = enrich_findings_with_mitre(findings)
        typer.echo("\nMITRE ATT&CK Mappings:")
        typer.echo("=" * 50)
        for entry in enriched:
            techniques = entry.get("mitre_techniques", [])
            if techniques:
                typer.echo(f"\n  {entry['finding']}")
                for t in techniques:
                    typer.echo(f"    -> {t['technique_id']} - {t['name']} ({t['tactic']})")


@app.command()
def evaluate(
    path: Path = typer.Argument(..., help="Path to CIC-IDS2017 CSV sample file"),
    output: Path = typer.Option(None, "--output", "-o", help="Save JSON results to file"),
):
    """Evaluate detection performance against a labeled CIC-IDS2017 dataset sample."""
    from .eval import evaluate_dataset, format_evaluation_report

    typer.echo(f"Evaluating: {path}")
    results = evaluate_dataset(path)
    report = format_evaluation_report(results)
    typer.echo(report)

    if output:
        # Save JSON (exclude non-serializable items)
        with open(output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
        typer.echo(f"\nResults saved to: {output}")


@app.command("dataset-info")
def dataset_info(
    path: Path = typer.Argument(..., help="Path to CIC-IDS2017 CSV file"),
    max_rows: int = typer.Option(10000, "--max-rows", "-n", help="Max rows to read"),
):
    """Show summary of a CIC-IDS2017 dataset CSV file."""
    from .dataset_loader import load_cicids_csv, dataset_summary

    typer.echo(f"Loading: {path}")
    headers, rows = load_cicids_csv(path, max_rows=max_rows)
    summary = dataset_summary(rows)

    typer.echo(f"\nTotal flows: {summary['total_flows']}")
    typer.echo(f"Benign:      {summary['benign']}")
    typer.echo(f"Malicious:   {summary['malicious']}")
    typer.echo(f"\nLabel Distribution:")
    for label, count in summary["label_distribution"].items():
        typer.echo(f"  {label:40s} {count:>8d}")
    typer.echo(f"\nCategory Distribution:")
    for cat, count in summary["category_distribution"].items():
        typer.echo(f"  {cat:25s} {count:>8d}")


@app.command("check-env")
def check_env():
    """Print whether OPENAI_API_KEY is loaded and which provider would be used (masked)."""
    from os import getenv
    from .llm_adapter import LLMAdapter
    openai_key = getenv("OPENAI_API_KEY")
    pplx_key = getenv("PERPLEXITY_API_KEY")
    gemini_key = getenv("GEMINI_API_KEY")
    deepseek_key = getenv("DEEPSEEK_API_KEY")
    if openai_key:
        masked = openai_key[:4] + "..." + openai_key[-4:]
        typer.echo(f"OPENAI_API_KEY present: yes ({masked})")
    else:
        typer.echo("OPENAI_API_KEY present: no")
    if pplx_key:
        masked = pplx_key[:4] + "..." + pplx_key[-4:]
        typer.echo(f"PERPLEXITY_API_KEY present: yes ({masked})")
    else:
        typer.echo("PERPLEXITY_API_KEY present: no")
    if gemini_key:
        masked = gemini_key[:4] + "..." + gemini_key[-4:]
        typer.echo(f"GEMINI_API_KEY present: yes ({masked})")
    else:
        typer.echo("GEMINI_API_KEY present: no")
    if deepseek_key:
        masked = deepseek_key[:4] + "..." + deepseek_key[-4:]
        typer.echo(f"DEEPSEEK_API_KEY present: yes ({masked})")
    else:
        typer.echo("DEEPSEEK_API_KEY present: no")

    try:
        adapter = LLMAdapter()
        adapter.ensure()
        typer.echo(f"Adapter provider: {adapter.provider}")
    except Exception as e:
        typer.echo(f"Adapter error: {e}")


@app.command()
def translate(
    text: str = typer.Argument(..., help="Text to translate"),
    language: str = typer.Option("es", "--lang", "-l", help="Target language code (es, fr, de, zh, ja)"),
    use_api: bool = typer.Option(False, "--api", help="Use Google Translate API (requires googletrans)")
):
    """Translate text to another language."""
    translator = Translator(use_api=use_api)
    
    if language not in translator.get_supported_languages():
        typer.echo(f"Error: Language '{language}' not supported.")
        typer.echo(f"Supported languages: {', '.join(translator.get_supported_languages())}")
        raise typer.Exit(1)
    
    translated = translator.translate_text(text, language)
    typer.echo(f"\nOriginal ({translator.get_language_name('en')}):")
    typer.echo(text)
    typer.echo(f"\nTranslated ({translator.get_language_name(language)}):")
    typer.echo(translated)


@app.command()
def translate_analysis(
    path: Path = typer.Argument(..., help="Path to log file"),
    language: str = typer.Option("es", "--lang", "-l", help="Target language code (es, fr, de, zh, ja)"),
    use_api: bool = typer.Option(False, "--api", help="Use Google Translate API"),
    output: Path = typer.Option(None, "--output", "-o", help="Save translated results to JSON file")
):
    """Analyze a log file and translate the results."""
    # First analyze the logs
    findings = analyze_logs(path)
    
    # Create analysis result structure
    analysis_result = {
        "Summary": f"{len(findings)} events found in log file",
        "Events": findings,
        "File": str(path)
    }
    
    # Translate the results
    translator = Translator(use_api=use_api)
    
    if language not in translator.get_supported_languages():
        typer.echo(f"Error: Language '{language}' not supported.")
        typer.echo(f"Supported languages: {', '.join(translator.get_supported_languages())}")
        raise typer.Exit(1)
    
    translated_result = translator.translate_analysis_result(analysis_result, language)
    
    # Display results
    typer.echo(f"\n{'='*60}")
    typer.echo(f"Log Analysis Results ({translator.get_language_name(language)})")
    typer.echo(f"{'='*60}\n")
    
    for key, value in translated_result.items():
        if isinstance(value, list):
            typer.echo(f"{key}:")
            for item in value:
                typer.echo(f"  - {item}")
        else:
            typer.echo(f"{key}: {value}")
    
    # Save to file if requested
    if output:
        with open(output, 'w', encoding='utf-8') as f:
            json.dump(translated_result, f, ensure_ascii=False, indent=2)
        typer.echo(f"\n✓ Results saved to: {output}")


@app.command("list-languages")
def list_languages(api: bool = typer.Option(False, "--api", help="Show API-supported languages")):
    """List all supported languages for translation."""
    translator = Translator(use_api=api)
    languages = translator.get_supported_languages()
    
    typer.echo("\nSupported Languages:")
    typer.echo("="*40)
    for lang_code in languages:
        lang_name = translator.get_language_name(lang_code)
        typer.echo(f"  {lang_code:6} - {lang_name}")
    typer.echo(f"\nTotal: {len(languages)} languages")
    
    if not api:
        typer.echo("\nNote: Use --api flag to see all API-supported languages")
        typer.echo("      (requires: pip install googletrans==4.0.0-rc1)")


def main():
    app()


if __name__ == "__main__":
    main()
