import typer
from pathlib import Path
from dotenv import load_dotenv
from .generator import generate_samples
from .analyzer import analyze_logs

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
def analyze(path: Path = typer.Argument(..., help="Path to log file")):
    """Analyze a log file and print findings."""
    findings = analyze_logs(path)
    for f in findings:
        typer.echo(f"- {f}")


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


def main():
    app()


if __name__ == "__main__":
    main()
