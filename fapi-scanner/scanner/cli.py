from pathlib import Path

import click

from scanner.engine import run_scan
from scanner.reporting.pdf import render_scan_pdf


@click.command()
@click.option("--target", required=True, help="Base URL of the AS under test")
@click.option("--pdf", "pdf_path", type=click.Path(dir_okay=False, path_type=Path), default=None, help="Write a PDF report to this path")
def scan(target, pdf_path):
    report = run_scan(target)
    summary = report["summary"]
    click.echo(
        f"Scan of {report['target']}: "
        f"{summary['pass']} pass / {summary['fail']} fail / {summary['error']} error"
    )
    for result in report["results"]:
        click.echo(f"[{result['status'].upper()}] {result['check_id']} — {result['description']}")
        click.echo(f"  {result['detail']}")
    if pdf_path is not None:
        pdf_path.write_bytes(render_scan_pdf(report))
        click.echo(f"Wrote PDF report to {pdf_path}")


def cli():
    scan()


if __name__ == "__main__":
    scan()
