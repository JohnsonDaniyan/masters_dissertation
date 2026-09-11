import click

from scanner.engine import run_scan


@click.command()
@click.option("--target", required=True, help="Base URL of the AS under test")
def scan(target):
    report = run_scan(target)
    summary = report["summary"]
    click.echo(
        f"Scan of {report['target']}: "
        f"{summary['pass']} pass / {summary['fail']} fail / {summary['error']} error"
    )
    for result in report["results"]:
        click.echo(f"[{result['status'].upper()}] {result['check_id']} — {result['description']}")
        click.echo(f"  {result['detail']}")


def cli():
    scan()


if __name__ == "__main__":
    scan()
