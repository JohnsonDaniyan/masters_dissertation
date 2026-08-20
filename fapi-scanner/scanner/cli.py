import click

from scanner.discovery.metadata_check import check_metadata_reachable
from scanner.engine import run_scan


@click.group(invoke_without_command=True)
@click.option("--target", help="Base URL of the AS under test")
@click.pass_context
def cli(ctx, target):
    if ctx.invoked_subcommand is not None:
        return
    if not target:
        raise click.UsageError("Missing option '--target'")
    result = check_metadata_reachable(target)
    click.echo(f"[{result.status.value.upper()}] {result.check_id} — {result.description}")
    click.echo(f"  {result.detail}")


@cli.command("scan-all")
@click.option("--target", required=True, help="Base URL of the AS under test")
def scan_all(target):
    report = run_scan(target)
    summary = report["summary"]
    click.echo(
        f"Scan of {report['target']}: "
        f"{summary['pass']} pass / {summary['fail']} fail / {summary['error']} error"
    )
    for result in report["results"]:
        click.echo(f"[{result['status'].upper()}] {result['check_id']} — {result['description']}")
        click.echo(f"  {result['detail']}")


def scan():
    cli()


if __name__ == "__main__":
    cli()
