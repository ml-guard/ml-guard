"""CLI ml-guard — точка входа консольного инструмента."""
from __future__ import annotations

import logging
import sys
from pathlib import Path

import click

from ml_guard import __version__
from ml_guard.findings import Severity
from ml_guard.runner import Runner
from ml_guard.output import FORMATTERS

# Импорт модулей-сканеров регистрирует их в default_registry через декоратор.
# Каждый новый сканер ДОЛЖЕН быть импортирован здесь, иначе он не появится
# в реестре. Это явное (а не «автомагическое») поведение нам подходит:
# тесты могут импортировать только нужные сканеры.
import ml_guard.scanners.pickle_scanner       # noqa: F401
import ml_guard.scanners.safetensors_scanner  # noqa: F401
import ml_guard.scanners.secret_scanner       # noqa: F401
import ml_guard.scanners.onnx_scanner         # noqa: F401
import ml_guard.scanners.cve_scanner          # noqa: F401


SEVERITY_CHOICES = [s.value for s in Severity]


@click.group()
@click.version_option(__version__, prog_name="ml-guard")
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging")
def main(verbose: bool) -> None:
    """ML Guard — security and compliance scanner for ML pipelines."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


@main.command()
@click.argument(
    "path",
    type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=Path),
)
@click.option(
    "-f", "--format", "output_format",
    type=click.Choice(["text", "json", "sarif"]),
    default="text",
    show_default=True,
    help="Output format",
)
@click.option(
    "-o", "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write output to file instead of stdout",
)
@click.option(
    "--fail-on",
    type=click.Choice(SEVERITY_CHOICES),
    default=None,
    help="Exit with non-zero status if any finding has severity ≥ this level. "
         "Default: 'critical' (or value from --config).",
)
@click.option(
    "--no-color", is_flag=True, default=False,
    help="Disable ANSI colors in text output",
)
@click.option(
    "--include", "include_patterns",
    multiple=True, metavar="GLOB",
    help="Only scan files matching this glob (repeatable). Matched against both "
         "the basename and the path relative to PATH.",
)
@click.option(
    "--exclude", "exclude_patterns",
    multiple=True, metavar="GLOB",
    help="Skip files matching this glob (repeatable). Takes precedence over --include.",
)
@click.option(
    "--scanners", "selected_scanners",
    multiple=True, metavar="NAME",
    help="Only run these scanners (repeatable; e.g. --scanners pickle). "
         "Default: run every registered scanner that applies.",
)
@click.option(
    "-c", "--config", "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to .ml-guard.yml. If omitted, ml-guard auto-discovers one in PATH or its parents.",
)
@click.option(
    "-j", "--workers",
    type=int, default=None,
    help="Number of parallel scanner threads. Default: min(8, cpu_count). Use 1 for deterministic output.",
)
@click.option(
    "--cve-db", "cve_db_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Path to OSV SQLite database for cve scanner. "
         "Default: $ML_GUARD_CVE_DB or $XDG_DATA_HOME/ml-guard/osv.db",
)
def scan(
    path: Path,
    output_format: str,
    output: Path | None,
    fail_on: str | None,
    no_color: bool,
    include_patterns: tuple[str, ...],
    exclude_patterns: tuple[str, ...],
    selected_scanners: tuple[str, ...],
    config_path: Path | None,
    workers: int | None,
    cve_db_path: Path | None,
) -> None:
    """Scan PATH (a file or directory) for ML security issues."""
    from ml_guard.config import load_config
    cfg = load_config(explicit_path=config_path, scan_root=path)

    # Если пользователь явно указал --cve-db, прокинем его через env.
    # CveScanner уже умеет читать ML_GUARD_CVE_DB; так не нужно ломать его API.
    if cve_db_path is not None:
        import os as _os
        _os.environ["ML_GUARD_CVE_DB"] = str(cve_db_path)

    runner = Runner(
        include_patterns=list(include_patterns) or None,
        exclude_patterns=list(exclude_patterns) or None,
        selected_scanners=list(selected_scanners) or None,
        config=cfg,
        workers=workers,
    )
    result = runner.run(path)

    formatter = FORMATTERS[output_format]
    if output_format == "text":
        rendered = formatter(result, use_color=not no_color and (output is None))
    else:
        rendered = formatter(result)

    if output is not None:
        output.write_text(rendered, encoding="utf-8")
        click.echo(f"Wrote {output_format} report to {output}")
    else:
        click.echo(rendered)

    # Exit code: иерархия fail_on  =  CLI > config > default("critical")
    if fail_on is not None:
        threshold = Severity(fail_on)
    elif cfg.fail_on is not None:
        threshold = cfg.fail_on
    else:
        threshold = Severity.CRITICAL
    if result.has_at_least(threshold):
        sys.exit(1)
    sys.exit(0)


@main.command(name="compliance")
@click.argument(
    "path",
    type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=Path),
)
@click.option(
    "--standard",
    type=str,
    default="eu-ai-act",
    show_default=True,
    help="Compliance standard to evaluate against. Use 'list' to see options.",
)
@click.option(
    "-o", "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Path for the generated PDF report (required unless --json).",
)
@click.option(
    "--json", "as_json", is_flag=True, default=False,
    help="Emit JSON summary to stdout instead of (or in addition to) PDF.",
)
@click.option(
    "-c", "--config", "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to .ml-guard.yml",
)
def compliance_cmd(
    path: Path,
    standard: str,
    output: Path | None,
    as_json: bool,
    config_path: Path | None,
) -> None:
    """Scan PATH and emit a compliance report (PDF) for an audit standard.

    Examples:

      \b
      # PDF report against EU AI Act
      ml-guard compliance ./models --standard eu-ai-act --output report.pdf

      \b
      # JSON summary for automation (e.g. status badge)
      ml-guard compliance ./models --json
    """
    from ml_guard import compliance as mod
    from ml_guard.config import load_config

    if standard == "list":
        click.echo("Available standards:")
        for sid in mod.list_standards():
            std = mod.get_standard(sid)
            click.echo(f"  {sid:<14}  {std.name}")
        return

    try:
        mod.get_standard(standard)
    except ValueError as e:
        raise click.BadParameter(str(e)) from e

    if output is None and not as_json:
        raise click.UsageError("Either --output FILE or --json is required.")

    cfg = load_config(explicit_path=config_path, scan_root=path)
    runner = Runner(config=cfg)
    result = runner.run(path)
    report = mod.build_report(result, scan_root=path, standard_id=standard)

    if output is not None:
        pdf_bytes = mod.render_pdf(report)
        output.write_bytes(pdf_bytes)
        click.echo(
            f"Wrote {len(pdf_bytes)} bytes to {output} — verdict: "
            f"{report.summary_text()}"
        )

    if as_json:
        import json as _json
        summary = {
            "standard": report.standard.id,
            "verdict":  "PASS" if report.overall_pass else "FAIL",
            "controls": {
                "passed": report.passed,
                "failed": report.failed,
                "total":  report.total_controls,
            },
            "files_scanned": report.files_scanned,
            "findings_total": len(report.all_findings),
            "timestamp": report.timestamp,
        }
        click.echo(_json.dumps(summary, indent=2))

    if not report.overall_pass:
        sys.exit(1)


@main.command(name="cve-update")
@click.argument(
    "source",
    type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=Path),
)
@click.option(
    "--db", "db_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Where to write the SQLite index. Default: $XDG_DATA_HOME/ml-guard/osv.db",
)
def cve_update(source: Path, db_path: Path | None) -> None:
    """Build / refresh the local OSV vulnerability database from SOURCE.

    SOURCE can be either:

    \b
      • A ZIP archive of OSV advisories (e.g. https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip)
      • A directory of OSV-format JSON files

    The resulting SQLite database is used by the `cve` scanner to check
    `requirements.txt`, `pyproject.toml`, `Pipfile.lock`, and `environment.yml`
    against known vulnerabilities — fully offline.
    """
    from ml_guard.cve_db import CveDatabase, default_db_path

    target = db_path if db_path is not None else default_db_path()

    db = CveDatabase(target)
    click.echo(f"Importing from {source} into {target} ...")

    if source.is_file() and source.suffix.lower() == ".zip":
        stats = db.import_zip(source)
    elif source.is_dir():
        stats = db.import_dir(source)
    else:
        raise click.UsageError(f"SOURCE must be a .zip file or a directory, got {source}")

    db_stats = db.stats()
    db.close()

    click.echo(
        f"  imported: {stats['imported']}  skipped: {stats['skipped']}  errors: {stats['errors']}"
    )
    click.echo(
        f"  total advisories in DB: {db_stats['total_advisories']}  "
        f"(malicious: {db_stats['malicious_packages']}, "
        f"distinct packages: {db_stats['packages_affected']})"
    )


@main.command(name="list-scanners")
def list_scanners() -> None:
    """Print all registered scanners and their descriptions."""
    from ml_guard.scanners import default_registry
    if not default_registry.all():
        click.echo("No scanners registered.")
        return
    click.echo("Registered scanners:")
    for s in default_registry.all():
        click.echo(f"  {s.name:<14} {s.description}")


@main.command(name="cve-update")
@click.argument(
    "source",
    type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=Path),
)
@click.option(
    "--db", "db_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Where to write the SQLite database. Default: $XDG_DATA_HOME/ml-guard/osv.db.",
)
def cve_update_cmd(source: Path, db_path: Path | None) -> None:
    """Build the local OSV database from a ZIP archive or directory of JSON files.

    The OSV PyPI dump is published at:
      https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip

    \b
    Typical workflow:
      $ wget https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip
      $ ml-guard cve-update all.zip
      ✓ Imported 19438 advisories in 2.8s into ~/.local/share/ml-guard/osv.db
      $ ml-guard scan ./my-project    # CVE checker now active

    Re-running this command refreshes the database (full reindex).
    """
    from ml_guard.cve_db import CveDatabase, default_db_path
    import time

    target = db_path or default_db_path()
    target.parent.mkdir(parents=True, exist_ok=True)

    started = time.monotonic()
    with CveDatabase(target) as db:
        if source.is_dir():
            stats = db.import_dir(source)
        else:
            stats = db.import_zip(source)

    elapsed = time.monotonic() - started
    size_mb = target.stat().st_size / (1024 * 1024)
    click.echo(
        f"✓ Imported {stats['imported']} advisories "
        f"({stats.get('skipped', 0)} skipped, {stats.get('errors', 0)} errors) "
        f"in {elapsed:.1f}s"
    )
    click.echo(f"  Database: {target} ({size_mb:.1f} MB)")


@main.command(name="cve-info")
@click.option(
    "--db", "db_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to the OSV database. Default: $XDG_DATA_HOME/ml-guard/osv.db.",
)
@click.option(
    "--package",
    type=str,
    default=None,
    help="Look up advisories for a specific package (e.g. --package transformers).",
)
@click.option(
    "--version",
    type=str,
    default=None,
    help="Version to check, used together with --package.",
)
def cve_info_cmd(db_path: Path | None, package: str | None, version: str | None) -> None:
    """Show stats or query the local OSV database.

    \b
    Examples:
      ml-guard cve-info                                    # show DB stats
      ml-guard cve-info --package transformers             # all advisories for package
      ml-guard cve-info --package transformers --version 4.30.0  # only matching ones
    """
    from ml_guard.cve_db import CveDatabase, default_db_path
    target = db_path or default_db_path()
    if not target.is_file():
        raise click.ClickException(
            f"OSV database not found at {target}. "
            f"Run `ml-guard cve-update <path-to-osv.zip>` first."
        )

    with CveDatabase(target) as db:
        if package is None:
            stats = db.stats()
            click.echo("OSV database stats:")
            for k, v in stats.items():
                click.echo(f"  {k:<25} {v}")
            return

        # Запрос по пакету
        if version is None:
            # Без версии — показываем все advisories, в которых упомянут пакет
            # (через ANY-match: используем version="0" чтобы _в большинстве случаев_
            # выбрать только malicious; для полноты добавим перечисление affected
            # ranges как контекст в выводе)
            click.echo(f"All advisories mentioning '{package}' (use --version for matching):")
            # Используем фактический запрос: версии 0 хватит для MAL,
            # для CVE-диапазонов нужно перечисление — не делаем здесь, чтобы не
            # тянуть SQL-инспекцию из публичного API. Подсказка:
            click.echo("  (this view shows packages where ANY version is malicious;")
            click.echo("   pin a version with --version to see range-matching CVEs)")
            advs = db.find_advisories_for(package, "0")
            for a in advs:
                tag = "MAL" if a.is_malicious else "CVE"
                click.echo(f"  [{tag}] {a.id} [{a.severity}] {a.summary[:80]}")
            click.echo(f"  total: {len(advs)}")
            return

        advs = db.find_advisories_for(package, version)
        click.echo(f"Advisories matching {package}=={version}:")
        if not advs:
            click.echo("  (none)")
            return
        for a in advs:
            tag = "MAL" if a.is_malicious else "CVE"
            aliases = ", ".join(a.aliases[:3]) if a.aliases else ""
            click.echo(f"  [{tag}] {a.id} [{a.severity}]")
            if aliases:
                click.echo(f"      aliases: {aliases}")
            if a.summary:
                click.echo(f"      {a.summary[:120]}")


@main.command(name="sbom")
@click.argument(
    "path",
    type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=Path),
)
@click.option(
    "-o", "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write SBOM to file instead of stdout (recommended: model_sbom.json)",
)
@click.option(
    "--min-severity",
    type=click.Choice(SEVERITY_CHOICES),
    default="medium",
    show_default=True,
    help="Include findings with at least this severity as vulnerabilities",
)
@click.option(
    "--no-deps", is_flag=True, default=False,
    help="Don't parse requirements.txt files",
)
@click.option(
    "-c", "--config", "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to .ml-guard.yml",
)
def sbom_cmd(
    path: Path,
    output: Path | None,
    min_severity: str,
    no_deps: bool,
    config_path: Path | None,
) -> None:
    """Scan PATH and emit a CycloneDX 1.5 SBOM (Software Bill of Materials).

    Suitable as a compliance attachment for EU AI Act / Cyber Resilience Act
    audits. Includes ML artifacts (with SHA-256), Python dependencies parsed
    from requirements.txt, and findings as vulnerabilities.
    """
    from ml_guard.config import load_config
    from ml_guard.sbom import build_sbom_json

    cfg = load_config(explicit_path=config_path, scan_root=path)
    runner = Runner(config=cfg)
    result = runner.run(path)

    sbom_json = build_sbom_json(
        result,
        scan_root=path,
        include_dependencies=not no_deps,
        min_severity=Severity(min_severity),
    )

    if output is not None:
        output.write_text(sbom_json, encoding="utf-8")
        click.echo(f"Wrote CycloneDX SBOM to {output}")
    else:
        click.echo(sbom_json)


if __name__ == "__main__":
    main()
