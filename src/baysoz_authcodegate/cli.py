# Baysöz Labs <baysozlabs@proton.me> — baysoz-authcodegate
"""Command-line entry point for baysoz-authcodegate by Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path

from .corpus import make_corpus
from .model import Bundle
from .oracle import audit_bundle
from .rules import RULE_CATALOG
from .sarif import build_sarif, summarize
from .tribunal import convene
from .version import PROJECT, VENDOR, VERSION


def _banner() -> None:
    print(f"{PROJECT} {VERSION} — {VENDOR}", file=sys.stderr)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROJECT,
        description=(
            "Offline OAuth 2.1 / OIDC authorization-code conformance oracle. "
            "Audits PKCE, redirect, replay, audience and DPoP bindings with SARIF gates."
        ),
        epilog=f"Built by {VENDOR}. No network calls, no services, no local models.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"{PROJECT} {VERSION} — {VENDOR}")
    commands = parser.add_subparsers(dest="command", required=True)

    audit = commands.add_parser(
        "audit",
        help="audit a bundle of captured authorization and token exchanges",
        epilog=f"Built by {VENDOR}.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    audit.add_argument("--input", required=True, type=Path, help="bundle JSON file")
    audit.add_argument("--sarif", type=Path, help="write SARIF 2.1.0 findings to this file")
    audit.add_argument("--now", type=int, help="override the evaluation timestamp (epoch seconds)")
    audit.set_defaults(handler=_audit)

    forge = commands.add_parser(
        "forge",
        help="emit the deterministic adversarial corpus and signed DPoP evidence",
        epilog=f"Built by {VENDOR}.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    forge.add_argument("--output", type=Path, help="write corpus JSON to this file instead of stdout")
    forge.set_defaults(handler=_forge)

    selftest = commands.add_parser(
        "selftest",
        help="run every adversarial case against the live oracle",
        epilog=f"Built by {VENDOR}.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    selftest.set_defaults(handler=_selftest)

    tribunal = commands.add_parser(
        "tribunal",
        help="convene the Supreme Grand Jury Tribunal over the adversarial corpus",
        epilog=f"Built by {VENDOR}.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    tribunal.set_defaults(handler=_tribunal)

    rules = commands.add_parser(
        "rules",
        help="print the normative rule catalogue",
        epilog=f"Built by {VENDOR}.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    rules.set_defaults(handler=_rules)
    return parser


def _audit(args: argparse.Namespace) -> int:
    _banner()
    document = json.loads(args.input.read_text(encoding="utf-8"))
    bundle = Bundle.from_mapping(document)
    if args.now is not None:
        bundle = replace(bundle, policy=replace(bundle.policy, now=args.now))
    evaluations = audit_bundle(bundle)
    report = build_sarif(evaluations, source_name=f"audit {args.input}")
    if args.sarif is not None:
        args.sarif.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    summary = summarize(evaluations)
    print(
        f"AUDIT issuer={bundle.policy.issuer} evaluated={summary['evaluated']} "
        f"allowed={summary['allowed']} denied={summary['denied']} findings={summary['findings']}"
    )
    for evaluation in evaluations:
        for finding in evaluation.findings:
            print(f"  {finding.rule_id} {finding.severity.value:<8} {evaluation.label}: {finding.title}")
    if args.sarif is not None:
        print(f"SARIF written to {args.sarif}")
    print(f"STATUS: {'PASS' if summary['findings'] == 0 else 'FAIL'} — {VENDOR}")
    return 0 if summary["findings"] == 0 else 1


def _forge(args: argparse.Namespace) -> int:
    _banner()
    document = json.dumps(make_corpus().to_document(), indent=2, ensure_ascii=False, sort_keys=True)
    if args.output is not None:
        args.output.write_text(document + "\n", encoding="utf-8")
        print(f"CORPUS written to {args.output} — {VENDOR}")
    else:
        print(document)
    return 0


def _selftest(args: argparse.Namespace) -> int:
    _banner()
    from .corpus import run_corpus

    results = run_corpus(make_corpus())
    for result in results:
        observed = result.evaluation.verdict.value
        rule = result.case.expected_rule or "-"
        status = "PASS" if result.passed else "FAIL"
        print(
            f"[{status}] {result.case.label} "
            f"expected={result.case.expected_verdict.value} observed={observed} rule={rule}"
        )
    passed = sum(1 for result in results if result.passed)
    print(f"SELFTEST: {passed}/{len(results)} adversarial cases concur — {VENDOR}")
    return 0 if passed == len(results) else 1


def _tribunal(args: argparse.Namespace) -> int:
    _banner()
    jurors, unanimous = convene()
    print("Supreme Grand Jury Tribunal — Baysöz Labs <baysozlabs@proton.me>")
    for juror in jurors:
        print(f"  {'PASS' if juror.passed else 'FAIL'} {juror.name}: {juror.detail}")
    print(f"VERDICT: {'UNANIMOUS PASS' if unanimous else 'NOT UNANIMOUS'} — {VENDOR}")
    return 0 if unanimous else 1


def _rules(args: argparse.Namespace) -> int:
    _banner()
    for rule in RULE_CATALOG.values():
        print(f"{rule.id} {rule.severity.value:<8} {rule.title} — {VENDOR}")
    print(f"CATALOGUE: {len(RULE_CATALOG)} rules — {VENDOR}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
        handler = getattr(args, "handler", None)
        if handler is None:
            parser.print_help()
            return 2
        return handler(args)
    except (ValueError, OSError) as error:
        print(f"ERROR: {error} — {VENDOR}", file=sys.stderr)
        return 2
