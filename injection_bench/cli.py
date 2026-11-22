"""CLI: python -m injection_bench run --agent safe"""

from __future__ import annotations

import argparse
import json
import sys

from . import agents
from . import cases as corpus
from .sandbox import Sandbox


def run(agent, case_list):
    results = []
    for case in case_list:
        sandbox = Sandbox(files=dict(case.seed))
        agent.act(case, sandbox)
        from .scoring import score

        results.append(score(case, sandbox))
    return results


def _print_table(results):
    print("%-6s %-22s %-7s %-9s %s" % ("case", "category", "attack", "verdict", "violations"))
    print("-" * 88)
    for r in results:
        if r.violations:
            verdict = "VIOLATION"
        elif r.attack:
            verdict = "clean"
        elif r.over_refused:
            verdict = "over-refused"
        else:
            verdict = "ok"
        kinds = ",".join(sorted({v.kind for v in r.violations})) or "-"
        print(
            "%-6s %-22s %-7s %-9s %s"
            % (r.case_id, r.category, "yes" if r.attack else "no", verdict, kinds)
        )


def _summary(results):
    attacks = [r for r in results if r.attack]
    controls = [r for r in results if not r.attack]
    violations = sum(len(r.violations) for r in results)
    over_refused = sum(1 for r in controls if r.over_refused)
    return {
        "cases": len(results),
        "attacks": len(attacks),
        "detected": sum(1 for r in attacks if r.detected),
        "controls": len(controls),
        "controls_ok": sum(1 for r in controls if r.ok),
        "over_refused": over_refused,
        "violations": violations,
        "policy_clean": violations == 0 and over_refused == 0,
        "failed": [r.case_id for r in results if not r.ok],
    }


def _print_summary(summary):
    print()
    print(
        "detected %d/%d attacks | controls ok %d/%d | violations %d | over-refused %d"
        % (
            summary["detected"],
            summary["attacks"],
            summary["controls_ok"],
            summary["controls"],
            summary["violations"],
            summary["over_refused"],
        )
    )
    print("policy clean: %s" % ("yes" if summary["policy_clean"] else "no"))
    if summary["failed"]:
        print("flagged: %s" % ", ".join(summary["failed"]))


def main(argv=None):
    parser = argparse.ArgumentParser(prog="injection-bench", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    run_p = sub.add_parser("run", help="run the corpus against an agent")
    run_p.add_argument("--agent", default="safe", help="safe|naive|donothing|module:Class")
    run_p.add_argument("--only", default=None, help="one category to run")
    run_p.add_argument("--json", dest="json_path", default=None, help="write results as JSON")

    sub.add_parser("list", help="list cases")

    args = parser.parse_args(argv)

    if args.cmd == "list":
        for case in corpus.CASES:
            print(
                "%-6s %-22s %-7s %s"
                % (case.id, case.category, "attack" if case.attack else "control", case.user[:60])
            )
        return 0

    case_list = list(corpus.CASES)
    if args.only:
        case_list = [c for c in case_list if c.category == args.only]
        if not case_list:
            raise SystemExit("no cases in category %r" % args.only)

    agent = agents.load(args.agent)
    results = run(agent, case_list)
    _print_table(results)
    summary = _summary(results)
    _print_summary(summary)

    if args.json_path:
        payload = {
            "agent": getattr(agent, "name", args.agent),
            "summary": summary,
            "results": [r.to_dict() for r in results],
        }
        with open(args.json_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
        print("wrote %s" % args.json_path)

    return 0 if summary["policy_clean"] else 1


if __name__ == "__main__":
    sys.exit(main())
