import argparse
import json
import os
import sys
from pathlib import Path

from .spec import (
    ValidationError,
    collect_reserved_field_warnings,
    load_spec,
    validate_spec,
)
from .orchestrator_v1 import run_case
from .campaign_runner_v1 import run_campaign
from .evaluator_v1 import eval_run_v1
from .redteam_corpus import MAX_CASE_COUNT, MIN_CASE_COUNT
from .redteam_generation import (
    MAX_OUTPUT_TOKENS,
    BudgetState,
    GenerationError,
    GenerationResult,
    generate_and_persist_corpus,
)
from .redteam_run import (
    TARGET_NAMES,
    RedTeamRunError,
    RedTeamRunValidationError,
    canonical_run_cli_output,
    run_accepted_corpus,
)
from .triage_dedup_v1 import triage_campaign_v1


_REDTEAM_DEFAULT_CASE_COUNT = 16


def _get_version() -> str:
    try:
        from importlib import metadata
    except Exception:
        metadata = None  # type: ignore[assignment]

    if metadata is not None:
        try:
            return str(metadata.version("plutonus-llmfuzz"))
        except Exception:
            pass

    try:
        import tomllib

        here = Path(__file__).resolve()
        repo_root = here.parents[2]
        pyproject = repo_root / "pyproject.toml"
        if not pyproject.exists():
            pyproject = here.parents[1] / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        project = data.get("project")
        if isinstance(project, dict):
            v = project.get("version")
            if isinstance(v, str) and v:
                return v
    except Exception:
        pass

    return "unknown"


def _stub(phase_session):
    print(f"Not implemented (Phase 3 Session {phase_session})")
    raise SystemExit(2)


def _handle_validate(args):
    try:
        raw = load_spec(args.spec)
        spec = validate_spec(raw)
        fields = collect_reserved_field_warnings(spec)
        if fields:
            if args.strict:
                print(
                    "spec: reserved fields not implemented (strict): " + ", ".join(fields),
                    file=sys.stderr,
                )
                raise SystemExit(2)
            print(
                "warning: reserved fields not implemented: " + ", ".join(fields),
                file=sys.stderr,
            )
    except ValidationError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from exc
    except Exception as exc:
        print(f"spec: unexpected error ({exc.__class__.__name__})", file=sys.stderr)
        raise SystemExit(2)
    return 0


def _handle_run(args):
    try:
        result = run_case(
            Path(args.spec),
            case_index=args.case_index,
            run_id=args.run_id,
            dry_run=args.dry_run,
        )
    except ValidationError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from exc
    except Exception as exc:
        print(f"run: unexpected error ({exc.__class__.__name__})", file=sys.stderr)
        raise SystemExit(1)
    print(str(result.run_dir))
    print(str(result.failure_record_path))
    return 0


def _handle_run_one(args):
    try:
        result = run_case(
            Path(args.spec),
            case_index=0,
            run_id=args.run_id,
            dry_run=args.dry_run,
        )
    except ValidationError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from exc
    except Exception as exc:
        print(f"run-one: unexpected error ({exc.__class__.__name__})", file=sys.stderr)
        raise SystemExit(1)
    print(str(result.run_dir))
    print(str(result.failure_record_path))
    return 0


def _handle_campaign(args):
    try:
        result = run_campaign(
            spec_path=Path(args.spec),
            cases=int(args.cases),
            start_index=int(args.start_index),
            exec_cases=bool(args.exec),
            timeout_s=(int(args.timeout_s) if args.timeout_s is not None else None),
            campaign_id=args.campaign_id,
            stop_on=args.stop_on,
            resume=bool(args.resume),
        )
    except ValidationError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from exc
    except Exception as exc:
        print(
            f"campaign: unexpected error ({exc.__class__.__name__}): {exc}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    print(str(result.campaign_id))
    print(str(result.campaign_root))
    return 0


def _handle_eval_run(args):
    try:
        result = eval_run_v1(
            Path(args.work_root_base),
            run_id=args.run_id,
            patch_failure_record=bool(args.patch_failure_record),
        )
    except Exception as exc:
        print(f"eval-run: unexpected error ({exc.__class__.__name__}): {exc}", file=sys.stderr)
        raise SystemExit(1)
    print(str(result.get("signature_v1", "")))
    return 0


def _parse_boolish(value: str) -> bool:
    v = str(value).strip().lower()
    if v in ("true", "1", "yes", "y", "on"):
        return True
    if v in ("false", "0", "no", "n", "off"):
        return False
    raise ValueError("expected true/false")


def _handle_triage_campaign(args):
    try:
        triage_campaign_v1(
            Path(args.work_root_base),
            campaign_id=args.campaign_id,
            top_k=int(args.top_k),
            include_pass=args.include_pass,
            write_md=args.write_md,
            patch_summary=args.patch_summary,
        )
    except Exception as exc:
        print(
            f"triage-campaign: unexpected error ({exc.__class__.__name__}): {exc}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return 0


def _create_redteam_provider():
    from .redteam_openai import create_openai_provider

    return create_openai_provider()


def _redteam_error_message(error: GenerationError) -> str:
    try:
        code = error.code
    except Exception:
        code = "provider_error"
    return str(GenerationError(code if isinstance(code, str) else "provider_error"))


def _redteam_local_error(args) -> GenerationError | None:
    if args.cases < MIN_CASE_COUNT or args.cases > MAX_CASE_COUNT:
        return GenerationError("invalid_configuration")
    if args.max_output_tokens < 1 or args.max_output_tokens > MAX_OUTPUT_TOKENS:
        return GenerationError("invalid_configuration")
    try:
        if not args.output or "\0" in args.output:
            return GenerationError("destination_invalid")
        destination = Path(args.output)
        if os.path.lexists(destination):
            return GenerationError("destination_exists")
        ancestor = destination.parent
        while not os.path.lexists(ancestor):
            parent = ancestor.parent
            if parent == ancestor:
                break
            ancestor = parent
        if os.path.lexists(ancestor):
            if not ancestor.is_dir():
                return GenerationError("destination_invalid")
            mode = os.W_OK | os.X_OK
            if os.access in os.supports_effective_ids:
                writable = os.access(ancestor, mode, effective_ids=True) is True
            else:
                writable = os.access(ancestor, mode) is True
            if not writable:
                return GenerationError("destination_invalid")
    except Exception:
        return GenerationError("destination_invalid")
    return None


def _redteam_success_output(result: GenerationResult) -> str:
    evidence = result.evidence
    return json.dumps(
        {
            "actual_estimated_cost_usd": (
                None
                if evidence.actual_estimated_cost_usd is None
                else str(evidence.actual_estimated_cost_usd)
            ),
            "attempts_consumed": evidence.attempts_consumed,
            "corpus_path": str(result.path),
            "corpus_sha256": result.corpus.corpus_sha256,
            "generated_case_count": len(result.corpus.cases),
            "input_tokens": evidence.actual_input_tokens,
            "output_tokens": evidence.actual_output_tokens,
            "reserved_maximum_cost_usd": str(evidence.reserved_maximum_cost_usd),
            "total_tokens": evidence.actual_total_tokens,
        },
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def _handle_redteam_generate(args):
    local_error = _redteam_local_error(args)
    if local_error is not None:
        print(f"redteam generate: {local_error}", file=sys.stderr)
        raise SystemExit(2)

    provider = None
    initialization_error: str | None = None
    try:
        provider = _create_redteam_provider()
    except GenerationError as exc:
        initialization_error = _redteam_error_message(exc)
    except Exception:
        initialization_error = "OpenAI provider initialization failed."
    if initialization_error is not None:
        print(f"redteam generate: {initialization_error}", file=sys.stderr)
        raise SystemExit(1)

    primary_error: str | None = None
    output: str | None = None
    cleanup_failed = False
    try:
        try:
            result = generate_and_persist_corpus(
                provider=provider,
                path=args.output,
                case_count=args.cases,
                max_output_tokens=args.max_output_tokens,
                budget_state=BudgetState(),
            )
            output = _redteam_success_output(result)
        except GenerationError as exc:
            primary_error = _redteam_error_message(exc)
        except Exception:
            primary_error = "Red Team corpus generation failed."
    finally:
        primary_active = sys.exception() is not None
        try:
            provider.close()
        except BaseException as cleanup_error:
            if primary_active:
                pass
            elif isinstance(cleanup_error, Exception):
                cleanup_failed = True
            else:
                raise

    if primary_error is not None:
        print(f"redteam generate: {primary_error}", file=sys.stderr)
        raise SystemExit(1)
    if cleanup_failed:
        print("redteam generate: OpenAI provider cleanup failed.", file=sys.stderr)
        raise SystemExit(1)
    if output is None:
        print("redteam generate: Red Team corpus generation failed.", file=sys.stderr)
        raise SystemExit(1)
    print(output)
    return 0


def _handle_redteam_run(args):
    try:
        result = run_accepted_corpus(
            target=args.target,
            output=args.output,
            corpus_path=args.corpus,
        )
    except RedTeamRunValidationError as exc:
        print(f"redteam run: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    except RedTeamRunError as exc:
        print(f"redteam run: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    except Exception:
        print("redteam run: Red Team execution failed.", file=sys.stderr)
        raise SystemExit(1) from None
    if not result.completed:
        print("redteam run: execution did not complete.", file=sys.stderr)
        raise SystemExit(1)
    print(canonical_run_cli_output(result))
    return 0


def _build_parser():
    parser = argparse.ArgumentParser(prog="llmfuzz")
    parser.add_argument("--version", action="version", version=_get_version())
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="Validate inputs")
    validate_parser.add_argument("--spec", required=True, help="Path to fuzzspec JSON")
    validate_parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on reserved fields (non-default values)",
    )
    validate_parser.set_defaults(handler=_handle_validate)

    run_parser = subparsers.add_parser("run", help="Run one fuzz case")
    run_parser.add_argument("--spec", required=True, help="Path to fuzzspec JSON")
    run_parser.add_argument("--case-index", type=int, required=True)
    run_parser.add_argument("--run-id")
    run_parser.add_argument("--dry-run", action="store_true")
    run_parser.set_defaults(handler=_handle_run)

    run_one_parser = subparsers.add_parser("run-one", help="Run one fuzz case")
    run_one_parser.add_argument("--spec", required=True, help="Path to fuzzspec JSON")
    run_one_parser.add_argument("--run-id")
    run_one_parser.add_argument("--dry-run", action="store_true")
    run_one_parser.set_defaults(handler=_handle_run_one)

    campaign_parser = subparsers.add_parser("campaign", help="Run campaign")
    campaign_parser.add_argument("--spec", required=True, help="Path to fuzzspec JSON")
    campaign_parser.add_argument("--cases", type=int, required=True)
    campaign_parser.add_argument("--start-index", type=int, default=0)
    campaign_parser.add_argument("--exec", action="store_true")
    campaign_parser.add_argument("--timeout-s", type=int)
    campaign_parser.add_argument("--campaign-id")
    campaign_parser.add_argument("--stop-on", default="FAIL,TIMEOUT")
    campaign_parser.add_argument("--resume", action="store_true")
    campaign_parser.set_defaults(handler=_handle_campaign)

    eval_run_parser = subparsers.add_parser("eval-run", help="Evaluate one run")
    eval_run_parser.add_argument("--work-root-base", required=True)
    eval_run_parser.add_argument("--run-id", required=True)
    eval_run_parser.add_argument("--patch-failure-record", action="store_true")
    eval_run_parser.set_defaults(handler=_handle_eval_run)

    triage_parser = subparsers.add_parser("triage-campaign", help="Triage + dedup campaign")
    triage_parser.add_argument("--work-root-base", required=True)
    triage_parser.add_argument("--campaign-id", required=True)
    triage_parser.add_argument("--top-k", type=int, default=50)
    triage_parser.add_argument("--include-pass", type=_parse_boolish, default=False)
    triage_parser.add_argument("--write-md", type=_parse_boolish, default=True)
    triage_parser.add_argument("--patch-summary", type=_parse_boolish, default=True)
    triage_parser.set_defaults(handler=_handle_triage_campaign)

    replay_parser = subparsers.add_parser("replay", help="Replay run")
    replay_parser.set_defaults(handler=lambda _args: _stub(5))

    redteam_parser = subparsers.add_parser("redteam", help="Red Team corpus operations")
    redteam_subparsers = redteam_parser.add_subparsers(
        dest="redteam_command",
        required=True,
    )
    generate_parser = redteam_subparsers.add_parser(
        "generate",
        help="Generate and persist an adversarial corpus",
    )
    generate_parser.add_argument(
        "--output",
        required=True,
        help="New corpus JSON destination",
    )
    generate_parser.add_argument(
        "--cases",
        type=int,
        default=_REDTEAM_DEFAULT_CASE_COUNT,
        help=(
            f"Case count ({MIN_CASE_COUNT}-{MAX_CASE_COUNT}; "
            f"default: {_REDTEAM_DEFAULT_CASE_COUNT})"
        ),
    )
    generate_parser.add_argument(
        "--max-output-tokens",
        type=int,
        default=MAX_OUTPUT_TOKENS,
        help=f"Maximum output tokens (1-{MAX_OUTPUT_TOKENS}; default: {MAX_OUTPUT_TOKENS})",
    )
    generate_parser.set_defaults(handler=_handle_redteam_generate)

    redteam_run_parser = redteam_subparsers.add_parser(
        "run",
        help="Execute the accepted corpus against a deterministic demo target",
    )
    redteam_run_parser.add_argument(
        "--target",
        required=True,
        choices=TARGET_NAMES,
        help="Locked demo target policy",
    )
    redteam_run_parser.add_argument(
        "--output",
        required=True,
        help="New Red Team execution output root",
    )
    redteam_run_parser.add_argument(
        "--corpus",
        help="Optional exact accepted corpus path",
    )
    redteam_run_parser.set_defaults(handler=_handle_redteam_run)

    return parser


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    main(sys.argv[1:])
