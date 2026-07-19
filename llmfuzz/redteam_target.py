from __future__ import annotations

import sys

from .redteam_demo_target import (
    FIXED_POLICY,
    MAX_TARGET_INPUT_BYTES,
    VULNERABLE_POLICY,
    canonical_target_output_bytes,
    load_target_input_bytes,
    target_output_for,
)


_FAILURE_MESSAGE = "redteam target: invalid input or target failure\n"


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        if arguments == ["--target", "vulnerable"]:
            policy = VULNERABLE_POLICY
        elif arguments == ["--target", "fixed"]:
            policy = FIXED_POLICY
        else:
            raise ValueError("invalid arguments")
        data = sys.stdin.buffer.read(MAX_TARGET_INPUT_BYTES + 1)
        target_input = load_target_input_bytes(data)
        output = target_output_for(target_input, policy)
        sys.stdout.buffer.write(canonical_target_output_bytes(output))
        return 0
    except Exception:
        sys.stderr.write(_FAILURE_MESSAGE)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
