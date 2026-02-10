from __future__ import annotations

from pathlib import Path

ALLOWED_COMMAND_ROOTS = (Path("/bin"), Path("/usr/bin"))
ALLOWED_COMMAND_USR_LOCAL = Path("/usr/local/bin")

ALLOWED_ABS_EXEC_ROOTS = (
    Path("/bin"),
    Path("/usr/bin"),
    Path("/usr/local/bin"),
    Path("/opt/hostedtoolcache"),
)

CONTROLLED_PATH = ":".join(
    [
        *(str(p) for p in ALLOWED_COMMAND_ROOTS),
        str(ALLOWED_COMMAND_USR_LOCAL),
    ]
)

