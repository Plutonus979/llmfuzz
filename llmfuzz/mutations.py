from dataclasses import dataclass
import base64
import hashlib
import json
import random

ALLOWED_OPS = ["flip_bit", "flip_byte", "truncate_tail", "append_bytes"]
MIN_LEN = 256


@dataclass(frozen=True)
class Mutation:
    op: str
    offset: int | None
    length: int | None
    value_b64: str | None
    note: str | None


@dataclass(frozen=True)
class MutationMeta:
    ops_count: int


def hash_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _effective_len(current_len: int, max_bytes: int | None) -> int:
    if max_bytes is None:
        return current_len
    return min(current_len, max_bytes)


def _feasible_ops(
    current_len: int,
    max_bytes: int | None,
    allowed_ops: list[str],
) -> list[str]:
    feasible: list[str] = []
    effective_len = _effective_len(current_len, max_bytes)
    for op in allowed_ops:
        if op in ("flip_bit", "flip_byte"):
            if effective_len > 0:
                feasible.append(op)
        elif op == "truncate_tail":
            if current_len > MIN_LEN:
                feasible.append(op)
        elif op == "append_bytes":
            if max_bytes is None or current_len < max_bytes:
                feasible.append(op)
    return feasible


def generate_case(
    seed_bytes: bytes,
    rng_seed: int,
    *,
    max_bytes: int | None,
    max_ops_per_case: int | None,
    allowed_ops: list[str] | None = None,
    return_meta: bool = False,
) -> list[Mutation] | tuple[list[Mutation], MutationMeta]:
    rng = random.Random(rng_seed)
    muts: list[Mutation] = []
    current_len = len(seed_bytes)
    ops_limit = 1 if max_ops_per_case is None else max_ops_per_case
    if ops_limit <= 0:
        meta = MutationMeta(ops_count=0)
        return (muts, meta) if return_meta else muts

    allowed = ALLOWED_OPS if allowed_ops is None else list(allowed_ops)
    ops_count = 0
    while ops_count < ops_limit:
        feasible = _feasible_ops(current_len, max_bytes, allowed)
        if not feasible:
            break
        op = rng.choice(feasible)
        effective_len = _effective_len(current_len, max_bytes)
        if op == "flip_bit":
            bit_offset = rng.randrange(effective_len * 8)
            muts.append(
                Mutation(
                    op=op,
                    offset=bit_offset,
                    length=None,
                    value_b64=None,
                    note=None,
                )
            )
            ops_count += 1
        elif op == "flip_byte":
            byte_offset = rng.randrange(effective_len)
            muts.append(
                Mutation(
                    op=op,
                    offset=byte_offset,
                    length=None,
                    value_b64=None,
                    note=None,
                )
            )
            ops_count += 1
        elif op == "truncate_tail":
            max_remove = current_len - MIN_LEN
            if max_remove <= 0:
                break
            length = 1 if max_remove == 1 else rng.randrange(1, max_remove + 1)
            muts.append(
                Mutation(
                    op=op,
                    offset=None,
                    length=length,
                    value_b64=None,
                    note=None,
                )
            )
            current_len -= length
            ops_count += 1
        elif op == "append_bytes":
            if max_bytes is None:
                length = 1
            else:
                max_add = max_bytes - current_len
                if max_add <= 0:
                    break
                length = rng.randrange(1, max_add + 1)
            payload = bytes(rng.randrange(256) for _ in range(length))
            value_b64 = base64.b64encode(payload).decode("ascii")
            muts.append(
                Mutation(
                    op=op,
                    offset=None,
                    length=length,
                    value_b64=value_b64,
                    note=None,
                )
            )
            current_len += length
            ops_count += 1
        else:
            break

    meta = MutationMeta(ops_count=ops_count)
    return (muts, meta) if return_meta else muts


def apply_mutations(
    seed_bytes: bytes,
    muts: list[Mutation],
    *,
    max_bytes: int | None = None,
) -> bytes:
    cur = bytearray(seed_bytes)
    for mut in muts:
        op = mut.op
        if op == "flip_bit":
            if mut.offset is None or not isinstance(mut.offset, int):
                raise ValueError("flip_bit: offset required")
            if mut.offset < 0 or mut.offset >= len(cur) * 8:
                raise ValueError("flip_bit: offset out of range")
            byte_index = mut.offset // 8
            bit_in_byte = mut.offset % 8
            cur[byte_index] ^= 1 << bit_in_byte
        elif op == "flip_byte":
            if mut.offset is None or not isinstance(mut.offset, int):
                raise ValueError("flip_byte: offset required")
            if mut.offset < 0 or mut.offset >= len(cur):
                raise ValueError("flip_byte: offset out of range")
            cur[mut.offset] ^= 0xFF
        elif op == "truncate_tail":
            if mut.length is None or not isinstance(mut.length, int):
                raise ValueError("truncate_tail: length required")
            if mut.length <= 0:
                raise ValueError("truncate_tail: length must be positive")
            new_len = len(cur) - mut.length
            if new_len < MIN_LEN:
                raise ValueError("truncate_tail: would go below MIN_LEN")
            del cur[new_len:]
        elif op == "append_bytes":
            if mut.length is None or not isinstance(mut.length, int):
                raise ValueError("append_bytes: length required")
            if mut.length <= 0:
                raise ValueError("append_bytes: length must be positive")
            if mut.value_b64 is None:
                raise ValueError("append_bytes: value_b64 required")
            try:
                decoded = base64.b64decode(mut.value_b64, validate=True)
            except Exception as exc:
                raise ValueError("append_bytes: invalid base64") from exc
            if len(decoded) != mut.length:
                raise ValueError("append_bytes: length mismatch")
            cur.extend(decoded)
        else:
            raise ValueError(f"unknown op: {op}")
    if max_bytes is not None and len(cur) > max_bytes:
        del cur[max_bytes:]
    return bytes(cur)


def mutations_to_jsonl(muts: list[Mutation]) -> str:
    lines: list[str] = []
    for i, mut in enumerate(muts):
        obj: dict[str, object] = {"i": i, "op": mut.op}
        if mut.offset is not None:
            obj["offset"] = mut.offset
        if mut.length is not None:
            obj["length"] = mut.length
        if mut.value_b64 is not None:
            obj["value_b64"] = mut.value_b64
        lines.append(json.dumps(obj, sort_keys=True, separators=(",", ":")))
    return "\n".join(lines)
