import secrets
from core.curve import get_p256_curve, is_on_curve, scalar_mult


def generate_private_key(n: int) -> int:
    # random private key in [1, n - 1]
    return secrets.randbelow(n - 1) + 1


def generate_keypair(
    private_key: int | None = None,
    debug_trace: list[str] | None = None,
    math_trace: list[str] | None = None
):
    # generate or validate private key
    curve = get_p256_curve()
    combined_trace = debug_trace is not None and debug_trace is math_trace

    if debug_trace is not None:
        debug_trace.append(f"loaded curve {curve.name.lower()}")

    if private_key is None:
        private_key = generate_private_key(curve.n)
        if debug_trace is not None:
            debug_trace.append(f"generated private key d = {private_key}")
    else:
        if not (1 <= private_key <= curve.n - 1):
            raise ValueError("Private key must be in the range [1, n - 1].")
        if debug_trace is not None:
            debug_trace.append(f"using private key d = {private_key}")

    # pubkey = privkey * g
    public_key = scalar_mult(
        private_key,
        curve.g,
        curve,
        math_trace,
        "d",
        "g",
        "q"
    )

    if debug_trace is not None and not combined_trace:
        debug_trace.append(
            f"computed public key q = d * g, q.x = {public_key.x}, q.y = {public_key.y}"
        )
        debug_trace.append(
            f"checked public key on curve: "
            f"{str(is_on_curve(public_key, curve, math_trace, 'q')).lower()}"
        )
    else:
        is_on_curve(public_key, curve, math_trace, "q")

    return private_key, public_key
