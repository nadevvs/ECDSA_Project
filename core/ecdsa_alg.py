from core.curve import get_p256_curve, point_add, scalar_mult, is_on_curve
from core.field import mod_inv
from core.hashing import hash_message
from core.keygen import generate_private_key


def sign_message(
    message: str,
    private_key: int,
    nonce: int | None = None,
    debug_trace: list[str] | None = None,
    math_trace: list[str] | None = None
):
    # sign msg with p-256 ecdsa
    curve = get_p256_curve()
    combined_trace = debug_trace is not None and debug_trace is math_trace

    if not (1 <= private_key <= curve.n - 1):
        raise ValueError("Private key must be in range [1, n - 1].")

    if debug_trace is not None:
        debug_trace.append(f"loaded curve {curve.name.lower()}, n = {curve.n}")

    e = hash_message(message)
    if debug_trace is not None and not combined_trace:
        debug_trace.append(f"hashed message, e = {e}")
    if math_trace is not None:
        math_trace.append(f"hash_message: input = {message}, sha256 integer = {e}")

    while True:
        if nonce is None:
            k = generate_private_key(curve.n)
            if debug_trace is not None:
                debug_trace.append(f"generated nonce k = {k}")
        else:
            k = nonce
            if not (1 <= k <= curve.n - 1):
                raise ValueError("Nonce must be in range [1, n - 1].")
            if debug_trace is not None:
                debug_trace.append(f"using nonce k = {k}")

        point_r = scalar_mult(
            k,
            curve.g,
            curve,
            math_trace,
            "k",
            "g",
            "r_point"
        )
        if debug_trace is not None and not combined_trace:
            debug_trace.append(
                f"computed r point: r_point = k * g, "
                f"r_point.x = {point_r.x}, r_point.y = {point_r.y}"
            )

        r = point_r.x % curve.n
        if debug_trace is not None:
            debug_trace.append(f"computed r = r_point.x mod n = {r}")

        # r can not be zero in valid sign
        if r == 0:
            if nonce is not None:
                raise ValueError("Invalid nonce: produced r = 0.")
            continue

        k_inv = mod_inv(k, curve.n, math_trace, "k", "n")
        if debug_trace is not None and not combined_trace:
            debug_trace.append(f"computed k inverse, k_inv = {k_inv}")

        s = (k_inv * (e + private_key * r)) % curve.n
        if debug_trace is not None and not combined_trace:
            debug_trace.append(
                f"computed s = k_inv * (e + private_key * r) mod n = {s}"
            )
        if math_trace is not None:
            math_trace.append(
                f"signature formula: s = k_inv * (e + private_key * r) mod n, result = {s}"
            )

        # s can not be zero in valid sign
        if s == 0:
            if nonce is not None:
                raise ValueError("Invalid nonce: produced s = 0.")
            continue

        return r, s


def verify_signature(
    message: str,
    public_key,
    signature,
    debug_trace: list[str] | None = None,
    math_trace: list[str] | None = None
):
    # verif
    curve = get_p256_curve()
    combined_trace = debug_trace is not None and debug_trace is math_trace
    r, s = signature
    if debug_trace is not None:
        debug_trace.append(f"loaded curve {curve.name.lower()}, n = {curve.n}")

    # sign nums must be in subgroup range
    if not (1 <= r <= curve.n - 1 and 1 <= s <= curve.n - 1):
        if debug_trace is not None:
            debug_trace.append("checked signature range: invalid")
        return False
    if debug_trace is not None:
        debug_trace.append("checked signature range: r ok, s ok")

    # pubkey must be valid curve point
    public_key_valid = (
        not public_key.infinity and
        is_on_curve(public_key, curve, math_trace, "q")
    )
    if not public_key_valid:
        if debug_trace is not None:
            debug_trace.append("checked public key on curve: false")
        return False
    if debug_trace is not None:
        debug_trace.append("checked public key on curve: true")

    e = hash_message(message)
    if debug_trace is not None and not combined_trace:
        debug_trace.append(f"hashed message, e = {e}")
    if math_trace is not None:
        math_trace.append(f"hash_message: input = {message}, sha256 integer = {e}")

    w = mod_inv(s, curve.n, math_trace, "s", "n")
    if debug_trace is not None and not combined_trace:
        debug_trace.append(f"computed w = s^-1 mod n = {w}")

    # build verif scalars
    u1 = (e * w) % curve.n
    u2 = (r * w) % curve.n
    if debug_trace is not None:
        debug_trace.append(f"computed u1 = e * w mod n = {u1}")
        debug_trace.append(f"computed u2 = r * w mod n = {u2}")

    # x = u1*g + u2*q
    point_1 = scalar_mult(
        u1,
        curve.g,
        curve,
        math_trace,
        "u1",
        "g",
        "point_1"
    )
    point_2 = scalar_mult(
        u2,
        public_key,
        curve,
        math_trace,
        "u2",
        "q",
        "point_2"
    )
    point_x = point_add(
        point_1,
        point_2,
        curve,
        math_trace,
        "point_1",
        "point_2"
    )
    if debug_trace is not None and not combined_trace:
        debug_trace.append(
            f"computed point x = u1*g + u2*q, point_x.x = {point_x.x}, point_x.y = {point_x.y}"
        )

    if point_x.infinity:
        if debug_trace is not None:
            debug_trace.append("computed point x is infinity, result = invalid")
        return False

    result = (point_x.x % curve.n) == r
    if debug_trace is not None:
        debug_trace.append(
            f"compared point_x.x mod n = {point_x.x % curve.n} with r = {r}, "
            f"result = {'valid' if result else 'invalid'}"
        )

    return result
