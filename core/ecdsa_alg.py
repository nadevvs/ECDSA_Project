from core.curve import get_p256_curve, point_add, scalar_mult
from core.field import mod_inv
from core.hashing import hash_message
from core.keygen import generate_private_key


def sign_message(message: str, private_key: int, nonce: int | None = None):
    curve = get_p256_curve()

    if not (1 <= private_key <= curve.n - 1):
        raise ValueError("Private key must be in the range [1, n - 1].")

    e = hash_message(message)

    while True:
        if nonce is None:
            k = generate_private_key(curve.n)
        else:
            k = nonce
            if not (1 <= k <= curve.n - 1):
                raise ValueError("Nonce must be in the range [1, n - 1].")

        point_r = scalar_mult(k, curve.g, curve)
        r = point_r.x % curve.n

        if r == 0:
            if nonce is not None:
                raise ValueError("Invalid nonce: produced r = 0.")
            continue

        k_inv = mod_inv(k, curve.n)
        s = (k_inv * (e + private_key * r)) % curve.n

        if s == 0:
            if nonce is not None:
                raise ValueError("Invalid nonce: produced s = 0.")
            continue

        return r, s


def verify_signature(message: str, public_key, signature):
    return
