import secrets
from core.curve import get_p256_curve, scalar_mult


def generate_private_key(n: int) -> int:
    return secrets.randbelow(n - 1) + 1


def generate_keypair(private_key: int | None = None):
    curve = get_p256_curve()

    if private_key is None:
        private_key = generate_private_key(curve.n)
    else:
        if not (1 <= private_key <= curve.n - 1):
            raise ValueError("Private key must be in the range [1, n - 1].")

    public_key = scalar_mult(private_key, curve.g, curve)
    return private_key, public_key
