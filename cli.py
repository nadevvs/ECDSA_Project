import argparse

from core.keygen import generate_keypair
from core.ecdsa_alg import sign_message, verify_signature
from tests import run_all_tests


def handle_genkey(args):
    try:
        private_key, public_key = generate_keypair(args.private_key)
    except ValueError as error:
        print(f"Error: {error}")
        return

    print("=== KEY GENERATION ===")
    print(f"Curve: P-256")
    print(f"Private key: {private_key}")
    print("Public key: ")
    print(f"  x = {public_key.x}")
    print(f"  y = {public_key.y}")


def handle_sign(args):
    if args.private_key <= 0:
        print("Error: private key must be a positive integer.")
        return

    if args.nonce is not None and args.nonce <= 0:
        print("Error: nonce must be a positive integer.")
        return

    signature = sign_message(
        message=args.message,
        private_key=args.private_key,
        nonce=args.nonce
    )

    print("=== SIGNATURE GENERATION ===")
    print(f"Message: {args.message}")
    print(f"Private key: {args.private_key}")
    if args.nonce is not None:
        print(f"Nonce: {args.nonce}")
    print("Signature:")
    print(f"  r = {signature[0]}")
    print(f"  s = {signature[1]}")


def handle_verify(args):
    public_key = (args.public_x, args.public_y)
    signature = (args.r, args.s)

    if args.r <= 0 or args.s <= 0:
        print("Error: signature values r and s must be positive integers.")
        return

    is_valid = verify_signature(
        message=args.message,
        public_key=public_key,
        signature=signature
    )

    print("=== SIGNATURE VERIFICATION ===")
    print(f"Message: {args.message}")
    print("Public key:")
    print(f"  x = {public_key[0]}")
    print(f"  y = {public_key[1]}")
    print("Signature:")
    print(f"  r = {signature[0]}")
    print(f"  s = {signature[1]}")
    print(f"Result: {'VALID' if is_valid else 'INVALID'}")


def handle_test(args):
    print("=== TEST EXECUTION ===")
    run_all_tests()


def build_parser():
    parser = argparse.ArgumentParser(
        description="ECDSA application implemented without cryptographic libraries."
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        help="Available commands"
    )

    genkey_parser = subparsers.add_parser(
        "genkey",
        help="Generate an ECDSA key pair"
    )
    genkey_parser.add_argument(
        "--private-key",
        type=int,
        help="Optional fixed private key for deterministic testing"
    )
    genkey_parser.set_defaults(func=handle_genkey)

    sign_parser = subparsers.add_parser(
        "sign",
        help="Sign a message using ECDSA"
    )
    sign_parser.add_argument(
        "--message",
        type=str,
        required=True,
        help="Message to sign"
    )
    sign_parser.add_argument(
        "--private-key",
        type=int,
        required=True,
        help="Private key used for signing"
    )
    sign_parser.add_argument(
        "--nonce",
        type=int,
        help="Optional fixed nonce value for deterministic testing"
    )
    sign_parser.set_defaults(func=handle_sign)

    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify an ECDSA signature"
    )
    verify_parser.add_argument(
        "--message",
        type=str,
        required=True,
        help="Original message"
    )
    verify_parser.add_argument(
        "--public-x",
        type=int,
        required=True,
        help="X coordinate of the public key"
    )
    verify_parser.add_argument(
        "--public-y",
        type=int,
        required=True,
        help="Y coordinate of the public key"
    )
    verify_parser.add_argument(
        "--r",
        type=int,
        required=True,
        help="First signature component"
    )
    verify_parser.add_argument(
        "--s",
        type=int,
        required=True,
        help="Second signature component"
    )
    verify_parser.set_defaults(func=handle_verify)

    test_parser = subparsers.add_parser(
        "test",
        help="Run project tests"
    )
    test_parser.set_defaults(func=handle_test)

    return parser


def run_cli():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)
