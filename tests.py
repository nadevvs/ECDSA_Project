from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from core.curve import (
    get_p256_curve,
    get_infinity,
    is_on_curve,
    point_add,
    point_neg,
    scalar_mult,
)
from core.keygen import generate_keypair
from core.ecdsa_alg import sign_message, verify_signature

TEST_PRIVATE_KEY = 12345
TEST_NONCE = 99999
TEST_MESSAGE = "hello ecdsa"

EXPECTED_PUBLIC_KEY_X = 17611591551394103526348166819472991346437344487394483771310531299395461896210
EXPECTED_PUBLIC_KEY_Y = 65195855187618849542991473502236155813942564250927181129449382163772576288998

EXPECTED_SIGNATURE_R = 31345868973708049920562301891544602536333865749401247712769522608617826980609
EXPECTED_SIGNATURE_S = 14317488386718389188682834004522823711485621232172113778465057221785732148899


def print_result(name: str, passed: bool):
    status = "PASS" if passed else "FAIL"
    print(f"{name}: {status}")


def test_base_point_on_curve() -> bool:
    curve = get_p256_curve()
    return is_on_curve(curve.g, curve)


def test_negated_base_point_on_curve() -> bool:
    curve = get_p256_curve()
    neg_g = point_neg(curve.g, curve)
    return is_on_curve(neg_g, curve)


def test_g_plus_infinity() -> bool:
    curve = get_p256_curve()
    inf = get_infinity()
    result = point_add(curve.g, inf, curve)
    return result == curve.g


def test_g_plus_neg_g() -> bool:
    curve = get_p256_curve()
    neg_g = point_neg(curve.g, curve)
    result = point_add(curve.g, neg_g, curve)
    return result.infinity


def test_double_g_on_curve() -> bool:
    curve = get_p256_curve()
    point_2g = scalar_mult(2, curve.g, curve)
    return is_on_curve(point_2g, curve)


def test_deterministic_public_key() -> bool:
    if EXPECTED_PUBLIC_KEY_X is None or EXPECTED_PUBLIC_KEY_Y is None:
        return False

    _, public_key = generate_keypair(TEST_PRIVATE_KEY)
    return public_key.x == EXPECTED_PUBLIC_KEY_X and public_key.y == EXPECTED_PUBLIC_KEY_Y


def test_deterministic_signature() -> bool:
    if EXPECTED_SIGNATURE_R is None or EXPECTED_SIGNATURE_S is None:
        return False

    r, s = sign_message(TEST_MESSAGE, TEST_PRIVATE_KEY, TEST_NONCE)
    return r == EXPECTED_SIGNATURE_R and s == EXPECTED_SIGNATURE_S


def test_signature_verification_and_message_change() -> bool:
    _, public_key = generate_keypair(TEST_PRIVATE_KEY)
    signature = sign_message(TEST_MESSAGE, TEST_PRIVATE_KEY, TEST_NONCE)

    valid_result = verify_signature(TEST_MESSAGE, public_key, signature)
    invalid_result = verify_signature(TEST_MESSAGE + "!", public_key, signature)

    return valid_result is True and invalid_result is False


def test_random_message_1() -> bool:
    message = "qwertqwertqwert"
    private_key = 11111
    nonce = 22222

    _, public_key = generate_keypair(private_key)
    signature = sign_message(message, private_key, nonce)

    return verify_signature(message, public_key, signature)


def test_random_message_2() -> bool:
    message = "asdzxcasdzxc123"
    private_key = 33333
    nonce = 44444

    _, public_key = generate_keypair(private_key)
    signature = sign_message(message, private_key, nonce)

    return verify_signature(message, public_key, signature)


def test_random_message_3() -> bool:
    message = "mnbvmnbvqwepoi"
    private_key = 55555
    nonce = 66666

    _, public_key = generate_keypair(private_key)
    signature = sign_message(message, private_key, nonce)

    return verify_signature(message, public_key, signature)


def test_long_message_1() -> bool:
    message = (
        "This is a very long message used for testing the ECDSA implementation. "
        "It contains many characters and is intended to verify whether hashing, "
        "signing, and verification work correctly for inputs much longer than a "
        "single short word or phrase."
    )
    private_key = 77777
    nonce = 88888

    _, public_key = generate_keypair(private_key)
    signature = sign_message(message, private_key, nonce)

    return verify_signature(message, public_key, signature)


def test_long_message_2() -> bool:
    message = (
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod "
        "tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, "
        "quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat."
    )
    private_key = 99999
    nonce = 111111

    _, public_key = generate_keypair(private_key)
    signature = sign_message(message, private_key, nonce)

    return verify_signature(message, public_key, signature)


def test_reject_modified_short_message() -> bool:
    original_message = "qwertqwertqwert"
    modified_message = "qwertqwertqwert!"
    private_key = 13579
    nonce = 24680

    _, public_key = generate_keypair(private_key)
    signature = sign_message(original_message, private_key, nonce)

    valid_original = verify_signature(original_message, public_key, signature)
    invalid_modified = verify_signature(modified_message, public_key, signature)

    return valid_original is True and invalid_modified is False


def test_reject_modified_long_message() -> bool:
    original_message = (
        "This is another long message prepared for checking whether the verification "
        "algorithm properly rejects modified input after the signature was generated."
    )
    modified_message = (
        "This is another long message prepared for checking whether the verification "
        "algorithm properly rejects modified input after the signature was generated?"
    )
    private_key = 31415
    nonce = 27182

    _, public_key = generate_keypair(private_key)
    signature = sign_message(original_message, private_key, nonce)

    valid_original = verify_signature(original_message, public_key, signature)
    invalid_modified = verify_signature(modified_message, public_key, signature)

    return valid_original is True and invalid_modified is False


def test_reference_public_key_with_cryptography() -> bool:
    _, public_key = generate_keypair(TEST_PRIVATE_KEY)

    reference_private_key = ec.derive_private_key(
        TEST_PRIVATE_KEY,
        ec.SECP256R1()
    )
    reference_public_numbers = reference_private_key.public_key().public_numbers()

    return (
        public_key.x == reference_public_numbers.x and
        public_key.y == reference_public_numbers.y
    )


def test_reference_verify_our_signature() -> bool:
    r, s = sign_message(TEST_MESSAGE, TEST_PRIVATE_KEY, TEST_NONCE)
    signature = utils.encode_dss_signature(r, s)

    reference_private_key = ec.derive_private_key(
        TEST_PRIVATE_KEY,
        ec.SECP256R1()
    )
    reference_public_key = reference_private_key.public_key()

    try:
        reference_public_key.verify(
            signature,
            TEST_MESSAGE.encode("utf-8"),
            ec.ECDSA(hashes.SHA256())
        )
    except InvalidSignature:
        return False

    return True


def test_verify_reference_signature() -> bool:
    reference_private_key = ec.derive_private_key(
        TEST_PRIVATE_KEY,
        ec.SECP256R1()
    )
    reference_signature = reference_private_key.sign(
        TEST_MESSAGE.encode("utf-8"),
        ec.ECDSA(hashes.SHA256())
    )
    r, s = utils.decode_dss_signature(reference_signature)

    _, public_key = generate_keypair(TEST_PRIVATE_KEY)

    return verify_signature(TEST_MESSAGE, public_key, (r, s))


def run_all_tests():
    tests = [
        ("Test 1 - Base point on curve", test_base_point_on_curve),
        ("Test 2 - Negated base point on curve", test_negated_base_point_on_curve),
        ("Test 3 - G + O = G", test_g_plus_infinity),
        ("Test 4 - G + (-G) = O", test_g_plus_neg_g),
        ("Test 5 - 2G on curve", test_double_g_on_curve),
        ("Test 6 - Deterministic public key", test_deterministic_public_key),
        ("Test 7 - Deterministic signature", test_deterministic_signature),
        ("Test 8 - Verify valid and reject modified message", test_signature_verification_and_message_change),
        ("Test 9 - Random short message signing and verification 1", test_random_message_1),
        ("Test 10 - Random short message signing and verification 2", test_random_message_2),
        ("Test 11 - Random short message signing and verification 3", test_random_message_3),
        ("Test 12 - Long message signing and verification 1", test_long_message_1),
        ("Test 13 - Long message signing and verification 2", test_long_message_2),
        ("Test 14 - Reject modified short message", test_reject_modified_short_message),
        ("Test 15 - Reject modified long message", test_reject_modified_long_message),
        ("Test 16 - Reference public key with cryptography", test_reference_public_key_with_cryptography),
        ("Test 17 - Reference verifies project signature", test_reference_verify_our_signature),
        ("Test 18 - Project verifies reference signature", test_verify_reference_signature),
    ]

    passed_count = 0

    print("=== RUNNING TESTS ===")
    for name, test_func in tests:
        try:
            passed = test_func()
        except Exception:
            passed = False

        print_result(name, passed)
        if passed:
            passed_count += 1

    print(f"\nSummary: {passed_count}/{len(tests)} tests passed.")
