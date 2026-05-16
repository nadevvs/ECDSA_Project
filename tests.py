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
from test_vectors import (
    TEST_PRIVATE_KEY,
    TEST_NONCE,
    TEST_MESSAGE,
    EXPECTED_PUBLIC_KEY_X,
    EXPECTED_PUBLIC_KEY_Y,
    EXPECTED_SIGNATURE_R,
    EXPECTED_SIGNATURE_S,
)


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
