# Testing Description

## 1. Purpose of testing

The tests check whether the manual ECDSA implementation works correctly. They cover both the mathematical blocks and the final signing and verification workflow.

The test suite checks:

- elliptic curve point operations,
- deterministic key generation,
- deterministic signature generation,
- signature verification,
- rejection of modified messages,
- comparison with the external `cryptography` reference implementation.

**Important:** before running the tests, install the dependencies:

```bash
python3 -m pip install -r requirements.txt
```

This is needed because tests 16-18 use `cryptography` as an external reference implementation.


Then, to run all tests simultaneously:

```bash
python3 main.py test
```

---

## 2. Testing approach

The tests are grouped by purpose.

### 2.1. Internal correctness tests

Tests 1-5 check the low-level elliptic curve operations:

- base point on curve,
- negated base point on curve,
- addition with point at infinity,
- addition of a point and its inverse,
- scalar multiplication for 2G.

These tests confirm that the curve arithmetic used later by ECDSA works correctly.

### 2.2. Deterministic ECDSA tests

Tests 6-7 use fixed values for private key, message, and nonce.

Checked values:

- expected public key coordinates,
- expected signature pair `(r, s)`.

These tests confirm that key generation and signing produce repeatable expected values.

### 2.3. Functional verification tests

Tests 8-15 check full signing and verification behavior:

- valid signature accepted,
- modified message rejected,
- short messages verified,
- long messages verified.

These tests confirm that valid signatures are accepted and changed messages are rejected.

### 2.4. Reference implementation tests

Tests 16-18 compare selected results with the Python `cryptography` package. This package is required for the tests, but it is not used in the project implementation.

The reference tests check:

- project public key against `cryptography` public key,
- `cryptography` verification of a project signature,
- project verification of a `cryptography` signature.

These tests confirm compatibility with an external P-256 ECDSA implementation.

---

## 3. Source of reference values

The deterministic test vectors were created with fixed private key, message, and nonce values. Because these inputs do not change, the generated public key and signature can be stored and compared in later runs.

Additional reference checks use the `cryptography` Python package as an independent P-256 ECDSA implementation. 

---

## 4. Console test output

The automated test run produced the following output:

```text
Test 1 - Base point on curve: PASS
Test 2 - Negated base point on curve: PASS
Test 3 - G + O = G: PASS
Test 4 - G + (-G) = O: PASS
Test 5 - 2G on curve: PASS
Test 6 - Deterministic public key: PASS
Test 7 - Deterministic signature: PASS
Test 8 - Verify valid and reject modified message: PASS
Test 9 - Random short message signing and verification 1: PASS
Test 10 - Random short message signing and verification 2: PASS
Test 11 - Random short message signing and verification 3: PASS
Test 12 - Long message signing and verification 1: PASS
Test 13 - Long message signing and verification 2: PASS
Test 14 - Reject modified short message: PASS
Test 15 - Reject modified long message: PASS
Test 16 - Reference public key with cryptography: PASS
Test 17 - Reference verifies project signature: PASS
Test 18 - Project verifies reference signature: PASS

Summary: 18/18 tests passed.
```

