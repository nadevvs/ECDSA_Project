# Code Structure and Design Approach

## 1. General design approach

The project is organized into separate files, where each file is responsible for one part of the ECDSA. 

The structure can be divided into three main levels:

1. entry point and command-line interface,
2. ECDSA operations,
3. low-level mathematical operations.

This separation also makes testing easier, because individual blocks can be checked separately.

---

## 2. Project file structure

The project is organized as follows:

```text
main.py
cli.py
tests.py
requirements.txt
core/
    __init__.py
    curve.py
    field.py
    hashing.py
    keygen.py
    ecdsa_alg.py
```

The root files start the program, handle user commands, and run tests. The `core` directory contains the implementation of the cryptographic and mathematical operations.

---

## 3. Description of each file

### 3.1. `main.py`

This is the entry point of the application. It calls the CLI runner and keeps program startup separated from the rest of the logic.

Main element:

- `main()` — starts the command-line interface.

---

### 3.2. `cli.py`

This file handles the command-line interface. It parses user arguments, defines commands such as `genkey`, `sign`, `verify`, and `test`, and prints the output. It also handles the optional `--debug` flag for commands that can show intermediate calculations.

Main elements:

- command parser,
- handlers for key generation, signing, verification, and tests,
- formatting of compact debug output.

Input: command-line arguments.

Output: readable console text.

---

### 3.3. `core/field.py`

This file contains finite field arithmetic needed by elliptic curve operations.

Main function:

- `mod_inv(a, m)` — computes the modular inverse of `a` modulo `m`.

This function uses the extended Euclidean algorithm. It is needed because division in modular arithmetic is done by multiplying by an inverse. The function can also optionally record debug information.

---

### 3.4. `core/curve.py`

This file contains the elliptic curve structures and point operations.

Main structures:

- `Point` — stores point coordinates and the infinity flag,
- `Curve` — stores curve parameters.

Main functions:

- `get_infinity()` — returns the point at infinity,
- `get_p256_curve()` — returns P-256 parameters,
- `is_on_curve(point, curve)` — checks the curve equation,
- `point_neg(point, curve)` — computes the inverse point,
- `point_add(p1, p2, curve)` — adds two points,
- `scalar_mult(k, point, curve)` — computes scalar multiplication.

This file is the main mathematical part of the project, because ECDSA depends on point addition and scalar multiplication.
Some functions in this file can optionally record debug information.

---

### 3.5. `core/hashing.py`

This file implements SHA-256 hashing and conversion of a message digest into an integer.

Main functions:

- `sha256(data)` — computes the SHA-256 digest,
- `hash_message(message)` — hashes a text message and returns an integer.

Keeping hashing separate makes the signing and verification functions shorter and easier to follow and preserves modular structure.

---

### 3.6. `core/keygen.py`

This file contains key generation logic.

Main functions:

- `generate_private_key(n)` — generates a private key in the valid range,
- `generate_keypair(private_key=None)` — returns a private key and public key.

The public key is computed as scalar multiplication of the private key and base point. The key generation function can optionally record debug information.

---

### 3.7. `core/ecdsa_alg.py`

This file contains the main ECDSA signing and verification logic.

Main functions:

- `sign_message(message, private_key, nonce=None)` — returns signature `(r, s)`,
- `verify_signature(message, public_key, signature)` — returns `True` or `False`.

This module combines hashing, curve arithmetic, modular inverse, and key values into the final ECDSA formulas. Signing and verification can optionally record debug information.

---

### 3.8. `tests.py`

This file runs tests.

Main elements:

- individual test functions,
- comparison with the `cryptography` reference implementation,
- `run_all_tests()` for executing the full test set.

---

## 4. Example data flow

A signing operation follows this path:

1. `main.py` starts the program,
2. `cli.py` parses the `sign` command,
3. `core/ecdsa_alg.py` receives the message and private key,
4. `core/hashing.py` hashes the message,
5. `core/curve.py` and `core/field.py` perform mathematical operations,
6. `core/ecdsa_alg.py` returns the signature,
7. `cli.py` prints the result.

Verification follows a similar path, but returns a boolean result instead of a signature.

---

## 5. Summary

The code structure follows the main parts of the ECDSA algorithm: input handling, hashing, finite field arithmetic, elliptic curve operations, key generation, signature logic, and testing. This division keeps the project easier to review and modify.
