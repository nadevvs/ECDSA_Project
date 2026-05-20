# ECDSA Algorithm Description

## 1. Purpose of the algorithm

This project implements ECDSA (Elliptic Curve Digital Signature Algorithm) in Python, without using standard cryptographic libraries for the core signature algorithm. ECDSA is used to prove message authenticity and integrity: one party signs a message with a private key, and another verifies it with the corresponding public key.

The application covers three main cryptographic operations:

- generation of an elliptic-curve key pair,
- creation of a digital signature for a text message,
- verification of the digital signature.

The implementation uses the NIST P-256 elliptic curve, also known as secp256r1. This curve is standardized and commonly used in real cryptographic systems.

---

## 2. Elliptic curves over finite fields

ECDSA is based on arithmetic performed on points lying on an elliptic curve over a finite field. In this project, the curve is defined over a prime field, so all operations are performed modulo a large prime number p.

The general form of the curve equation is:

```text
y^2 ≡ x^3 + ax + b (mod p)
```

where:

- p is the prime that defines the field,
- a and b are constants that define the curve,
- (x, y) is a point on the curve.

Unlike ordinary arithmetic on integers, elliptic curve arithmetic is performed on curve points. The main operations are:

- point addition,
- point doubling,
- scalar multiplication.

### 2.1. Point addition

If two different points P and Q lie on the curve, they can be added to obtain another point R:

```text
R = P + Q
```

The result is computed with elliptic curve formulas, with all calculations performed modulo p.

### 2.2. Point doubling

If the same point is added to itself, the operation is called point doubling:

```text
R = 2P
```

This operation has a separate formula because the slope is calculated differently than for two distinct points.

### 2.3. Scalar multiplication

Scalar multiplication is the repeated addition of a point:

```text
kP = P + P + ... + P
```

where P is added k times. In this project, scalar multiplication is implemented with the double-and-add method.

---

## 3. ECDSA key pair

ECDSA uses two keys:

- private key d — a secret integer,
- public key Q — a point on the elliptic curve.

The public key is computed from the private key by scalar multiplication of the base point G:

```text
Q = dG
```

where:

- d is the private key,
- G is the standard base point of the selected curve,
- Q is the public key.

The security of the scheme depends on the elliptic curve discrete logarithm problem. It is easy to compute Q = dG when d is known, but infeasible in practice to recover d from Q.

---

## 4. Role of hashing in ECDSA

Before a message is signed, it is hashed into a fixed-length digest. The signature is created from this hash value, not directly from the full message.

In this project, SHA-256 is used. The message is encoded in UTF-8, hashed, and converted to an integer used during signing and verification.

Hashing is necessary because:

- the message may be of arbitrary length,
- the signing algorithm works on fixed-size numerical values,
- even a small change in the message causes a different digest.

---

## 5. Signature generation in ECDSA

To sign a message, the following values are used:

- the private key d,
- the message hash e,
- a fresh one-time secret nonce k.

The signature generation procedure is:

1. Compute the message hash e.
2. Choose a nonce k such that 1 <= k <= n - 1.
3. Compute the point:

```text
R = kG
```

4. Take the first signature component:

```text
r = x_R mod n
```

where x_R is the x-coordinate of point R.
5. Compute the second signature component:

```text
s = k^(-1)(e + dr) mod n
```

6. The final signature is the pair:

```text
(r, s)
```

If either r = 0 or s = 0, a new nonce must be chosen and the process repeated.

The nonce k is very important. Reusing the same nonce for different messages can reveal the private key.

---

## 6. Signature verification in ECDSA

To verify a signature, the verifier uses:

- the original message,
- the signature (r, s),
- the public key Q.

The verification procedure is:

1. Check whether r and s are in the valid range.
2. Compute the message hash e.
3. Compute the modular inverse:

```text
w = s^(-1) mod n
```

4. Compute:

```text
u1 = ew mod n
u2 = rw mod n
```

5. Compute the point:

```text
X = u1G + u2Q
```

6. The signature is valid if:

```text
x_X mod n = r
```

where x_X is the x-coordinate of point X.

If the relation holds, it means the message was signed with the matching private key and was not changed afterward.

---

## 7. Chosen curve: NIST P-256

The implementation uses the standard curve **NIST P-256 (secp256r1)**. This curve is defined by a set of public domain parameters:

- field prime p,
- coefficients a and b,
- base point G,
- order n,
- cofactor h.

This curve was selected because:

- it is standardized,
- it is widely used,
- it is suitable for a manual implementation project,
- it fits the standard ECDSA scheme directly.

---

## 8. Mathematical blocks implemented in the project

The implementation is divided into several mathematical blocks:

1. Finite field arithmetic
   - modular inverse.

2. Elliptic curve point operations
   - point negation,
   - point addition,
   - point doubling,
   - scalar multiplication.

3. Key generation
   - generation of private key,
   - computation of public key.

4. Hashing
   - SHA-256 digest computation,
   - conversion of digest to integer.

5. ECDSA logic
   - signature generation,
   - signature verification.

This decomposition follows the natural structure of ECDSA and makes each part easier to test separately.

