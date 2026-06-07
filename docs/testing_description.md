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

---

## 5. Debug output

Key values and intermediate calculations printed by `--debug` flag.

### 5.1. Key generation

```bash
python3 main.py genkey --private-key 12345 --debug
```

```text
debug:
loaded curve p-256
using private key d = 12345
scalar_mult: computing d = 12345 times g using double-and-add, scalar bits = 14, additions = 6, doublings = 14, q = (17611591551394103526348166819472991346437344487394483771310531299395461896210, 65195855187618849542991473502236155813942564250927181129449382163772576288998)
is_on_curve: q, left = y^2 mod p = 38442251892502350094272226924834206007254010274827057081880990302214457539449, right = x^3 + ax + b mod p = 38442251892502350094272226924834206007254010274827057081880990302214457539449, result = true
```

### 5.2. Signature generation

```bash
python3 main.py sign --message "hello ecdsa" --private-key 12345 --nonce 99999 --debug
```

```text
debug:
loaded curve p-256, n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
hash_message: input = hello ecdsa, sha256 integer = 93539847192247872696734389604601626176534887467972909253879269004239417835878
using nonce k = 99999
scalar_mult: computing k = 99999 times g using double-and-add, scalar bits = 17, additions = 10, doublings = 17, r_point = (31345868973708049920562301891544602536333865749401247712769522608617826980609, 51918322062141401992654725850158801069621268882996997091686602298206106335672)
computed r = r_point.x mod n = 31345868973708049920562301891544602536333865749401247712769522608617826980609
mod_inv: computing inverse of k = 99999 mod n, result = 59188876209527795395494381926478440069993943571804953306165623597891759534195
signature formula: s = k_inv * (e + private_key * r) mod n, result = 14317488386718389188682834004522823711485621232172113778465057221785732148899
```

### 5.3. Signature verification

```bash
python3 main.py verify --message "hello ecdsa" --public-x 17611591551394103526348166819472991346437344487394483771310531299395461896210 --public-y 65195855187618849542991473502236155813942564250927181129449382163772576288998 --r 31345868973708049920562301891544602536333865749401247712769522608617826980609 --s 14317488386718389188682834004522823711485621232172113778465057221785732148899 --debug
```

```text
debug:
loaded curve p-256, n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
checked signature range: r ok, s ok
is_on_curve: q, left = y^2 mod p = 38442251892502350094272226924834206007254010274827057081880990302214457539449, right = x^3 + ax + b mod p = 38442251892502350094272226924834206007254010274827057081880990302214457539449, result = true
checked public key on curve: true
hash_message: input = hello ecdsa, sha256 integer = 93539847192247872696734389604601626176534887467972909253879269004239417835878
mod_inv: computing inverse of s = 14317488386718389188682834004522823711485621232172113778465057221785732148899 mod n, result = 70046364514645532295469269007921434094481243313247121862666145671924402904674
computed u1 = e * w mod n = 51266530898713924088547275019381083297113898009699584616939366850071589867714
computed u2 = r * w mod n = 78925813217841159936331346197184718523420596542170329987595493773352892447436
scalar_mult: computing u1 = 51266530898713924088547275019381083297113898009699584616939366850071589867714 times g using double-and-add, scalar bits = 255, additions = 122, doublings = 255, point_1 = (77055819106934312310104207092327028461420372437121967456930324677803389641761, 44124474160768680838956817202776311914033448395002229853351618149376472345471)
scalar_mult: computing u2 = 78925813217841159936331346197184718523420596542170329987595493773352892447436 times q using double-and-add, scalar bits = 256, additions = 126, doublings = 256, point_2 = (45586371810372147768017733654063211823261972220095832503634892725201395944595, 79542972074642849334389978407812256291537125405342522268010625953589609010207)
point_add: adding point_1 + point_2, case = different points, slope = 90887170952316886175242681751657946894343128959565251792781035981574440204663, result = (31345868973708049920562301891544602536333865749401247712769522608617826980609, 51918322062141401992654725850158801069621268882996997091686602298206106335672)
compared point_x.x mod n = 31345868973708049920562301891544602536333865749401247712769522608617826980609 with r = 31345868973708049920562301891544602536333865749401247712769522608617826980609, result = valid
```
