# Functional Description of the Application

## 1. General purpose of the application

The application is a console-based Python program that implements the Elliptic Curve Digital Signature Algorithm (ECDSA). It provides the main operations needed to work with digital signatures on elliptic curves.

The application supports the following functions:

- generating an elliptic-curve key pair,
- signing a text message,
- verifying a digital signature,
- running automated correctness tests.

The implementation uses the NIST P-256 elliptic curve and works entirely in console mode. This keeps the interaction direct and makes testing from the terminal straightforward.

---

## 2. Application operating mode

The program is started from the command line. Commands and arguments are passed to `main.py`.

The general execution format is:

```bash
python3 main.py <command> [arguments]
```

---

## 3. Supported commands

### 3.1. Key generation command

The `genkey` command is used to generate an ECDSA key pair.

Example:

```bash
python3 main.py genkey
```

The command:

1. loads the P-256 curve parameters,
2. generates a private key in the valid range,
3. computes the public key,
4. prints the key values.

The command also supports deterministic generation with a fixed private key:

```bash
python3 main.py genkey --private-key 12345
```

This option is useful when the same key pair must be reproduced during testing or comparison.

#### Input

- `--private-key` — optional integer value.

#### Output

The command prints:

- the curve name,
- the private key as an integer,
- the public key coordinates `x` and `y` as integers.

---

### 3.2. Signature generation command

The `sign` command is used to generate a digital signature for a text message.

Example:

```bash
python3 main.py sign --message "hello ecdsa" --private-key 12345
```

The command:

1. hashes the provided message,
2. selects a nonce,
3. computes the ECDSA signature,
4. prints the signature components.

For deterministic tests, a fixed nonce can be provided:

```bash
python3 main.py sign --message "hello ecdsa" --private-key 12345 --nonce 99999
```

This is useful in tests because the same message, private key, and nonce always produce the same signature.

---

### 3.3. Signature verification command

The `verify` command is used to verify whether a signature is valid for a given message and public key.

Example:

```bash
python3 main.py verify --message "hello ecdsa" --public-x <value> --public-y <value> --r <value> --s <value>
```

The command:

1. hashes the given message,
2. validates the provided public key and signature values,
3. performs ECDSA verification,
4. prints the verification result.

#### Input

- `--message` — required text string,
- `--public-x` — required integer, x-coordinate of the public key,
- `--public-y` — required integer, y-coordinate of the public key,
- `--r` — required integer, first signature component,
- `--s` — required integer, second signature component.

#### Output

The command prints:

- the input message,
- the public key coordinates,
- the signature values,
- final result: `VALID` or `INVALID`.

This command can be used for both positive and negative tests, for example when the message was changed after signing.

---

### 3.4. Debug flag

The `genkey`, `sign`, and `verify` commands support an optional `--debug` flag. This flag does not change the result of the operation. It only adds a compact trace after the normal output.

Examples:

```bash
python3 main.py genkey --private-key 12345 --debug
python3 main.py sign --message "hello ecdsa" --private-key 12345 --nonce 99999 --debug
python3 main.py verify --message "hello ecdsa" --public-x <value> --public-y <value> --r <value> --s <value> --debug
```

The debug trace can include algorithm steps and mathematical operations such as message hashing, scalar multiplication, modular inverse calculation, curve validation, point addition, and final formula values.

---

### 3.5. Test execution command

The `test` command runs a series of implemented correctness tests. The full test suite uses the dependency listed in `requirements.txt` for comparison with the external `cryptography` reference implementation.

Example:

```bash
python3 main.py test
```

It prints the result of each test and a final summary.

This command validates both the point arithmetic and the higher-level ECDSA functions.

---

## 4. Input data format

The application uses command-line arguments. Numerical parameters are provided as integers, and text data is passed through the `--message` argument.

### 4.1. Message format

The message is provided as a text string:

```bash
--message "hello ecdsa"
```

Inside the program, the message is encoded as UTF-8 bytes before hashing.

### 4.2. Key format

- Private key: integer,
- Public key: pair of integer coordinates `(x, y)`.

### 4.3. Signature format

The ECDSA signature is a pair of integers:

- `r`,
- `s`.

### 4.4. Tests format

Deterministic tests use fixed values of:

- message,
- private key,
- nonce,
- expected public key,
- expected signature.

This allows the output to be compared with stored reference values.

---

## 5. Output data format

The program prints readable console output. Depending on the command, it includes:

### 5.1. Key generation output

- curve name,
- private key,
- public key coordinates.

### 5.2. Signature output

- message,
- private key,
- optional nonce,
- values `r` and `s`.

### 5.3. Verification output

- message,
- public key,
- signature,
- result `VALID` or `INVALID`.

### 5.4. Test output

- test names,
- pass/fail status,
- final summary.

---

## 6. Error handling and validation

The application performs basic input validation, including:

- checking whether private key and nonce are positive,
- checking whether signature values are in a valid range,
- checking whether the public key lies on the selected curve,
- handling invalid deterministic values.

If an invalid value is provided, the program reports an error instead of continuing with incorrect data.

---

## 7. User interface characteristics

The application uses a command-line interface. Each operation is selected by a command such as `genkey`, `sign`, `verify`, or `test`, and the needed values are passed as arguments.
