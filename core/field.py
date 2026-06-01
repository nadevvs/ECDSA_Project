def mod_inv(
    a: int,
    m: int,
    math_trace: list[str] | None = None,
    value_name: str = "a",
    modulus_name: str = "m"
) -> int:
    # modular inverse with extended euclid alg
    if a == 0:
        raise ValueError("Inverse does not exist for zero.")

    # init remainder and coef vals
    old_r, r = a % m, m
    old_s, s = 1, 0

    # reduce gcd and track inverse coef
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s

    # inverse exist only if nums are coprime
    if old_r != 1:
        raise ValueError("Inverse does not exist.")

    result = old_s % m

    if math_trace is not None:
        math_trace.append(
            f"mod_inv: computing inverse of {value_name} = {a} "
            f"mod {modulus_name}, result = {result}"
        )

    return result
