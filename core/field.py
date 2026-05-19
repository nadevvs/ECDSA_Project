def mod_inv(a: int, m: int) -> int:
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

    return old_s % m

