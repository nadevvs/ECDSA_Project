from dataclasses import dataclass
from core.field import mod_inv


@dataclass(frozen=True)
class Point:
    x: int | None
    y: int | None
    infinity: bool = False


@dataclass(frozen=True)
class Curve:
    name: str
    p: int
    a: int
    b: int
    g: Point
    n: int
    h: int


def get_infinity() -> Point:
    # point at infinity helper
    return Point(None, None, True)


def get_p256_curve() -> Curve:
    # nist p-256 curve params
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

    gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    h = 1

    g = Point(gx, gy)

    return Curve(
        name="P-256",
        p=p,
        a=a,
        b=b,
        g=g,
        n=n,
        h=h
    )


def is_on_curve(
    point: Point,
    curve: Curve,
    math_trace: list[str] | None = None,
    point_name: str = "point"
) -> bool:
    # check curve eq: y^2 = x^3 + ax + b
    if point.infinity:
        if math_trace is not None:
            math_trace.append(f"is_on_curve: {point_name} is infinity, result = true")
        return True

    left = (point.y * point.y) % curve.p
    right = (point.x * point.x * point.x + curve.a * point.x + curve.b) % curve.p

    result = left == right

    if math_trace is not None:
        math_trace.append(
            f"is_on_curve: {point_name}, left = y^2 mod p = {left}, "
            f"right = x^3 + ax + b mod p = {right}, result = {str(result).lower()}"
        )

    return result


def point_neg(point: Point, curve: Curve) -> Point:
    # inverse point over finite field
    if point.infinity:
        return point

    return Point(point.x, (-point.y) % curve.p)


def point_add(
    p1: Point,
    p2: Point,
    curve: Curve,
    math_trace: list[str] | None = None,
    left_name: str = "point_1",
    right_name: str = "point_2"
) -> Point:
    # handle infinity as neutral elem
    if p1.infinity:
        if math_trace is not None:
            math_trace.append(
                f"point_add: adding {left_name} + {right_name}, "
                f"case = left infinity, result = {p2}"
            )
        return p2

    if p2.infinity:
        if math_trace is not None:
            math_trace.append(
                f"point_add: adding {left_name} + {right_name}, "
                f"case = right infinity, result = {p1}"
            )
        return p1

    # vertical line gives infinity
    if p1.x == p2.x and (p1.y != p2.y or p1.y == 0):
        result = get_infinity()
        if math_trace is not None:
            math_trace.append(
                f"point_add: adding {left_name} + {right_name}, "
                f"case = vertical line, result = infinity"
            )
        return result

    # same point means tangent slope
    if p1.x == p2.x and p1.y == p2.y:
        operation_case = "same point doubling"
        slope = (
            (3 * p1.x * p1.x + curve.a) *
            mod_inv(2 * p1.y, curve.p)
        ) % curve.p

    else:
        # diff points use secant slope
        operation_case = "different points"
        slope = (
            (p2.y - p1.y) *
            mod_inv(p2.x - p1.x, curve.p)
        ) % curve.p

    # calc result point coords
    x3 = (slope * slope - p1.x - p2.x) % curve.p
    y3 = (slope * (p1.x - x3) - p1.y) % curve.p

    result = Point(x3, y3)

    if math_trace is not None:
        math_trace.append(
            f"point_add: adding {left_name} + {right_name}, "
            f"case = {operation_case}, slope = {slope}, "
            f"result = ({result.x}, {result.y})"
        )

    return result


def scalar_mult(
    k: int,
    point: Point,
    curve: Curve,
    math_trace: list[str] | None = None,
    scalar_name: str = "k",
    point_name: str = "point",
    result_name: str = "result"
) -> Point:
    # scalar mult by double-and-add
    original_k = k

    if k == 0 or point.infinity:
        result = get_infinity()
        if math_trace is not None:
            math_trace.append(
                f"scalar_mult: computing {scalar_name} * {point_name}, "
                f"case = zero scalar or infinity point, result = infinity"
            )
        return result

    if k < 0:
        return scalar_mult(
            -k,
            point_neg(point, curve),
            curve,
            math_trace,
            f"-{scalar_name}",
            f"-{point_name}",
            result_name
        )

    result = get_infinity()

    addend = point
    additions = 0
    doublings = 0
    scalar_bits = k.bit_length()

    # scan scalar bits from lsb to msb
    while k > 0:
        if k & 1:
            result = point_add(result, addend, curve)
            additions += 1

        addend = point_add(addend, addend, curve)
        doublings += 1
        k >>= 1

    if math_trace is not None:
        math_trace.append(
            f"scalar_mult: computing {scalar_name} = {original_k} times {point_name} "
            f"using double-and-add, scalar bits = {scalar_bits}, "
            f"additions = {additions}, doublings = {doublings}, "
            f"{result_name} = ({result.x}, {result.y})"
        )

    return result
