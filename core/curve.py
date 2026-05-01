from dataclasses import dataclass


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
    return Point(None, None, True)


def get_p256_curve() -> Curve:
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

def is_on_curve(point: Point, curve: Curve) -> bool:
    if point.infinity:
        return True

    left = (point.y * point.y) % curve.p
    right = (point.x * point.x * point.x + curve.a * point.x + curve.b) % curve.p

    return left == right
