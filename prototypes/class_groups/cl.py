from abc import ABC, abstractmethod
from random import randint
from typing import Self, override
from prototypes.class_groups.group import AbelianGroup


class Cl(AbelianGroup, ABC):
    def __init__(self, a: int, b: int, c: int) -> None:
        assert b * b - 4 * a * c == self.discriminant()
        self.a, self.b, self.c = _reduce(a, b, c)

    @classmethod
    @abstractmethod
    def discriminant(cls) -> int: ...

    @classmethod
    @override
    def random(cls) -> Self:
        raise NotImplementedError

    @classmethod
    @override
    def zero(cls) -> Self:
        d = cls.discriminant()
        if d % 2 == 1:
            return cls(1, 1, -(d - 1) // 4)
        else:
            return cls(1, 0, -d // 4)

    @override
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return False
        return self.a == other.a and self.b == other.b and self.c == other.c

    @override
    def __neg__(self) -> Self:
        return type(self)(self.a, -self.b, self.c)

    @override
    def __add__(self, other: Self) -> Self:
        d, r, s, t = _egcd(self.a, other.a, (self.b + other.b) // 2)
        a = self.a * other.a // d**2
        b = other.b + 2 * other.a * (s * (self.b - other.b) // 2 - t * other.c) // d
        c = (b**2 - self.discriminant()) // (4 * a)
        return type(self)(a, b, c)

    @override
    def __copy__(self) -> Self:
        return type(self)(self.a, self.b, self.c)

    def __repr__(self) -> str:
        return "({}, {}, {})".format(self.a, self.b, self.c)


def new_cl_class(discriminant: int) -> type[Cl]:
    assert discriminant % 4 == 1 and _is_probably_prime(-discriminant)

    return type(
        "Cl{}".format(-discriminant),
        (Cl,),
        {
            "discriminant": classmethod(override(lambda cls: discriminant)),
            "__module__": __name__,
        },
    )


def _is_normal(a: int, b: int, _c: int) -> bool:
    return -a < b <= a


def _is_reduced(a: int, b: int, c: int) -> bool:
    return _is_normal(a, b, c) and a <= c and (b >= 0 if a == c else True)


def _is_probably_prime(p: int) -> bool:
    assert p % 4 == 3

    for i in range(16):
        x = randint(2, p - 1)
        y = pow(x, (p - 1) // 2, p)
        if y != 1 and y != p - 1:
            return False
    return True


def _reduction_step(a: int, b: int, c: int) -> tuple[int, int, int]:
    s = (c + b) // (2 * c)
    return (
        c,
        -b + 2 * s * c,
        c * s**2 - b * s + a,
    )


def _reduce(a: int, b: int, c: int) -> tuple[int, int, int]:
    if not _is_normal(a, b, c):
        a, b, c = c, -b, a
    while not _is_reduced(a, b, c):
        a, b, c = _reduction_step(a, b, c)
    return a, b, c


def _egcd(*integers: int) -> tuple[int, ...]:
    if len(integers) == 0:
        return (0,)

    (g, cs) = (integers[0], [1])  # Running accumulators for the results.
    for i, a in enumerate(integers):
        if not isinstance(a, int):  # Check type of all arguments.
            raise TypeError(
                "'"
                + type(a).__name__
                + "'"
                + " object cannot be interpreted as an integer"
            )
        if i == 0:  # First argument is already assigned to ``g``.
            continue

        # Perform an iterative version of the extended Euclidean algorithm for
        # the pair of inputs ``g`` and ``a``.
        (s, t, x0, x1, y0, y1) = (g, a, 1, 0, 0, 1)
        while t != 0:
            (q, s, t) = (s // t, t, s % t)
            (x0, x1) = (x1, x0 - q * x1)
            (y0, y1) = (y1, y0 - q * y1)

        # Assign the result of the two-argument algorithm to the running
        # accumulators.
        (g, s, t) = (s, x0, y0)
        cs = [c * s for c in cs] + [t]

    # To conform to the behavior of ``math.gcd``, always return the greatest
    # common divisor as a non-negative integer (adjusting the coefficients
    # accordingly, if necessary).
    return tuple([abs(g)] + ([-c for c in cs] if g < 0 else cs))
