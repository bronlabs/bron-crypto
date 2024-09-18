from random import randint


# decompose is an algorithm that takes an integer as input and returns (t,k): its decomposition of the form 2^t(2k+1) with k>0
def decompose(mu: int) -> tuple[int, int]:
    t = (mu & -mu).bit_length() - 1
    k = mu >> (t + 1)
    return t, k


# get_two_firsts is an algorithm that takes an integer as input and returns two candidates for w1 and w2 which are potentially the sum of 2 squares
def get_two_firsts(mu: int) -> tuple[int, int]:
    w1_len = mu.bit_length() // 2 + 1

    while True:
        w1 = randint(0, 2**w1_len)
        w2_len = (mu - w1 * w1).bit_length() // 2 + 1
        w2 = randint(0, 2**w2_len)
        if ((w1 * w1 + w2 * w2) <= mu) and (w1 % 2 != w2 % 2):
            return w1, w2


# euclidian_adhoc takes as input two integers and returns the two last remainder of the euclidian algorithm that are lower or equal to the square root of the second input (namely p)
def euclidian_adhoc(u: int, p: int) -> tuple[int, int]:
    r = p % u
    while u * u > p:
        a = u
        u = r
        if u != 0:
            r = a % u

    return r, u


def sqrt_minus_one(p: int) -> int | None:
    quarter_p = (p - 1) >> 2

    for i in range(5):
        sqrt_candidate = pow(randint(1, p), quarter_p, p)
        if pow(sqrt_candidate, 2, p) == p - 1:
            return sqrt_candidate

    return None


# get_two_lasts takes as input p computed by get_two_firsts and returns a boolean and two integers, if the boolean is true then the two integers are w3 and w4
def get_two_lasts(p: int) -> tuple[bool, int, int]:
    if p == 0:
        return True, 0, 0

    if p == 1:
        return True, 1, 0

    minus_one_root = sqrt_minus_one(p)
    if minus_one_root is None:
        return False, 0, 0

    w3, w4 = euclidian_adhoc(minus_one_root, p)
    if p != (w3**2 + w4**2):
        return False, 0, 0

    return True, w3, w4


# get_four_squares returns the four integers that are the decomposition of mu into sum of four squares
def get_four_squares(mu: int) -> tuple[int, int, int, int]:
    assert mu >= 0 and isinstance(mu, int)
    if mu == 0:
        return 0, 0, 0, 0

    t, k = decompose(mu)

    # t == 1
    if t == 1:
        while True:
            w1, w2 = get_two_firsts(mu)
            p = mu - w1**2 - w2**2
            exists, w3, w4 = get_two_lasts(p)
            if exists:
                return abs(w1), abs(w2), abs(w3), abs(w4)

    # t is odd and not 1
    if t % 2 == 1:
        s = 2 ** ((t - 1) // 2)
        w1, w2, w3, w4 = get_four_squares(mu // (s**2))
        return s * abs(w1), s * abs(w2), s * abs(w3), s * abs(w4)

    # t is even
    w1, w2, w3, w4 = get_four_squares(2 * (2 * k + 1))
    w1, w2, w3, w4 = tuple(sorted([w1, w2, w3, w4], key=lambda x: x % 2))
    s = 2 ** ((t // 2) - 1)

    if t == 0:
        return (
            (abs((w1 + w2) // 2)),
            (abs((w1 - w2) // 2)),
            (abs((w3 + w4) // 2)),
            (abs((w3 - w4) // 2)),
        )
    else:
        return (
            (abs(s * (w1 + w2))),
            (abs(s * (w1 - w2))),
            (abs(s * (w3 + w4))),
            (abs(s * (w3 - w4))),
        )
