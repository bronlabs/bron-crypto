from random import randint

# sort the vector such that the two first element are the same modulo 2 and do the same for the 2 last elements
def sort(w1, w2, w3, w4):
    if (w1 % 2) != (w2 % 2):
        if (w1 % 2) == (w3 % 2):
            (w2, w3) = (w3, w2)
        else:
            (w2, w4) = (w4, w2)
    return w1, w2, w3, w4

# decompose is an algorithm that takes an integer as input and returns (t,k): its decomposition of the form 2^t(2k+1) with k>0
def decompose(mu):
    tmp = mu
    t = 0
    while tmp % 2==0:
        tmp = tmp // 2
        t = t + 1
    tmp = tmp - 1
    k = tmp // 2
    return t, k

# get_two_firsts is an algorithm that takes an integer as input and returns two candidates for w1 and w2 and the integer p which is potentially the sum of 2 squares
def get_two_firsts(mu):
    w1 = 0
    w2 = 0
    w1len = mu.bit_length() //2 +1
    while (w1 % 2 == w2 % 2) or (w1 * w1 + w2 * w2 > mu):
        w1 = randint(0,2 ** w1len)
        w2 = randint(0, 2 ** ((mu - w1 * w1).bit_length() // 2 +1))

    return w1, w2

# euclidianAdhoc takes as input two integers and returns the two last remainder of the euclidian algorithm that are lower or equal to the square root of the second input (namely p)
def euclidian_adhoc(u, p):
    r = p % u
    while u * u > p:
        a = u
        u = r
        if u != 0:
            r = a % u
    return r, u

# the next function takes as input p computed by get_two_firsts and returns a boolean and two integers, if the boolean is true then the two integers are w3 and w4
def get_two_lasts(p) -> tuple[bool, int, int]:
    if p == 0:
        return True, 0, 0

    if p == 1:
        return True, 1, 0

    quarter_p = (p - 1) >> 2
    sqr_u = pow(randint(1, p), quarter_p, p)
    u = pow(sqr_u, 2, p)
    if pow(u, p - 1, p) != 1:
        return False, 0, 0
    for i in range(5): #u==(p-1) happens half the time if p is prime, failing this test 6 times would mean p has less chance than 1/2^6 to be prime (meh probabilities but that's the spirit)
        if u == (p - 1):
            (w3, w4) = euclidian_adhoc(sqr_u, p)
            if p == (w3 ** 2 + w4 ** 2):
                return True, w3, w4
            else:
                return False, 0, 0
        u = pow(randint(1, p), quarter_p, p)
    return False, 0, 0

# the next function returns the four integer that is the decomposition of mu into sums of four square
def get_four_square(mu):
    assert mu >= 0
    if mu == 0:
        return 0, 0, 0, 0
    (t, k) = decompose(mu)

    if t == 1:
        (w1, w2) = get_two_firsts(mu)
        p = mu - w1 ** 2 - w2 ** 2
        (exist, w3, w4) = get_two_lasts(p)

        while not exist:
            (w1, w2) = get_two_firsts(mu)
            p = mu - w1 ** 2 - w2 ** 2
            (exist, w3, w4) = get_two_lasts(p)
        return abs(w1), abs(w2), abs(w3), abs(w4)

    if t % 2 == 1:
        s = 2 ** ((t - 1) // 2)
        (w1, w2, w3, w4) = get_four_square(mu // (s ** 2))
        return s * abs(w1), s * abs(w2), s * abs(w3), s * abs(w4)

    (w1, w2, w3, w4) = get_four_square(2 * (2 * k + 1))
    (w1, w2, w3, w4) = sort(w1, w2, w3 ,w4)
    s = 2 ** ((t // 2) - 1)
    if t == 0:
        return (abs((w1 + w2) // 2)), (abs((w1 - w2) // 2)), (abs((w3 + w4) // 2)), (abs((w3 - w4) // 2))
    return (abs(s * (w1 + w2))), (abs(s * (w1 - w2))), (abs(s * (w3 + w4))), (abs(s * (w3 - w4)))

