# def pm(k, t, M):
#     denominator = 0.71867 * (2^k) / k
#     c = 8*(pi^2 - 6)/3

#     double_sigma = 0
#     for j in range(2, M+1):
#         for m in range (j, M+1):
#             if m == 2 :
#                 continue
#             double_sigma += 2^(m*(1-t)-j-(k-1)/j)

#     numerator = 2^(k-2-M*t) + c * 2^(k-2+t) * double_sigma
#     return (numerator / denominator)

# def P(k, t):
#     M_max = floor(2*sqrt(k-1) - 1)
#     best = +infinity
#     for M in range(3, M_max+1):
#         p = pm(k, t, M)
#         if p < best:
#             best = p
#     return strength(best)

from sage.parallel.decorate import parallel

R = RealField(64)

@parallel
def P(k, t):
    k = R(k)
    t = R(t)
    denominator = R(0.71867) * (2^k) / k
    c = 8*(R(pi)^2 - 6)/3
    M_max = floor(2*sqrt(k-1) - 1)
    double_sigma = 0
    best = +infinity
    for M in range(3, M_max+1):
        for j in range(2, M+1):
            m = M
            if m == 2 :
                continue
            double_sigma += 2^(m*(1-t) - j - (k-1)/j)
        numerator = 2^(k-2-M*t) + c * 2^(k-2+t) * double_sigma
        p_M = (numerator / denominator)
        if p_M < best:
            best = p_M
    return best

def strength(p):
    return floor(-log(p, 2))

required_iterations = {}
kappa = 80
last = None
for e in range(3, 21):
    k = 2 ^ e
    if last == 1:
        required_iterations[k] = 1
        continue
    t = 1
    p = P(k, t)
    while strength(p) < kappa:
        t += 1
        p = P(k, t)
    required_iterations[k] = t
    last = t

print(required_iterations)

# @parallel  # or @parallel(ncpus=4) if you want to cap it
# def compute_row(k):
#     row = [strength(P(k, t)) for t in ts]
#     return row

# ks = list(range(100, 601, 50))
# ts = list(range(1, 11))

# results = list(compute_row(ks))
# # results is a list of ((k,), row) in arbitrary order, so sort by k
# results.sort(key=lambda item: item[0][0])

# for k, row in results:
#     print(' '.join(str(v) for v in row))
#     print()

# for k in ks:
#     for t in ts:
#         print(strength(P(k, t)), end=' ')
#     print('\n')


# required_iterations = {}
# kappa = 128
# for e in range(2, 21):
#     k = 2 ^ e
#     t = 1
#     p = P(k, t)
#     while strength(p) < kappa:
#         t += 1
#         p = P(k, t)
#     required_iterations[k] = t

# print(required_iterations)
