#!/usr/bin/env sage

'''
Computes the required number of rounds of Miller-Rabin, from Appendix C of FIPS 186-5.
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
'''

from sage.parallel.decorate import parallel
import json
import sys

if len(sys.argv) != 2:
    print(sys.argv)
    sys.exit("Usage: fips1865c.sage <statistical_security_level>")

R = RealField(64)

def p(k, t, M):
    k = R(k)
    t = R(t)
    double_sum = 0
    for m in range(3, M+1):
        inner_sum = 0
        for j in range(2, m+1):
            inner_sum += 1/(2^(j+(k-1)/j))
        double_sum += 2^(m-(m-1)*t) * inner_sum
    return R(2.00743)*R(ln(2))*k*2^(-k) * (2^(k-2-R(M)*t) + ((8*(R(pi)^2 - 6))/3) * 2^(k-2) * double_sum)

@parallel
def find_t(k, kappa):
    for t in range(1, ceil(kappa/2)):
        for M in range(3, floor(2*sqrt(k - 1) - 1)):
            p_val = p(k, t, M)
            if p_val < 2^(-kappa):
                return t

def required_iterations(statistical_security_level):
    ans = {}
    last = None
    bitLen = 5 # In Go, Primality checks will be 100% accurate for < 2^64
    while last != 1:
        bitLen += 1
        k = 2 ^ bitLen
        t = find_t(k, statistical_security_level)
        ans[k] = t
        last = t
    # Convert Sage Integer types to Python int for JSON serialization
    return {int(k): int(v) for k, v in ans.items()}


statistical_security_level = eval(preparse(sys.argv[1]))
print(json.dumps(required_iterations(statistical_security_level), indent=2))