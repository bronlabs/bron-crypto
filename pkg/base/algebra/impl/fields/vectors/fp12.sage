#!/usr/bin/env sage

import os
import pathlib

def gen_test_vectors_add(fp12, cases, outfile_name):
    set_random_seed(0xc0962b9ba290b33c)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp12.random_element()
            b = fp12.random_element()
            c = a + b
            outfile.write('    {\n')
            outfile.write('      "a": ["%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(a[0][0][0]), hex(a[0][0][1]), hex(a[0][1][0]), hex(a[0][1][1]), hex(a[0][2][0]), hex(a[0][2][1]), hex(a[1][0][0]), hex(a[1][0][1]), hex(a[1][1][0]), hex(a[1][1][1]), hex(a[1][2][0]), hex(a[1][2][1])))
            outfile.write('      "b": ["%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(b[0][0][0]), hex(b[0][0][1]), hex(b[0][1][0]), hex(b[0][1][1]), hex(b[0][2][0]), hex(b[0][2][1]), hex(b[1][0][0]), hex(b[1][0][1]), hex(b[1][1][0]), hex(b[1][1][1]), hex(b[1][2][0]), hex(b[1][2][1])))
            outfile.write('      "c": ["%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"]\n' % (hex(c[0][0][0]), hex(c[0][0][1]), hex(c[0][1][0]), hex(c[0][1][1]), hex(c[0][2][0]), hex(c[0][2][1]), hex(c[1][0][0]), hex(c[1][0][1]), hex(c[1][1][0]), hex(c[1][1][1]), hex(c[1][2][0]), hex(c[1][2][1])))
            outfile.write('    }%s\n' % ("," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_sub(fp12, cases, outfile_name):
    set_random_seed(0x941a84f34b13f105)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp12.random_element()
            b = fp12.random_element()
            c = a - b
            outfile.write('    {\n')
            outfile.write('      "a": ["%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(a[0][0][0]), hex(a[0][0][1]), hex(a[0][1][0]), hex(a[0][1][1]), hex(a[0][2][0]), hex(a[0][2][1]), hex(a[1][0][0]), hex(a[1][0][1]), hex(a[1][1][0]), hex(a[1][1][1]), hex(a[1][2][0]), hex(a[1][2][1])))
            outfile.write('      "b": ["%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(b[0][0][0]), hex(b[0][0][1]), hex(b[0][1][0]), hex(b[0][1][1]), hex(b[0][2][0]), hex(b[0][2][1]), hex(b[1][0][0]), hex(b[1][0][1]), hex(b[1][1][0]), hex(b[1][1][1]), hex(b[1][2][0]), hex(b[1][2][1])))
            outfile.write('      "c": ["%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"]\n' % (hex(c[0][0][0]), hex(c[0][0][1]), hex(c[0][1][0]), hex(c[0][1][1]), hex(c[0][2][0]), hex(c[0][2][1]), hex(c[1][0][0]), hex(c[1][0][1]), hex(c[1][1][0]), hex(c[1][1][1]), hex(c[1][2][0]), hex(c[1][2][1])))
            outfile.write('    }%s\n' % ("," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_neg(fp12, cases, outfile_name):
    set_random_seed(0x71b2b18f78a859c1)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp12.random_element()
            c = -a
            outfile.write('    {\n')
            outfile.write('      "a": ["%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(a[0][0][0]), hex(a[0][0][1]), hex(a[0][1][0]), hex(a[0][1][1]), hex(a[0][2][0]), hex(a[0][2][1]), hex(a[1][0][0]), hex(a[1][0][1]), hex(a[1][1][0]), hex(a[1][1][1]), hex(a[1][2][0]), hex(a[1][2][1])))
            outfile.write('      "c": ["%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"]\n' % (hex(c[0][0][0]), hex(c[0][0][1]), hex(c[0][1][0]), hex(c[0][1][1]), hex(c[0][2][0]), hex(c[0][2][1]), hex(c[1][0][0]), hex(c[1][0][1]), hex(c[1][1][0]), hex(c[1][1][1]), hex(c[1][2][0]), hex(c[1][2][1])))
            outfile.write('    }%s\n' % ("," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_mul(fp12, cases, outfile_name):
    set_random_seed(0x480a24ff48f48bc6)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp12.random_element()
            b = fp12.random_element()
            c = a * b
            outfile.write('    {\n')
            outfile.write('      "a": ["%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(a[0][0][0]), hex(a[0][0][1]), hex(a[0][1][0]), hex(a[0][1][1]), hex(a[0][2][0]), hex(a[0][2][1]), hex(a[1][0][0]), hex(a[1][0][1]), hex(a[1][1][0]), hex(a[1][1][1]), hex(a[1][2][0]), hex(a[1][2][1])))
            outfile.write('      "b": ["%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(b[0][0][0]), hex(b[0][0][1]), hex(b[0][1][0]), hex(b[0][1][1]), hex(b[0][2][0]), hex(b[0][2][1]), hex(b[1][0][0]), hex(b[1][0][1]), hex(b[1][1][0]), hex(b[1][1][1]), hex(b[1][2][0]), hex(b[1][2][1])))
            outfile.write('      "c": ["%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"]\n' % (hex(c[0][0][0]), hex(c[0][0][1]), hex(c[0][1][0]), hex(c[0][1][1]), hex(c[0][2][0]), hex(c[0][2][1]), hex(c[1][0][0]), hex(c[1][0][1]), hex(c[1][1][0]), hex(c[1][1][1]), hex(c[1][2][0]), hex(c[1][2][1])))
            outfile.write('    }%s\n' % ("," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_div(fp12, cases, outfile_name):
    set_random_seed(0x94054289fbd40af5)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp12.random_element()
            b = fp12.random_element()
            ok = 1 if not b.is_zero() else 0
            c = a / b if ok == 1 else fp12(0)
            outfile.write('    {\n')
            outfile.write('      "a": ["%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(a[0][0][0]), hex(a[0][0][1]), hex(a[0][1][0]), hex(a[0][1][1]), hex(a[0][2][0]), hex(a[0][2][1]), hex(a[1][0][0]), hex(a[1][0][1]), hex(a[1][1][0]), hex(a[1][1][1]), hex(a[1][2][0]), hex(a[1][2][1])))
            outfile.write('      "b": ["%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(b[0][0][0]), hex(b[0][0][1]), hex(b[0][1][0]), hex(b[0][1][1]), hex(b[0][2][0]), hex(b[0][2][1]), hex(b[1][0][0]), hex(b[1][0][1]), hex(b[1][1][0]), hex(b[1][1][1]), hex(b[1][2][0]), hex(b[1][2][1])))
            outfile.write('      "c": ["%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(c[0][0][0]), hex(c[0][0][1]), hex(c[0][1][0]), hex(c[0][1][1]), hex(c[0][2][0]), hex(c[0][2][1]), hex(c[1][0][0]), hex(c[1][0][1]), hex(c[1][1][0]), hex(c[1][1][1]), hex(c[1][2][0]), hex(c[1][2][1])))
            outfile.write('      "ok": %d\n' % (ok))
            outfile.write('    }%s\n' % ("," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_inv(fp12, cases, outfile_name):
    set_random_seed(0x15c309c1399dc776)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp12.random_element()
            ok = 1 if not a.is_zero() else 0
            c = 1 / a if ok == 1 else fp12(0)
            outfile.write('    {\n')
            outfile.write('      "a": ["%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(a[0][0][0]), hex(a[0][0][1]), hex(a[0][1][0]), hex(a[0][1][1]), hex(a[0][2][0]), hex(a[0][2][1]), hex(a[1][0][0]), hex(a[1][0][1]), hex(a[1][1][0]), hex(a[1][1][1]), hex(a[1][2][0]), hex(a[1][2][1])))
            outfile.write('      "c": ["%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(c[0][0][0]), hex(c[0][0][1]), hex(c[0][1][0]), hex(c[0][1][1]), hex(c[0][2][0]), hex(c[0][2][1]), hex(c[1][0][0]), hex(c[1][0][1]), hex(c[1][1][0]), hex(c[1][1][1]), hex(c[1][2][0]), hex(c[1][2][1])))
            outfile.write('      "ok": %d\n' % (ok))
            outfile.write('    }%s\n' % ("," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_square(fp12, cases, outfile_name):
    set_random_seed(0x4943f61868e898c8)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp12.random_element()
            c = a^2
            outfile.write('    {\n')
            outfile.write('      "a": ["%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(a[0][0][0]), hex(a[0][0][1]), hex(a[0][1][0]), hex(a[0][1][1]), hex(a[0][2][0]), hex(a[0][2][1]), hex(a[1][0][0]), hex(a[1][0][1]), hex(a[1][1][0]), hex(a[1][1][1]), hex(a[1][2][0]), hex(a[1][2][1])))
            outfile.write('      "c": ["%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"]\n' % (hex(c[0][0][0]), hex(c[0][0][1]), hex(c[0][1][0]), hex(c[0][1][1]), hex(c[0][2][0]), hex(c[0][2][1]), hex(c[1][0][0]), hex(c[1][0][1]), hex(c[1][1][0]), hex(c[1][1][1]), hex(c[1][2][0]), hex(c[1][2][1])))
            outfile.write('    }%s\n' % ("," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_sqrt(fp12, cases, outfile_name):
    set_random_seed(0x376256a71fddfeba)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            c = fp12.random_element()
            a = c^2
            outfile.write('    {\n')
            outfile.write('      "a": ["%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(a[0][0][0]), hex(a[0][0][1]), hex(a[0][1][0]), hex(a[0][1][1]), hex(a[0][2][0]), hex(a[0][2][1]), hex(a[1][0][0]), hex(a[1][0][1]), hex(a[1][1][0]), hex(a[1][1][1]), hex(a[1][2][0]), hex(a[1][2][1])))
            outfile.write('      "c": ["%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(c[0][0][0]), hex(c[0][0][1]), hex(c[0][1][0]), hex(c[0][1][1]), hex(c[0][2][0]), hex(c[0][2][1]), hex(c[1][0][0]), hex(c[1][0][1]), hex(c[1][1][0]), hex(c[1][1][1]), hex(c[1][2][0]), hex(c[1][2][1])))
            outfile.write('      "ok": 1\n')
            outfile.write('    }%s\n' % ("," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

p = 0x429d16a1
fp = GF(p)
k2.<x> = PolynomialRing(fp)
fp2.<u> = GF((p, 2), modulus=x^2+7)
k6.<y> = PolynomialRing(fp2)
fp6.<v> = fp2.extension(y^3-(u+4))
assert fp6.is_field()
k12.<z> = PolynomialRing(fp6)
fp12.<w> = fp6.extension(z^2-(v+5))
assert fp12.is_field()

cases = 128
infile_name = os.getenv("GOFILE")
gen_test_vectors_add(fp12, cases, pathlib.Path(infile_name).with_suffix('.add.gen.json'))
gen_test_vectors_sub(fp12, cases, pathlib.Path(infile_name).with_suffix('.sub.gen.json'))
gen_test_vectors_neg(fp12, cases, pathlib.Path(infile_name).with_suffix('.neg.gen.json'))
gen_test_vectors_mul(fp12, cases, pathlib.Path(infile_name).with_suffix('.mul.gen.json'))
gen_test_vectors_div(fp12, cases, pathlib.Path(infile_name).with_suffix('.div.gen.json'))
gen_test_vectors_inv(fp12, cases, pathlib.Path(infile_name).with_suffix('.inv.gen.json'))
gen_test_vectors_square(fp12, cases, pathlib.Path(infile_name).with_suffix('.square.gen.json'))
gen_test_vectors_sqrt(fp12, cases, pathlib.Path(infile_name).with_suffix('.sqrt.gen.json'))
