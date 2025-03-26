#!/usr/bin/env sage

import os
import pathlib

def gen_test_vectors_add(fp6, cases, outfile_name):
    set_random_seed(0xa98f6b6da9252852)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp6.random_element()
            b = fp6.random_element()
            c = a + b
            outfile.write('    {\n')
            outfile.write('      "a": ["%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(a[0][0]), hex(a[0][1]), hex(a[1][0]), hex(a[1][1]), hex(a[2][0]), hex(a[2][1])))
            outfile.write('      "b": ["%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(b[0][0]), hex(b[0][1]), hex(b[1][0]), hex(b[1][1]), hex(b[2][0]), hex(b[2][1])))
            outfile.write('      "c": ["%s", "%s", "%s", "%s", "%s", "%s"]\n' % (hex(c[0][0]), hex(c[0][1]), hex(c[1][0]), hex(c[1][1]), hex(c[2][0]), hex(c[2][1])))
            outfile.write('    }%s\n' % ("," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_sub(fp6, cases, outfile_name):
    set_random_seed(0x951218ce0bd7003f)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp6.random_element()
            b = fp6.random_element()
            c = a - b
            outfile.write('    {\n')
            outfile.write('      "a": ["%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(a[0][0]), hex(a[0][1]), hex(a[1][0]), hex(a[1][1]), hex(a[2][0]), hex(a[2][1])))
            outfile.write('      "b": ["%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(b[0][0]), hex(b[0][1]), hex(b[1][0]), hex(b[1][1]), hex(b[2][0]), hex(b[2][1])))
            outfile.write('      "c": ["%s", "%s", "%s", "%s", "%s", "%s"]\n' % (hex(c[0][0]), hex(c[0][1]), hex(c[1][0]), hex(c[1][1]), hex(c[2][0]), hex(c[2][1])))
            outfile.write('    }%s\n' % ("," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_neg(fp6, cases, outfile_name):
    set_random_seed(0x146f515c569a5fe7)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp6.random_element()
            c = -a
            outfile.write('    {\n')
            outfile.write('      "a": ["%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(a[0][0]), hex(a[0][1]), hex(a[1][0]), hex(a[1][1]), hex(a[2][0]), hex(a[2][1])))
            outfile.write('      "c": ["%s", "%s", "%s", "%s", "%s", "%s"]\n' % (hex(c[0][0]), hex(c[0][1]), hex(c[1][0]), hex(c[1][1]), hex(c[2][0]), hex(c[2][1])))
            outfile.write('    }%s\n' % ("," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_mul(fp6, cases, outfile_name):
    set_random_seed(0x9b6f175e833d05a)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp6.random_element()
            b = fp6.random_element()
            c = a * b
            outfile.write('    {\n')
            outfile.write('      "a": ["%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(a[0][0]), hex(a[0][1]), hex(a[1][0]), hex(a[1][1]), hex(a[2][0]), hex(a[2][1])))
            outfile.write('      "b": ["%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(b[0][0]), hex(b[0][1]), hex(b[1][0]), hex(b[1][1]), hex(b[2][0]), hex(b[2][1])))
            outfile.write('      "c": ["%s", "%s", "%s", "%s", "%s", "%s"]\n' % (hex(c[0][0]), hex(c[0][1]), hex(c[1][0]), hex(c[1][1]), hex(c[2][0]), hex(c[2][1])))
            outfile.write('    }%s\n' % ("," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_div(fp6, cases, outfile_name):
    set_random_seed(0x3043800765aa3cb5)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp6.random_element()
            b = fp6.random_element()
            ok = 1 if not b.is_zero() else 0
            c = a / b if ok == 1 else fp6(0)
            outfile.write('    {\n')
            outfile.write('      "a": ["%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(a[0][0]), hex(a[0][1]), hex(a[1][0]), hex(a[1][1]), hex(a[2][0]), hex(a[2][1])))
            outfile.write('      "b": ["%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(b[0][0]), hex(b[0][1]), hex(b[1][0]), hex(b[1][1]), hex(b[2][0]), hex(b[2][1])))
            outfile.write('      "c": ["%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(c[0][0]), hex(c[0][1]), hex(c[1][0]), hex(c[1][1]), hex(c[2][0]), hex(c[2][1])))
            outfile.write('      "ok": %d\n' % (ok))
            outfile.write('    }%s\n' % ("," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_inv(fp6, cases, outfile_name):
    set_random_seed(0x709a685dc779b772)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp6.random_element()
            ok = 1 if not a.is_zero() else 0
            c = a.inverse() if ok == 1 else fp6(0)
            outfile.write('    {\n')
            outfile.write('      "a": ["%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(a[0][0]), hex(a[0][1]), hex(a[1][0]), hex(a[1][1]), hex(a[2][0]), hex(a[2][1])))
            outfile.write('      "c": ["%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(c[0][0]), hex(c[0][1]), hex(c[1][0]), hex(c[1][1]), hex(c[2][0]), hex(c[2][1])))
            outfile.write('      "ok": %d\n' % (ok))
            outfile.write('    }%s\n' % ("," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_square(fp6, cases, outfile_name):
    set_random_seed(0xdb9c0ca2d5f9f41f)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp6.random_element()
            c = a^2
            outfile.write('    {\n')
            outfile.write('      "a": ["%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(a[0][0]), hex(a[0][1]), hex(a[1][0]), hex(a[1][1]), hex(a[2][0]), hex(a[2][1])))
            outfile.write('      "c": ["%s", "%s", "%s", "%s", "%s", "%s"]\n' % (hex(c[0][0]), hex(c[0][1]), hex(c[1][0]), hex(c[1][1]), hex(c[2][0]), hex(c[2][1])))
            outfile.write('    }%s\n' % ("," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_sqrt(fp6, cases, outfile_name):
    set_random_seed(0xb82ab7aa2ff1565f)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            c = fp6.random_element()
            a = c^2
            outfile.write('    {\n')
            outfile.write('      "a": ["%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(a[0][0]), hex(a[0][1]), hex(a[1][0]), hex(a[1][1]), hex(a[2][0]), hex(a[2][1])))
            outfile.write('      "c": ["%s", "%s", "%s", "%s", "%s", "%s"],\n' % (hex(c[0][0]), hex(c[0][1]), hex(c[1][0]), hex(c[1][1]), hex(c[2][0]), hex(c[2][1])))
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
assert fp6.is_field() == True

cases = 16
infile_name = os.getenv("GOFILE")
gen_test_vectors_add(fp6, cases, pathlib.Path(infile_name).with_suffix('.add.gen.json'))
gen_test_vectors_sub(fp6, cases, pathlib.Path(infile_name).with_suffix('.sub.gen.json'))
gen_test_vectors_neg(fp6, cases, pathlib.Path(infile_name).with_suffix('.neg.gen.json'))
gen_test_vectors_mul(fp6, cases, pathlib.Path(infile_name).with_suffix('.mul.gen.json'))
gen_test_vectors_div(fp6, cases, pathlib.Path(infile_name).with_suffix('.div.gen.json'))
gen_test_vectors_inv(fp6, cases, pathlib.Path(infile_name).with_suffix('.inv.gen.json'))
gen_test_vectors_square(fp6, cases, pathlib.Path(infile_name).with_suffix('.square.gen.json'))
gen_test_vectors_sqrt(fp6, cases, pathlib.Path(infile_name).with_suffix('.sqrt.gen.json'))
