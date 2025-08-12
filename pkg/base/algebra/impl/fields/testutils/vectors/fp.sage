#!/usr/bin/env sage

import os
import pathlib

def gen_test_vectors_fp_add(modulus, cases, outfile_name):
    set_random_seed(0xe1e2ce95147c14a9)
    fp = GF(modulus)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp.random_element()
            b = fp.random_element()
            c = a + b
            outfile.write('    {"a": ["%s"], "b": ["%s"], "c": ["%s"]}%s\n' % (hex(a), hex(b), hex(c), "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_fp_sub(modulus, cases, outfile_name):
    set_random_seed(0x26b8ddfac5d5fc52)
    fp = GF(modulus)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp.random_element()
            b = fp.random_element()
            c = a - b
            outfile.write('    {"a": ["%s"], "b": ["%s"], "c": ["%s"]}%s\n' % (hex(a), hex(b), hex(c), "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_fp_neg(modulus, cases, outfile_name):
    set_random_seed(0xddac4f0332365372)
    fp = GF(modulus)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp.random_element()
            c = -a
            outfile.write('    {"a": ["%s"], "c": ["%s"]}%s\n' % (hex(a), hex(c), "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_fp_mul(modulus, cases, outfile_name):
    set_random_seed(0xdeadbeefcafebabe)
    fp = GF(modulus)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp.random_element()
            b = fp.random_element()
            c = a * b
            outfile.write('    {"a": ["%s"], "b": ["%s"], "c": ["%s"]}%s\n' % (hex(a), hex(b), hex(c), "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_fp_div(modulus, cases, outfile_name):
    set_random_seed(0x4dffb070b70c897)
    fp = GF(modulus)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp.random_element()
            b = fp.random_element()
            c = a / b
            ok = 0 if b.is_zero() else 1
            outfile.write('    {"a": ["%s"], "b": ["%s"], "c": ["%s"], "ok": %d}%s\n' % (hex(a), hex(b), hex(c), ok, "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_fp_inv(modulus, cases, outfile_name):
    set_random_seed(0x147c8cb19d75f642)
    fp = GF(modulus)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp.random_element()
            c = a.inverse()
            ok = 0 if a.is_zero() else 1
            outfile.write('    {"a": ["%s"], "c": ["%s"], "ok": %d}%s\n' % (hex(a), hex(c), ok, "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_fp_square(modulus, cases, outfile_name):
    set_random_seed(0x23d1d1e3dd90de36)
    fp = GF(modulus)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp.random_element()
            c = a^2
            outfile.write('    {"a": ["%s"], "c": ["%s"]}%s\n' % (hex(a), hex(c), "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_fp_sqrt(modulus, cases, outfile_name):
    set_random_seed(0x531672187c6c29bc)
    fp = GF(modulus)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp.random_element()
            ok = 1 if a.is_square() else 0
            c = a.sqrt() if ok == 1 else 0
            outfile.write('    {"a": ["%s"], "c": ["%s"], "ok": %d}%s\n' % (hex(a), hex(c), ok, "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

modulus=0x429d16a1
cases=16
infile_name = os.getenv("GOFILE")
gen_test_vectors_fp_add(modulus, cases, pathlib.Path(infile_name).with_suffix('.add.gen.json'))
gen_test_vectors_fp_sub(modulus, cases, pathlib.Path(infile_name).with_suffix('.sub.gen.json'))
gen_test_vectors_fp_neg(modulus, cases, pathlib.Path(infile_name).with_suffix('.neg.gen.json'))
gen_test_vectors_fp_mul(modulus, cases, pathlib.Path(infile_name).with_suffix('.mul.gen.json'))
gen_test_vectors_fp_div(modulus, cases, pathlib.Path(infile_name).with_suffix('.div.gen.json'))
gen_test_vectors_fp_inv(modulus, cases, pathlib.Path(infile_name).with_suffix('.inv.gen.json'))
gen_test_vectors_fp_square(modulus, cases, pathlib.Path(infile_name).with_suffix('.square.gen.json'))
gen_test_vectors_fp_sqrt(modulus, cases, pathlib.Path(infile_name).with_suffix('.sqrt.gen.json'))
