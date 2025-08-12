#!/usr/bin/env sage

import os
import pathlib

def gen_test_vectors_add(fp2, cases, outfile_name):
    set_random_seed(0xd717d11469b4715c)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp2.random_element()
            b = fp2.random_element()
            c = a + b
            outfile.write('    {"a": ["%s", "%s"], "b": ["%s", "%s"], "c": ["%s", "%s"]}%s\n' % (hex(a[0]), hex(a[1]), hex(b[0]), hex(b[1]), hex(c[0]), hex(c[1]), "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_sub(fp2, cases, outfile_name):
    set_random_seed(0xa2b19d6d9e7bd97a)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp2.random_element()
            b = fp2.random_element()
            c = a - b
            outfile.write('    {"a": ["%s", "%s"], "b": ["%s", "%s"], "c": ["%s", "%s"]}%s\n' % (hex(a[0]), hex(a[1]), hex(b[0]), hex(b[1]), hex(c[0]), hex(c[1]), "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_neg(fp2, cases, outfile_name):
    set_random_seed(0x4eab7b7590f9b857)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp2.random_element()
            c = -a
            outfile.write('    {"a": ["%s", "%s"], "c": ["%s", "%s"]}%s\n' % (hex(a[0]), hex(a[1]), hex(c[0]), hex(c[1]), "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_mul(fp2, cases, outfile_name):
    set_random_seed(0x4a83a9bd42a398a1)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp2.random_element()
            b = fp2.random_element()
            c = a * b
            outfile.write('    {"a": ["%s", "%s"], "b": ["%s", "%s"], "c": ["%s", "%s"]}%s\n' % (hex(a[0]), hex(a[1]), hex(b[0]), hex(b[1]), hex(c[0]), hex(c[1]), "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_div(fp2, cases, outfile_name):
    set_random_seed(0x44894db375fd8766)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp2.random_element()
            b = fp2.random_element()
            ok = 0 if b.is_zero() else 1
            c = a / b if ok == 1 else fp2(0)
            outfile.write('    {"a": ["%s", "%s"], "b": ["%s", "%s"], "c": ["%s", "%s"], "ok": %d}%s\n' % (hex(a[0]), hex(a[1]), hex(b[0]), hex(b[1]), hex(c[0]), hex(c[1]), ok, "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_inv(fp2, cases, outfile_name):
    set_random_seed(0xe7a9b8ce8d359d09)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp2.random_element()
            ok = 0 if a.is_zero() else 1
            c = a.inverse() if ok == 1 else fp2(0)
            outfile.write('    {"a": ["%s", "%s"], "c": ["%s", "%s"], "ok": %d}%s\n' % (hex(a[0]), hex(a[1]), hex(c[0]), hex(c[1]), ok, "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_square(fp2, cases, outfile_name):
    set_random_seed(0x66d88a121010c480)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp2.random_element()
            c = a^2
            outfile.write('    {"a": ["%s", "%s"], "c": ["%s", "%s"]}%s\n' % (hex(a[0]), hex(a[1]), hex(c[0]), hex(c[1]), "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_sqrt(fp2, cases, outfile_name):
    set_random_seed(0x31556d8cecf0fadb)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp2.random_element()
            ok = 1 if a.is_square() else 0
            c = a.sqrt() if ok == 1 else fp2(0)
            outfile.write('    {"a": ["%s", "%s"], "c": ["%s", "%s"], "ok": %d}%s\n' % (hex(a[0]), hex(a[1]), hex(c[0]), hex(c[1]), ok, "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

modulus = 0x429d16a1
fp2.<u> = GF((modulus, 2), modulus=x^2+7)
cases = 16
infile_name = os.getenv("GOFILE")
gen_test_vectors_add(fp2, cases, pathlib.Path(infile_name).with_suffix('.add.gen.json'))
gen_test_vectors_sub(fp2, cases, pathlib.Path(infile_name).with_suffix('.sub.gen.json'))
gen_test_vectors_neg(fp2, cases, pathlib.Path(infile_name).with_suffix('.neg.gen.json'))
gen_test_vectors_mul(fp2, cases, pathlib.Path(infile_name).with_suffix('.mul.gen.json'))
gen_test_vectors_div(fp2, cases, pathlib.Path(infile_name).with_suffix('.div.gen.json'))
gen_test_vectors_inv(fp2, cases, pathlib.Path(infile_name).with_suffix('.inv.gen.json'))
gen_test_vectors_square(fp2, cases, pathlib.Path(infile_name).with_suffix('.square.gen.json'))
gen_test_vectors_sqrt(fp2, cases, pathlib.Path(infile_name).with_suffix('.sqrt.gen.json'))
