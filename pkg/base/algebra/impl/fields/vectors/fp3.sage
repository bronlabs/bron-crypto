#!/usr/bin/env sage

import os
import pathlib

def gen_test_vectors_add(fp3, cases, outfile_name):
    set_random_seed(0x329d34a759d056e4)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp3.random_element()
            b = fp3.random_element()
            c = a + b
            outfile.write('    {"a": ["%s", "%s", "%s"], "b": ["%s", "%s", "%s"], "c": ["%s", "%s", "%s"]}%s\n' % (hex(a[0]), hex(a[1]), hex(a[2]), hex(b[0]), hex(b[1]), hex(b[2]), hex(c[0]), hex(c[1]), hex(c[2]), "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_sub(fp3, cases, outfile_name):
    set_random_seed(0xcdf3fbd6f3d86ac3)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp3.random_element()
            b = fp3.random_element()
            c = a - b
            outfile.write('    {"a": ["%s", "%s", "%s"], "b": ["%s", "%s", "%s"], "c": ["%s", "%s", "%s"]}%s\n' % (hex(a[0]), hex(a[1]), hex(a[2]), hex(b[0]), hex(b[1]), hex(b[2]), hex(c[0]), hex(c[1]), hex(c[2]), "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_neg(fp3, cases, outfile_name):
    set_random_seed(0x4eab7b7590f9b857)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp3.random_element()
            c = -a
            outfile.write('    {"a": ["%s", "%s", "%s"], "c": ["%s", "%s", "%s"]}%s\n' % (hex(a[0]), hex(a[1]), hex(a[2]), hex(c[0]), hex(c[1]), hex(c[2]), "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_mul(fp3, cases, outfile_name):
    set_random_seed(0x1d68adf37c685111)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp3.random_element()
            b = fp3.random_element()
            c = a * b
            outfile.write('    {"a": ["%s", "%s", "%s"], "b": ["%s", "%s", "%s"], "c": ["%s", "%s", "%s"]}%s\n' % (hex(a[0]), hex(a[1]), hex(a[2]), hex(b[0]), hex(b[1]), hex(b[2]), hex(c[0]), hex(c[1]), hex(c[2]), "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_div(fp3, cases, outfile_name):
    set_random_seed(0xd1fcc498d61b4c10)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp3.random_element()
            b = fp3.random_element()
            ok = 0 if b.is_zero() else 1
            c = a / b if ok == 1 else fp3(0)
            outfile.write('    {"a": ["%s", "%s", "%s"], "b": ["%s", "%s", "%s"], "c": ["%s", "%s", "%s"], "ok": %d}%s\n' % (hex(a[0]), hex(a[1]), hex(a[2]), hex(b[0]), hex(b[1]), hex(b[2]), hex(c[0]), hex(c[1]), hex(c[2]), ok, "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_inv(fp3, cases, outfile_name):
    set_random_seed(0xf6705a1b693b52da)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp3.random_element()
            ok = 0 if a.is_zero() else 1
            c = a.inverse() if ok == 1 else fp3(0)
            outfile.write('    {"a": ["%s", "%s", "%s"], "c": ["%s", "%s", "%s"], "ok": %d}%s\n' % (hex(a[0]), hex(a[1]), hex(a[2]), hex(c[0]), hex(c[1]), hex(c[2]), ok, "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_square(fp3, cases, outfile_name):
    set_random_seed(0xa957b41ce84aa0be)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp3.random_element()
            c = a^2
            outfile.write('    {"a": ["%s", "%s", "%s"], "c": ["%s", "%s", "%s"]}%s\n' % (hex(a[0]), hex(a[1]), hex(a[2]), hex(c[0]), hex(c[1]), hex(c[2]), "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

def gen_test_vectors_sqrt(fp3, cases, outfile_name):
    set_random_seed(0xc7f33a4aa7cac9fb)

    with open(outfile_name, 'w') as outfile:
        outfile.write('{\n')
        outfile.write('  "vectors": [\n')
        for i in range(cases):
            a = fp3.random_element()
            ok = 1 if a.is_square() else 0
            c = a.sqrt() if ok == 1 else fp3(0)
            outfile.write('    {"a": ["%s", "%s", "%s"], "c": ["%s", "%s", "%s"], "ok": %d}%s\n' % (hex(a[0]), hex(a[1]), hex(a[2]), hex(c[0]), hex(c[1]), hex(c[2]), ok, "," if i != cases - 1 else ""))
        outfile.write('  ]\n')
        outfile.write('}\n')

modulus = 0x429d16a1
fp3.<u> = GF((0x429d16a1, 3), modulus=x^3-5)
cases = 16
infile_name = os.getenv("GOFILE")
gen_test_vectors_add(fp3, cases, pathlib.Path(infile_name).with_suffix('.add.gen.json'))
gen_test_vectors_sub(fp3, cases, pathlib.Path(infile_name).with_suffix('.sub.gen.json'))
gen_test_vectors_neg(fp3, cases, pathlib.Path(infile_name).with_suffix('.neg.gen.json'))
gen_test_vectors_mul(fp3, cases, pathlib.Path(infile_name).with_suffix('.mul.gen.json'))
gen_test_vectors_div(fp3, cases, pathlib.Path(infile_name).with_suffix('.div.gen.json'))
gen_test_vectors_inv(fp3, cases, pathlib.Path(infile_name).with_suffix('.inv.gen.json'))
gen_test_vectors_square(fp3, cases, pathlib.Path(infile_name).with_suffix('.square.gen.json'))
gen_test_vectors_sqrt(fp3, cases, pathlib.Path(infile_name).with_suffix('.sqrt.gen.json'))
