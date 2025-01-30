#!/usr/bin/env python3

from sage.all_cmdline import *

def main():
    if len(sys.argv) != 2:
        print(sys.argv)
        sys.exit("Usage: root-of-unity.py <modulus>")

    p = eval(preparse(sys.argv[1]))
    fp = GF(p)
    e = (p-1).trailing_zero_bits()
    d = fp.primitive_element()
    z = d**(p >> e)
    print(hex(z), hex(p))

if __name__ == '__main__':
    main()
