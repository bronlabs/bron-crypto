import json

from sage.all import *

f2 = GF(2)['u']
(u,) = f2._first_ngens(1)

bf128 = GF((2, 128), name='v', modulus=u**128 + u**7 + u**2 + u + 1, names=('v',))
(v,) = bf128._first_ngens(1)

def int_repr(fe):
    value = 0
    for i in range(128):
        elem = Integer(fe[i]) << i
        value += elem
    return value

vector = {
    "mul": [],
    "add": [],
    "sub": [],
    "neg": [],
}

set_random_seed(0xcafebabe)
for i in range(16):
    x = bf128.random_element()
    y = bf128.random_element()
    z = x * y
    vector["mul"].append({
        "x": int_repr(x).to_bytes(16, "big").hex(),
        "y": int_repr(y).to_bytes(16, "big").hex(),
        "z": int_repr(z).to_bytes(16, "big").hex(),
    })

    x = bf128.random_element()
    y = bf128.random_element()
    z = x + y
    vector["add"].append({
        "x": int_repr(x).to_bytes(16, "big").hex(),
        "y": int_repr(y).to_bytes(16, "big").hex(),
        "z": int_repr(z).to_bytes(16, "big").hex(),
    })

    x = bf128.random_element()
    y = bf128.random_element()
    z = x - y
    vector["sub"].append({
        "x": int_repr(x).to_bytes(16, "big").hex(),
        "y": int_repr(y).to_bytes(16, "big").hex(),
        "z": int_repr(z).to_bytes(16, "big").hex(),
    })

    x = bf128.random_element()
    z = -x
    vector["neg"].append({
        "x": int_repr(x).to_bytes(16, "big").hex(),
        "z": int_repr(z).to_bytes(16, "big").hex(),
    })

print(json.dumps(vector, indent=2))
