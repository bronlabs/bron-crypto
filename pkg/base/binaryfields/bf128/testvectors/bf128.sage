import json

bf128 = GF((2, 128), name='u', modulus=x^128 + x^7 + x^2 + x + 1)

def int_repr(fe):
    value = 0
    for i in range(128):
        elem = Integer(fe[i]) << i
        value += elem
    return value

vector = {
    "mul": [],
    "div": [],
    "inv": [],
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
    z = x / y
    vector["div"].append({
        "x": int_repr(x).to_bytes(16, "big").hex(),
        "y": int_repr(y).to_bytes(16, "big").hex(),
        "z": int_repr(z).to_bytes(16, "big").hex(),
    })

    x = bf128.random_element()
    z = x.inverse()
    vector["inv"].append({
        "x": int_repr(x).to_bytes(16, "big").hex(),
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
