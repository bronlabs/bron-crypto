# `map_to_curve`
MapToCurve maps a list of elements of a finite field F to a list of points
on an elliptic curve E over F. The mapping is deterministic, following the
instructions from [RFC9380](https://datatracker.ietf.org/doc/html/rfc9380#section-6):
  - _Montgomery curves_ --> Elligator 2 method (Section 6.7.1, Section 6.8.2 for
    twisted edwards).
  - _Weierstrass curves_ --> Simplified Shallue-van de Woestijne-Ulas (SWU)
    method (Section 6.6.2) if possible.
