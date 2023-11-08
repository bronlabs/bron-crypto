# ECSVDP-DHC (Elliptic Curve Secret Value Derivation Primitive, Diffie-Hellman version with cofactor multiplication)

This package implements ECSVDP-DHC, as per section 7.2.2 of [IEEE 1363-2000](https://standards.ieee.org/ieee/1363/2049/)

ECSVDP-DHC is the Elliptic Curve Secret Value Derivation Primitive, Diffie-Hellman version with cofactor multiplication. It is based on the work of Diffie and Hellman [B47], Kaliski [B88], Koblitz [B94], Law et al. [B98], and Miller [B117]. This primitive derives a shared secret value from one party’s private key and another party’s public key, where both have the same set of EC domain parameters. If two parties correctly execute this primitive, they will produce the same output. This primitive can be invoked by a scheme to derive a shared secret key; specifically, it may be used with the schemes ECKAS-DH1 and DL/ECKAS-DH2. It does not assume the validity of the input public key - unlike ECSVDP-DH.

## Notes
1. This primitive addresses small subgroup attacks, which may occur when the public key W′ is not valid (see D.5.1.6). A key agreement scheme only needs to validate that W′ is on the elliptic curve defined by a and b over GF (q) before executing this primitive (see also 7.2.1).
2. The cofactor k depends only on the EC domain parameters. Hence, it can be computed once for a given set of domain parameters and stored as part of the domain parameters. Similarly, in the compatibility case, the value k–1 can be computed once and stored with the domain parameters, and the integer t can be computed once for a given private key s. Algorithms for computing or verifying the cofactor are included in A.12.3.
3. When the public key W′ and the private key s are valid, the point P will be an element of a subset of the elliptic curve that consists of all the multiples of G (except for the element O). As a consequence, z will always be defined in this case. When the public key is invalid, the output will be either “invalid public key” or an element of order r on the elliptic curve; in particular, it will not be in a small subgroup.
4. In the compatibility case, ECSVDP-DHC computes the same output for valid keys as ECSVDP-DH, so an implementation that conforms with ECSVDP-DHC in the compatibility case also conforms with ECSVDP-DH.

## Input:
- The EC domain parameters q, a, b, r, G, and the cofactor associated with the keys s and W′ (the domain parameters shall be the same for both s and W′) - Notation defined in 7.1.1
- The party’s own private key s
- The other party’s public key W′
- An indication as to whether compatibility with ECSVDP-DH is desired - For our case, it is preset.

## Assumptions:
1. Private key s, EC domain parameters q, a, b, r, G, and k are valid.
2. The private key is associated with the domain parameters.
3. W′ is on the elliptic curve defined by a and b over GF (q).
4. GCD (k, r) = 1.

## Output:
- The derived shared secret value, which is a field element z ∈ GF (q); or `Invalid Public Key` (q is the order of the base field)

## Operation:
1. compute an integer $t = k^{-1}s \pmod r$ where $k$ is the cofactor of the curve, and $r$ is the order of the subgroup.
2. Compute an elliptic curve point $P = kt W^{\prime}$.
3. **ABORT** If P = O and output `Invalid Public Key`.
4. Let $z = x_{P}$, the x-coordinate of P.
5. **OUTPUT** z as the shared secret value.



## References
- [B47] Diffie, W., and Hellman, M. “New Directions in Cryptography,” IEEE Transactions on Information Theory 22 (1976), pp. 644-654.
- [B88] Kaliski, B. S., Jr., “Compatible Cofactor Multiplication for Diffie-Hellman Primitives,” Electronics Letters, Vol. 34, no. 25 (December 10, 1998), pp. 2396-2397.
- [B94] Koblitz, N. “Elliptic Curve Cryptosystems,” Mathematics of Computation 48 (1987), pp. 203-209.
- [B98] Law, L., Menezes, A., Qu, M., Solinas, J., and Vanstone, S. “An Efficient Protocol for Authenticated Key Agreement,” Technical Report CORR 98-05, Dept. of C & O, University of Waterloo, Canada, March 1998 (revised August 28, 1998). Available at http://www.cacr.math.uwaterloo.ca/.
- [B117] Miller, V. S. “Use of Elliptic Curves in Cryptography,” H. C. Williams, Ed., Advances in Cryptology, CRYPTO ’85, Lecture Notes in Computer Science 218 (1986), Springer-Verlag, pp. 417-426.
