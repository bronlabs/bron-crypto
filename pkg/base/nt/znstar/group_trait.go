package znstar

import (
	"fmt"
	"io"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

type unitWrapper[A modular.Arithmetic] interface {
	set(*num.Uint, A, *num.NatPlus)
	Arithmetic() A
	Modulus() *num.NatPlus
	IsUnknownOrder() bool
	Jacobi() (int, error)
	base.Transparent[*num.Uint]
}

type unitWrapperPtrConstraint[A modular.Arithmetic, WT any] interface {
	*WT
	unitWrapper[A]
}

// UnitGroupTrait is the shared implementation of the unit group (Z/NZ)*
// for every concrete group in this package (RSA mod N, Paillier mod N², …).
// The type parameters capture:
//
//   - A: the arithmetic backend. SimpleModulus denotes the unknown-order
//     view (no trapdoor); OddPrimeFactors / OddPrimeSquareFactors denote
//     the known-order view where the factorisation of N is retained and
//     CRT-based arithmetic is available.
//   - W / WT: the wrapper element type and its underlying struct,
//     threaded through so that trait methods returning "an element"
//     produce a typed RSA or Paillier element rather than an abstract
//     UnitTrait.
//
// All state is captured in three fields: the ambient ring Z/NZ (zMod),
// the chosen arithmetic (arith), and the primary modulus N (n) — for
// Paillier this is the square root of zMod's modulus and therefore the
// correct modulus for operations like "raise to the N-th power".
type UnitGroupTrait[A modular.Arithmetic, W unitWrapperPtrConstraint[A, WT], WT any] struct {
	zMod  *num.ZMod
	arith A
	n     *num.NatPlus
}

// Name returns a canonical textual label for the group, of the form
// "U(Z/NZ)*" with N the ambient modulus. Intended for diagnostics and
// transcript labelling in Fiat-Shamir hashes where a stable group
// identifier matters for domain separation.
func (g *UnitGroupTrait[A, W, WT]) Name() string {
	return fmt.Sprintf("U(Z/%sZ)*", g.Modulus().String())
}

// Order returns the multiplicative order of the group. For the known-order
// view this is φ(N) (or φ(N²) for Paillier, which equals N·φ(N)); for the
// unknown-order view the returned Cardinal reports IsUnknown() == true so
// that algorithms requiring the order can fall back to bounded-exponent
// techniques instead of computing modulo it.
func (g *UnitGroupTrait[A, W, WT]) Order() cardinal.Cardinal {
	return g.arith.MultiplicativeOrder()
}

// IsUnknownOrder reports whether this group is being viewed as one of unknown
// order (i.e. with the SimpleModulus arithmetic) or known order (with
// OddPrimeFactors / OddPrimeSquareFactors).
func (g *UnitGroupTrait[A, W, WT]) IsUnknownOrder() bool {
	_, ok := any(g.arith).(*modular.SimpleModulus)
	return ok
}

// OpIdentity is the multiplicative identity (i.e. 1), exposed under the
// generic group-operation name expected by the algebra interfaces.
func (g *UnitGroupTrait[A, W, WT]) OpIdentity() W {
	return g.One()
}

// One returns the identity element 1 of the group, already typed as the
// concrete wrapper W so that generic algorithms receive a ready-to-use
// group element without further conversion.
func (g *UnitGroupTrait[A, W, WT]) One() W {
	var u WT
	W(&u).set(g.zMod.One(), g.arith, g.n)
	return W(&u)
}

// Random samples a uniformly random element of the unit group, rejecting
// any draw that is not coprime with N. Rejection sampling is used (rather
// than generating in a subgroup of known order) so that the distribution
// is exactly uniform on (Z/NZ)* regardless of whether the factorisation
// of N is available.
func (g *UnitGroupTrait[A, W, WT]) Random(prng io.Reader) (W, error) {
	for {
		r, err := g.zMod.Random(prng)
		if err != nil {
			return nil, errs.Wrap(err)
		}
		var u WT
		W(&u).set(r, g.arith, g.n)
		if W(&u).Value().Lift().Coprime(g.Modulus().Lift()) {
			return W(&u), nil
		}
	}
}

// RandomQuadraticResidue samples a uniformly random element of QR_N, the
// subgroup of quadratic residues. It does so by squaring a uniform unit:
// the map r ↦ r² from (Z/NZ)* to QR_N is surjective, and its fibres all
// have the same cardinality (four for N a Blum integer, two otherwise),
// so r² is uniform on QR_N whenever r is uniform on (Z/NZ)*.
func (g *UnitGroupTrait[A, W, WT]) RandomQuadraticResidue(prng io.Reader) (W, error) {
	r, err := g.Random(prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("couldn't sample r")
	}
	var r2 WT
	W(&r2).set(r.Value().Mul(r.Value()), g.arith, g.n)
	return W(&r2), nil
}

// RandomWithJacobi samples a uniformly random element of (Z/NZ)* whose
// Jacobi symbol matches j (which must be ±1). The sampling uses rejection
// so the distribution is exactly uniform on the requested Jacobi class.
// Elements with Jacobi +1 include QR_N as a subgroup (but also contain
// non-residues when N is composite — distinguishing them is the QR
// assumption); elements with Jacobi -1 are always quadratic non-residues.
func (g *UnitGroupTrait[A, W, WT]) RandomWithJacobi(j int, prng io.Reader) (W, error) {
	if j != 1 && j != -1 {
		return nil, ErrValue.WithMessage("Jacobi symbol must be either 1 or -1")
	}
	for {
		r, err := g.Random(prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("couldn't sample r")
		}
		jacobi, err := r.Jacobi()
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to compute Jacobi symbol")
		}
		if jacobi == j {
			return r, nil
		}
	}
}

// Hash deterministically maps an arbitrary byte string to a uniformly
// distributed unit of the group. It drives a BLAKE2b XOF of WideElementSize
// bytes (twice the modulus size minus the statistical-security margin),
// reduces the digest modulo N, and rejects any result that is not coprime
// with N. The rejection rate is negligible; the construction is used to
// derive group-dependent challenges and commitments from Fiat-Shamir
// transcripts without biasing the distribution.
func (g *UnitGroupTrait[A, W, WT]) Hash(input []byte) (W, error) {
	xof, err := blake2b.NewXOF(uint32(g.WideElementSize()), nil)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	if _, err := xof.Write(input); err != nil {
		return nil, errs.Wrap(err)
	}
	digest := make([]byte, g.WideElementSize())
	var x, v numct.Nat
	for {
		if _, err = io.ReadFull(xof, digest); err != nil {
			return nil, errs.Wrap(err)
		}
		if ok := x.SetBytes(digest); ok == ct.False {
			return nil, ErrFailed.WithMessage("failed to interpret hash digest as Nat")
		}
		// Perform modular reduction using the modulus from n
		g.zMod.ModulusCT().Mod(&v, &x)

		vNat, err := num.N().FromNatCT(&v)
		if err != nil {
			return nil, errs.Wrap(err)
		}

		if g.zMod.Modulus().Nat().Coprime(vNat) {
			uv, err := g.zMod.FromNat(vNat)
			if err != nil {
				return nil, errs.Wrap(err)
			}
			var zn WT
			W(&zn).set(uv, g.arith, g.n)
			return W(&zn), nil
		}
	}
}

// Modulus returns the ambient modulus of the group, i.e. the modulus of
// (Z/NZ)*. For RSA groups this is N; for Paillier groups it is N².
func (g *UnitGroupTrait[A, W, WT]) Modulus() *num.NatPlus {
	return g.zMod.Modulus()
}

// ModulusCT returns the constant-time modulus handle used by the modular
// arithmetic layer. Prefer this over Modulus().ModulusCT() on hot paths
// that already have a group handle; it skips a conversion.
func (g *UnitGroupTrait[A, W, WT]) ModulusCT() *numct.Modulus {
	return g.zMod.Modulus().ModulusCT()
}

// ElementSize is the byte length used when serialising a group element —
// exactly the modulus's byte length. Uniform random elements may use all
// of it.
func (g *UnitGroupTrait[A, W, WT]) ElementSize() int {
	return g.zMod.ElementSize()
}

// WideElementSize is the byte length used when sampling an element from
// a hash digest: it is large enough that reducing a uniform WideElementSize
// draw modulo N yields a distribution statistically indistinguishable from
// uniform over [0, N). Used by Hash and by any Fiat-Shamir-style derivation
// that must avoid modular-reduction bias.
func (g *UnitGroupTrait[A, W, WT]) WideElementSize() int {
	return g.zMod.WideElementSize()
}

// FromNatCT lifts a raw numct.Nat to a group element after verifying it is
// a unit (coprime with the modulus). Intended for internal use on hot paths
// where the input is already in the constant-time representation; it is
// the lowest-overhead path from a modular-arithmetic result back into a
// typed group element.
func (g *UnitGroupTrait[A, W, WT]) FromNatCT(input *numct.Nat) (W, error) {
	if input == nil {
		return nil, ErrIsNil.WithMessage("input must not be nil")
	}
	elem, err := g.zMod.FromNatCT(input)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create element from nat")
	}
	var out WT
	W(&out).set(elem, g.arith, g.n)
	if !W(&out).Value().Lift().Coprime(g.Modulus().Lift()) {
		return nil, ErrValue.WithMessage("input is not a unit")
	}
	return W(&out), nil
}

// FromUint lifts a *num.Uint to a group element. The input must already
// carry this group's modulus and must be coprime with N; both conditions
// are verified. Use this when ingesting a value that has been deserialised
// from the network or reconstructed from another computation and needs to
// be typed as a member of this group.
func (g *UnitGroupTrait[A, W, WT]) FromUint(input *num.Uint) (W, error) {
	if input == nil {
		return nil, ErrIsNil.WithMessage("input must not be nil")
	}
	if !g.Modulus().Equal(input.Modulus()) {
		return nil, ErrValue.WithMessage("input is not in the same modulus")
	}
	var out WT
	W(&out).set(input.Clone(), g.arith, g.n)
	if !W(&out).Value().Lift().Coprime(g.Modulus().Lift()) {
		return nil, ErrValue.WithMessage("input is not a unit")
	}
	return W(&out), nil
}

// FromBytes decodes a group element from its canonical big-endian byte
// encoding. The result is validated as a unit; any byte string that
// encodes a value not coprime with N is rejected with ErrValue, so this
// is safe to use as a deserialisation entry point for values arriving
// over the wire.
func (g *UnitGroupTrait[A, W, WT]) FromBytes(input []byte) (W, error) {
	if len(input) == 0 {
		return nil, ErrIsNil.WithMessage("input must not be empty")
	}
	v, err := g.zMod.FromBytes(input)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create unit from bytes")
	}
	var out WT
	W(&out).set(v, g.arith, g.n)
	if !W(&out).Value().Lift().Coprime(g.Modulus().Lift()) {
		return nil, ErrValue.WithMessage("input is not a unit")
	}
	return W(&out), nil
}

// FromCardinal constructs a group element from an arbitrary-precision
// cardinal. Useful when the input originates from cardinality computations
// (orders, sizes, challenge spaces) rather than modular arithmetic. The
// cardinal is reduced mod N and the coprimality check is enforced.
func (g *UnitGroupTrait[A, W, WT]) FromCardinal(input cardinal.Cardinal) (W, error) {
	elem, err := g.zMod.FromCardinal(input)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create element from cardinal")
	}
	var out WT
	W(&out).set(elem, g.arith, g.n)
	if !W(&out).Value().Lift().Coprime(g.Modulus().Lift()) {
		return nil, ErrValue.WithMessage("input is not a unit")
	}
	return W(&out), nil
}

// FromUint64 is a convenience constructor for small constants (most
// commonly 1, 2, -1 ≡ N-1). It verifies that the requested value is a unit
// and errors out otherwise — in particular, FromUint64(0) always fails.
func (g *UnitGroupTrait[A, W, WT]) FromUint64(input uint64) (W, error) {
	elem, err := g.zMod.FromCardinal(cardinal.New(input))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create element from uint64")
	}
	var out WT
	W(&out).set(elem, g.arith, g.n)
	if !W(&out).Value().Lift().Coprime(g.Modulus().Lift()) {
		return nil, ErrValue.WithMessage("input is not a unit")
	}

	return W(&out), nil
}

// AmbientGroup returns the full ring Z/NZ (not just its unit subgroup).
// Needed by primitives such as Paillier encryption whose output lives in
// (Z/N²Z)* but whose plaintext representative is taken via ring addition
// in Z/N²Z before the unit check is applied.
func (g *UnitGroupTrait[A, W, WT]) AmbientGroup() *num.ZMod {
	return g.zMod
}

// AmbientStructure is the same handle as AmbientGroup, typed to the
// algebra.Structure interface so that generic algorithms can operate on
// the ring without knowing its concrete realisation.
func (g *UnitGroupTrait[A, W, WT]) AmbientStructure() algebra.Structure[*num.Uint] {
	return g.zMod
}

// ScalarStructure returns the ring Z, which acts on the unit group via
// exponentiation: u ↦ u^k for k ∈ Z. Exposed as a Structure so that
// generic Z-module algorithms (multi-scalar multiplication, linear
// combinations in Schnorr-style proofs) can find the scalar ring.
func (*UnitGroupTrait[A, W, WT]) ScalarStructure() algebra.Structure[*num.Int] {
	return num.Z()
}

// Arithmetic returns the modular-arithmetic backend. The concrete
// type (SimpleModulus vs OddPrimeFactors vs OddPrimeSquareFactors)
// determines whether the trapdoor view is active and whether CRT
// acceleration is available.
func (g *UnitGroupTrait[A, W, WT]) Arithmetic() A {
	return g.arith
}
