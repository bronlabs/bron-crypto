package znstar

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

// SamplePaillierGroup samples a Paillier unit group (Z/N²Z)* with N = pq
// of the given bit length. The underlying primes are drawn via the standard
// RSA generator (no additional structural constraint), so the resulting
// group supports Paillier encryption and homomorphic addition but does not
// on its own satisfy the Blum / safe-prime structure some ZK proofs require.
func SamplePaillierGroup(keyLen uint, prng io.Reader) (*PaillierGroupKnownOrder, error) {
	if prng == nil {
		return nil, ErrIsNil.WithMessage("prng")
	}
	p, q, err := nt.GeneratePrimePair(num.NPlus(), keyLen, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to generate prime pair")
	}
	return NewPaillierGroup(p, q)
}

// SampleSafePaillierGroup samples a Paillier group whose primes are safe:
// p = 2p' + 1, q = 2q' + 1. In (Z/N²Z)* this makes the subgroup of N-th
// residues cyclic of prime order p'q', which eliminates small-subgroup
// attacks and is required by CGGMP21's Π^{enc} and Π^{log*} proofs that
// reason about random elements drawn from the N-th residue subgroup.
func SampleSafePaillierGroup(keyLen uint, prng io.Reader) (*PaillierGroupKnownOrder, error) {
	if prng == nil {
		return nil, ErrIsNil.WithMessage("prng")
	}
	p, q, err := nt.GenerateSafePrimePair(num.NPlus(), keyLen, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to generate safe prime pair")
	}
	return NewPaillierGroup(p, q)
}

// SamplePaillierBlumGroup samples a Paillier group over a Paillier-Blum
// modulus: N = pq with p, q ≡ 3 (mod 4) and gcd(N, φ(N)) = 1. This is the
// exact shape CGGMP21 uses for its Paillier instances: the Blum condition
// gives canonical square roots, while gcd(N, φ(N)) = 1 is what makes the
// map x ↦ x^N bijective on (Z/N²Z)* and is the soundness hinge for
// Π^{mod} / Π^{fac} proofs.
// Note that we effectively skip gcd(N, φ(N)) = 1 check, because it will be reduntant
// if p and q have the same bit length.
func SamplePaillierBlumGroup(keyLen uint, prng io.Reader) (*PaillierGroupKnownOrder, error) {
	if prng == nil {
		return nil, ErrIsNil.WithMessage("prng")
	}
	p, q, err := nt.GenerateBlumPrimePair(num.NPlus(), keyLen, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to generate blum prime pair")
	}
	return NewPaillierGroup(p, q)
}

// NewPaillierGroup builds the known-order Paillier group (Z/N²Z)* from
// primes p, q supplied by the caller. Both are Miller-Rabin-checked and
// required to have equal bit length; the caller is responsible for any
// additional constraints (Blum, safe-prime) their protocol demands. The
// retained factorisation lets the arithmetic layer execute CRT-based
// modular exponentiation mod p² and mod q² — the standard optimisation
// for Paillier decryption — and enables exact lifting of N-th residues.
func NewPaillierGroup(p, q *num.NatPlus) (*PaillierGroupKnownOrder, error) {
	if p == nil || q == nil {
		return nil, ErrValue.WithMessage("p and q must not be nil")
	}
	if p.TrueLen() != q.TrueLen() {
		return nil, ErrValue.WithMessage("p and q must have the same length")
	}
	if !p.IsProbablyPrime() {
		return nil, ErrValue.WithMessage("p must be prime")
	}
	if !q.IsProbablyPrime() {
		return nil, ErrValue.WithMessage("q must be prime")
	}
	n := p.Mul(q)
	zMod, err := num.NewZMod(n.Square())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create ZMod")
	}
	exp, ok := modular.NewOddPrimeSquareFactors(p.Value(), q.Value())
	if ok == ct.False {
		return nil, ErrFailed.WithMessage("failed to create OddPrimeFactors")
	}
	return &PaillierGroupKnownOrder{
		UnitGroupTrait: UnitGroupTrait[*modular.OddPrimeSquareFactors, *PaillierGroupElement[*modular.OddPrimeSquareFactors], PaillierGroupElement[*modular.OddPrimeSquareFactors]]{
			zMod:  zMod,
			arith: exp,
			n:     n,
		},
	}, nil
}

// NewPaillierGroupOfUnknownOrder constructs (Z/n²Z)* from the modulus alone.
// n² and n must satisfy n² = n·n, so the caller cannot smuggle a modulus
// unrelated to a plausible Paillier key; the check does not, however, verify
// that n is the product of two primes (which is the verifier's job via a
// Π^{mod} proof or equivalent). This is the view every party holds about a
// counterparty's Paillier public key.
func NewPaillierGroupOfUnknownOrder(n2, n *num.NatPlus) (*PaillierGroupUnknownOrder, error) {
	if !n.Mul(n).Equal(n2) {
		return nil, ErrValue.WithMessage("n isn't sqrt of n")
	}
	zMod, err := num.NewZMod(n2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create ZMod")
	}
	arith, ok := modular.NewSimple(zMod.Modulus().ModulusCT())
	if ok == ct.False {
		return nil, ErrFailed.WithMessage("failed to create SimpleModulus")
	}

	return &PaillierGroupUnknownOrder{
		UnitGroupTrait: UnitGroupTrait[*modular.SimpleModulus, *PaillierGroupElement[*modular.SimpleModulus], PaillierGroupElement[*modular.SimpleModulus]]{
			zMod:  zMod,
			arith: arith,
			n:     n,
		},
	}, nil
}

// ArithmeticPaillier is the type-set constraint selecting the arithmetic
// backing a Paillier group: *modular.SimpleModulus for the unknown-order
// view (Barrett reduction over N²) and *modular.OddPrimeSquareFactors for
// the known-order view (CRT mod p² and q², giving the standard Paillier
// decryption speedup).
type ArithmeticPaillier interface {
	*modular.SimpleModulus | *modular.OddPrimeSquareFactors
	modular.Arithmetic
}

type (
	// PaillierGroupKnownOrder is the trapdoor-aware view of (Z/N²Z)*: the
	// factorisation N = pq is retained so that the arithmetic can decrypt
	// and compute N-th residues exactly. Only a legitimate holder of
	// (p, q) — e.g. the owner of the Paillier key — should hold a value
	// of this type.
	PaillierGroupKnownOrder = PaillierGroup[*modular.OddPrimeSquareFactors]
	// PaillierGroupUnknownOrder is the trapdoor-free view of (Z/N²Z)*. This
	// is what a counterparty sees: homomorphic addition and re-randomisation
	// are available; decryption and exact N-th-residue lifting are not.
	PaillierGroupUnknownOrder = PaillierGroup[*modular.SimpleModulus]

	// PaillierGroupElementKnownOrder is an element of a PaillierGroupKnownOrder.
	// Arithmetic on it uses CRT decomposition mod p² and q².
	PaillierGroupElementKnownOrder = PaillierGroupElement[*modular.OddPrimeSquareFactors]
	// PaillierGroupElementUnknownOrder is an element of a
	// PaillierGroupUnknownOrder; arithmetic is performed directly modulo N².
	PaillierGroupElementUnknownOrder = PaillierGroupElement[*modular.SimpleModulus]
)

// PaillierGroup is the unit group (Z/N²Z)* underlying Paillier encryption.
// The generic parameter X toggles between known-order (trapdoor-aware,
// decryption-capable) and unknown-order (public-key-only) views of the
// same group, letting callers express at the type level which side of a
// protocol they are on.
type PaillierGroup[X ArithmeticPaillier] struct {
	UnitGroupTrait[X, *PaillierGroupElement[X], PaillierGroupElement[X]]
}

// Equal reports whether two Paillier groups share the same ambient modulus
// N² and the same trapdoor status. Two groups with identical N² but
// different knowledge-of-order are treated as distinct, mirroring the
// prover/verifier asymmetry captured at the type level.
func (g *PaillierGroup[X]) Equal(other *PaillierGroup[X]) bool {
	return g.zMod.Modulus().Equal(other.zMod.Modulus()) && g.Order().IsUnknown() == other.Order().IsUnknown()
}

// N returns the Paillier modulus N (i.e. the square root of the group's
// ambient modulus N²). It is the primary cryptographic parameter:
// plaintexts live in Z/NZ, ciphertexts in (Z/N²Z)*, and the N-th residue
// subgroup is the "noise" subgroup that hides plaintexts.
func (g *PaillierGroup[X]) N() *num.NatPlus {
	return g.n
}

// EmbedRSA lifts an element of (Z/NZ)* into (Z/N²Z)* via the inclusion of
// representatives. The underlying integer is unchanged; only its modulus
// is reinterpreted. This is the mapping used when a protocol samples a
// randomiser in the RSA group and needs to treat it as a Paillier unit
// (e.g. the r factor in Paillier encryption Enc(m; r) = (1+N)^m · r^N mod N²).
// The call fails if u is not drawn from the RSA group with modulus equal
// to this Paillier group's N.
func (g *PaillierGroup[X]) EmbedRSA(u *RSAGroupElementUnknownOrder) (*PaillierGroupElement[X], error) {
	if u == nil {
		return nil, ErrIsNil.WithMessage("u")
	}
	if !g.n.Equal(u.Modulus()) {
		return nil, ErrValue.WithMessage("unit is not in the correct RSA group")
	}
	v, err := num.NewUintGivenModulus(u.Value().Value(), g.ModulusCT())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to embed RSA unit into Paillier unit")
	}
	return &PaillierGroupElement[X]{
		UnitTrait: UnitTrait[X, *PaillierGroupElement[X], PaillierGroupElement[X]]{
			v:     v,
			arith: g.arith,
			n:     g.n,
		},
	}, nil
}

// NthResidue maps u ∈ (Z/N²Z)* to u^N mod N² — the canonical N-th residue
// associated with u. Every Paillier ciphertext decomposes as a plaintext-
// carrying factor (1+N)^m times an N-th residue r^N that carries no
// information about m; this method computes that residue factor. The
// known-order specialisation of the arithmetic implements ExpToN with a
// CRT-optimised fast path; otherwise we fall back to a generic ModExp by N.
func (g *PaillierGroup[X]) NthResidue(u *PaillierGroupElementUnknownOrder) (*PaillierGroupElement[X], error) {
	if u == nil {
		return nil, ErrIsNil.WithMessage("argument must not be nil")
	}
	if !u.Modulus().Equal(g.Modulus()) {
		return nil, ErrValue.WithMessage("argument must be in the paillier group with modulus equal to the Paillier modulus")
	}
	pu, err := g.FromNatCT(u.Value().Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to lift rsaUnit to Paillier group")
	}
	lift, ok := any(g.arith).(interface {
		ExpToN(out, base *numct.Nat)
	})
	if !ok {
		return pu.Exp(g.n.Nat()), nil
	}
	var out numct.Nat
	lift.ExpToN(&out, pu.Value().Value())
	v, err := num.NewUintGivenModulus(&out, g.ModulusCT())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create unit from lifted value")
	}
	return &PaillierGroupElement[X]{
		UnitTrait: UnitTrait[X, *PaillierGroupElement[X], PaillierGroupElement[X]]{
			v:     v,
			arith: g.arith,
			n:     g.n,
		},
	}, nil
}

// Representative maps a plaintext m ∈ (-N/2, N/2) to its canonical Paillier
// encoding (1 + mN) mod N² — the deterministic, noise-free "core" of a
// Paillier ciphertext. A full encryption is then Representative(m) · r^N
// for a uniformly random r ∈ (Z/NZ)*. The plaintext is taken in the
// symmetric representation so that small negative values encode naturally;
// the call fails with ErrValue if |m| ≥ N/2.
func (g *PaillierGroup[X]) Representative(plaintext *numct.Int) (*PaillierGroupElement[X], error) {
	if g.N().ModulusCT().IsInRangeSymmetric(plaintext) == ct.False {
		return nil, ErrValue.WithMessage("plaintext is out of range: |plaintext| >= n/2")
	}
	var shiftedPlaintext numct.Nat
	g.N().ModulusCT().ModI(&shiftedPlaintext, plaintext)
	var out numct.Nat
	g.ModulusCT().ModMul(&out, &shiftedPlaintext, g.N().Value())
	out.Increment()
	return g.FromNatCT(&out)
}

// ForgetOrder projects a known-order Paillier group to its unknown-order
// view by dropping the (p, q) factorisation and replacing the CRT
// arithmetic with reduction modulo N². This is the operation performed
// whenever a Paillier public key is exported: after ForgetOrder the
// resulting group supports only operations available to an outside party
// — homomorphic addition, re-randomisation, encryption — but not decryption.
func (g *PaillierGroup[X]) ForgetOrder() *PaillierGroupUnknownOrder {
	arith, ok := modular.NewSimple(g.zMod.Modulus().ModulusCT())
	if ok == ct.False {
		panic(ErrFailed.WithMessage("failed to create SimpleModulus"))
	}
	return &PaillierGroupUnknownOrder{
		UnitGroupTrait: UnitGroupTrait[*modular.SimpleModulus, *PaillierGroupElement[*modular.SimpleModulus], PaillierGroupElement[*modular.SimpleModulus]]{
			zMod:  g.zMod,
			arith: arith,
			n:     g.n,
		},
	}
}

// PaillierGroupElement is an element of a Paillier unit group (Z/N²Z)*.
// In Paillier, ciphertexts and their homomorphic products live here. The
// type parameter X encodes at compile time whether the element is held
// under the trapdoor view (the key owner) or under the public-key view
// (everyone else), preventing accidental cross-context mixing.
type PaillierGroupElement[X ArithmeticPaillier] struct {
	UnitTrait[X, *PaillierGroupElement[X], PaillierGroupElement[X]]
}

// N returns the Paillier modulus N (the square root of the ambient
// modulus N² this element is reduced modulo). It is the cryptographic
// parameter plaintexts are reduced modulo and the exponent in the
// N-th-residue decomposition of the element.
func (u *PaillierGroupElement[X]) N() *num.NatPlus {
	return u.n
}

// Clone returns an independent deep copy of the element. Subsequent
// arithmetic on either copy does not alias the other's state — important
// when buffering ciphertexts across protocol rounds or threads.
func (u *PaillierGroupElement[X]) Clone() *PaillierGroupElement[X] {
	return &PaillierGroupElement[X]{
		UnitTrait: UnitTrait[X, *PaillierGroupElement[X], PaillierGroupElement[X]]{
			v:     u.v.Clone(),
			arith: u.arith,
			n:     u.n,
		},
	}
}

// Structure returns the Paillier group structure of the element.
func (u *PaillierGroupElement[X]) Structure() algebra.Structure[*PaillierGroupElement[X]] {
	return u.Group()
}

// Group returns the Paillier group this element belongs to.
func (u *PaillierGroupElement[X]) Group() *PaillierGroup[X] {
	return &PaillierGroup[X]{
		UnitGroupTrait: UnitGroupTrait[X, *PaillierGroupElement[X], PaillierGroupElement[X]]{
			zMod:  u.v.Group(),
			arith: u.arith,
			n:     u.n,
		},
	}
}

// LearnOrder converts a Paillier group element of unknown order to one with known order.
func (u *PaillierGroupElement[X]) LearnOrder(g *PaillierGroupKnownOrder) (*PaillierGroupElementKnownOrder, error) {
	if g == nil {
		return nil, ErrIsNil.WithMessage("g")
	}
	if !u.n.Equal(g.n) {
		return nil, ErrValue.WithMessage("unit is not in the correct Paillier group")
	}
	return &PaillierGroupElementKnownOrder{
		UnitTrait: UnitTrait[*modular.OddPrimeSquareFactors, *PaillierGroupElementKnownOrder, PaillierGroupElementKnownOrder]{
			v:     u.v.Clone(),
			arith: g.arith,
			n:     g.n,
		},
	}, nil
}

// ForgetOrder converts a Paillier group element with known order to one with unknown order.
func (u *PaillierGroupElement[X]) ForgetOrder() *PaillierGroupElementUnknownOrder {
	arith, ok := modular.NewSimple(u.v.Group().Modulus().ModulusCT())
	if ok == ct.False {
		panic(ErrFailed.WithMessage("failed to create SimpleModulus"))
	}
	return &PaillierGroupElementUnknownOrder{
		UnitTrait: UnitTrait[*modular.SimpleModulus, *PaillierGroupElementUnknownOrder, PaillierGroupElementUnknownOrder]{
			v:     u.v.Clone(),
			arith: arith,
			n:     u.n,
		},
	}
}
