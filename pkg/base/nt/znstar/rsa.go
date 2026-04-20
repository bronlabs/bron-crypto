package znstar

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
)

// SampleRSAGroup samples an RSA unit group (Z/NZ)* with N = pq of the given
// bit length, where p and q are sampled via crypto/rsa.GenerateKey. The
// resulting group has known order (the factorisation is retained for CRT
// acceleration). No structural constraint beyond primality and equal bit
// length is imposed on p, q; callers that need safe primes, Blum primes,
// or Paillier-Blum moduli should use SampleSafeRSAGroup,
// SampleBlumRSAGroup, or SamplePaillierBlumGroup respectively.
func SampleRSAGroup(keyLen uint, prng io.Reader) (*RSAGroupKnownOrder, error) {
	if prng == nil {
		return nil, ErrIsNil.WithMessage("prng")
	}
	p, q, err := nt.GeneratePrimePair(num.NPlus(), keyLen, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to generate prime pair")
	}
	return NewRSAGroup(p, q)
}

// SampleSafeRSAGroup samples an RSA group (Z/NZ)* with N = pq the product
// of two safe primes p = 2p' + 1, q = 2q' + 1. In this group the subgroup
// QR_N of quadratic residues is cyclic of prime order p'q', which (a) rules
// out small-subgroup attacks, (b) makes a uniformly random QR a generator
// except with negligible probability, and (c) makes the discrete logarithm
// problem in QR_N plausibly hard. This is the group underlying the
// CGGMP21 ring-Pedersen CRS.
func SampleSafeRSAGroup(keyLen uint, prng io.Reader) (*RSAGroupKnownOrder, error) {
	if prng == nil {
		return nil, ErrIsNil.WithMessage("prng")
	}
	p, q, err := nt.GenerateSafePrimePair(num.NPlus(), keyLen, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to generate safe prime pair")
	}
	return NewRSAGroup(p, q)
}

// SampleBlumRSAGroup samples an RSA group (Z/NZ)* with N = pq a Blum
// integer (p ≡ q ≡ 3 mod 4). In this group -1 is a quadratic non-residue
// with Jacobi symbol +1, so the four square roots of any QR split into
// two "sign"-paired cosets of QR_N — which is exactly the structure
// exploited by Paillier-Blum proofs and Rabin-style commitments.
func SampleBlumRSAGroup(keyLen uint, prng io.Reader) (*RSAGroupKnownOrder, error) {
	if prng == nil {
		return nil, ErrIsNil.WithMessage("prng")
	}
	p, q, err := nt.GenerateBlumPrimePair(num.NPlus(), keyLen, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to generate blum prime pair")
	}
	return NewRSAGroup(p, q)
}

// NewRSAGroup builds the known-order RSA group (Z/NZ)* from primes p, q
// supplied by the caller. Both primes are checked for primality (Miller-
// Rabin) and equal bit length; no safe-prime / Blum condition is enforced
// here, so the caller is responsible for feeding primes with the structure
// required downstream. The resulting group carries the factorisation via
// modular.OddPrimeFactors, which enables CRT-accelerated ModExp and the
// QR decision procedure via per-prime Legendre symbols.
func NewRSAGroup(p, q *num.NatPlus) (*RSAGroupKnownOrder, error) {
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
	zMod, err := num.NewZMod(n)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create ZMod")
	}
	arith, ok := modular.NewOddPrimeFactors(p.Value(), q.Value())
	if ok == ct.False {
		return nil, ErrFailed.WithMessage("failed to create OddPrimeFactors")
	}
	return &RSAGroupKnownOrder{
		UnitGroupTrait: UnitGroupTrait[*modular.OddPrimeFactors, *RSAGroupElement[*modular.OddPrimeFactors], RSAGroupElement[*modular.OddPrimeFactors]]{
			zMod:  zMod,
			arith: arith,
			n:     n,
		},
	}, nil
}

// NewRSAGroupOfUnknownOrder constructs an RSA group (Z/mZ)* from the
// modulus alone — no factorisation. This is the view held by a verifier
// or by any party that must operate on an RSA group without being entrusted
// with the trapdoor (p, q). All modular operations fall back to simple
// Barrett / Montgomery reduction over m; CRT acceleration and the exact
// QR test via Legendre symbols are unavailable in this view.
func NewRSAGroupOfUnknownOrder(m *num.NatPlus) (*RSAGroupUnknownOrder, error) {
	zMod, err := num.NewZMod(m)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create ZMod")
	}
	arith, ok := modular.NewSimple(zMod.Modulus().ModulusCT())
	if ok == ct.False {
		return nil, ErrFailed.WithMessage("failed to create SimpleModulus")
	}
	return &RSAGroupUnknownOrder{
		UnitGroupTrait: UnitGroupTrait[*modular.SimpleModulus, *RSAGroupElement[*modular.SimpleModulus], RSAGroupElement[*modular.SimpleModulus]]{
			zMod:  zMod,
			arith: arith,
			n:     m,
		},
	}, nil
}

// ArithmeticRSA is the type-set constraint distinguishing the two flavours
// of modular arithmetic that can back an RSA group: *modular.SimpleModulus
// (no factorisation, Barrett-style reduction only) for the unknown-order
// view, and *modular.OddPrimeFactors (p, q retained for CRT acceleration
// and exact residuosity decisions) for the known-order view. The generic
// RSAGroup[X] is specialised along this axis via type aliases.
type ArithmeticRSA interface {
	*modular.SimpleModulus | *modular.OddPrimeFactors
	modular.Arithmetic
}

type (
	// RSAGroupKnownOrder is the trapdoor-aware view of (Z/NZ)*: the
	// factorisation N = pq is retained and the arithmetic performs CRT-based
	// reduction mod p and mod q in parallel. Only a party that legitimately
	// holds the factorisation (a prover, or a trusted setup authority)
	// should be handling values of this type.
	RSAGroupKnownOrder = RSAGroup[*modular.OddPrimeFactors]
	// RSAGroupUnknownOrder is the trapdoor-free view of (Z/NZ)*: arithmetic
	// proceeds via Barrett-style reduction over N, and no primitive on this
	// type can reveal (p, q). This is the view a verifier — or an
	// adversarial observer — holds.
	RSAGroupUnknownOrder = RSAGroup[*modular.SimpleModulus]

	// RSAGroupElementKnownOrder is an element of an RSAGroupKnownOrder and
	// benefits from CRT-accelerated modular exponentiation and exact QR
	// decisions via per-prime Legendre symbols.
	RSAGroupElementKnownOrder = RSAGroupElement[*modular.OddPrimeFactors]
	// RSAGroupElementUnknownOrder is an element of an RSAGroupUnknownOrder.
	// All arithmetic is performed with respect to the composite modulus;
	// QR membership cannot be decided without an accompanying ZK proof.
	RSAGroupElementUnknownOrder = RSAGroupElement[*modular.SimpleModulus]
)

// RSAGroup is the unit group (Z/NZ)* of an RSA modulus. The generic
// parameter X picks between the known-order and unknown-order views;
// functions that only make sense in the known-order view (e.g. exact
// quadratic-residuosity decisions) error out when called on the
// unknown-order specialisation at run time.
type RSAGroup[X ArithmeticRSA] struct {
	UnitGroupTrait[X, *RSAGroupElement[X], RSAGroupElement[X]]
}

// IsQuadraticResidue decides QR_N membership for elem. In the known-order
// view the decision is exact: the Legendre symbol is computed modulo each
// prime factor p, q of N, and elem is a QR iff it is a QR modulo both.
// In the unknown-order view QR-ness is conjectured-hard (the Quadratic
// Residuosity assumption), so this method refuses to answer and returns
// ErrValue; callers that need a witnessed decision in that setting must
// accompany elem with a ZK proof (e.g. CGGMP21's Π^{mod}).
func (g *RSAGroup[X]) IsQuadraticResidue(elem *RSAGroupElement[X]) (bool, error) {
	if elem == nil {
		return false, ErrIsNil.WithMessage("elem")
	}
	if !elem.v.Group().Modulus().Equal(g.zMod.Modulus()) {
		return false, ErrValue.WithMessage("element is not in the correct RSA group")
	}
	if elem.IsUnknownOrder() {
		return false, ErrValue.WithMessage("it is intractable to determine quadratic residuosity for elements of unknown order")
	}
	return elem.IsTorsionFree(), nil
}

// Equal reports whether two RSA groups describe the same ambient group
// (Z/NZ)* and carry the same knowledge-of-order status. Two groups with
// equal modulus but different trapdoor status are treated as distinct,
// reflecting the type-level distinction between prover and verifier views.
func (g *RSAGroup[X]) Equal(other *RSAGroup[X]) bool {
	return g.zMod.Modulus().Equal(other.zMod.Modulus()) && g.Order().IsUnknown() == other.Order().IsUnknown()
}

// ForgetOrder projects a known-order RSA group to its unknown-order view
// by dropping the (p, q) factorisation and switching the arithmetic to
// Barrett-style reduction over N. This is the operation a prover performs
// when transporting group parameters to a verifier: the modulus and its
// elements remain cryptographically valid, but no trapdoor information
// flows with them.
func (g *RSAGroup[X]) ForgetOrder() *RSAGroupUnknownOrder {
	arith, ok := modular.NewSimple(g.zMod.Modulus().ModulusCT())
	if ok == ct.False {
		panic(ErrFailed.WithMessage("failed to create SimpleModulus"))
	}
	return &RSAGroupUnknownOrder{
		UnitGroupTrait: UnitGroupTrait[*modular.SimpleModulus, *RSAGroupElement[*modular.SimpleModulus], RSAGroupElement[*modular.SimpleModulus]]{
			zMod:  g.zMod,
			arith: arith,
			n:     g.n,
		},
	}
}

// RSAGroupElement is an element of an RSA unit group. The generic parameter
// X ties it to the known/unknown-order flavour of its parent group and, at
// the type level, prevents multiplying elements drawn from different groups
// or accidentally mixing a prover-held (known-order) element with one that
// the verifier has received without the trapdoor.
type RSAGroupElement[X ArithmeticRSA] struct {
	UnitTrait[X, *RSAGroupElement[X], RSAGroupElement[X]]
}

// Clone returns a deep copy of the element sharing nothing with the
// original's internal representation. Because the underlying *num.Uint is
// cloned, subsequent in-place arithmetic on either copy does not affect
// the other — important for code that buffers group elements across ZK
// rounds.
func (u *RSAGroupElement[X]) Clone() *RSAGroupElement[X] {
	return &RSAGroupElement[X]{
		UnitTrait: UnitTrait[X, *RSAGroupElement[X], RSAGroupElement[X]]{
			v:     u.v.Clone(),
			arith: u.arith,
			n:     u.n,
		},
	}
}

// Structure reifies the ambient group the element belongs to as an
// algebra.Structure. Useful for generic algorithms that operate on a
// Structure handle (sampling, serialisation, equality) without having to
// know whether the specific instantiation is RSA or Paillier.
func (u *RSAGroupElement[X]) Structure() algebra.Structure[*RSAGroupElement[X]] {
	return &RSAGroup[X]{
		UnitGroupTrait: UnitGroupTrait[X, *RSAGroupElement[X], RSAGroupElement[X]]{
			zMod:  u.v.Group(),
			arith: u.arith,
			n:     u.n,
		},
	}
}

// LearnOrder re-types an unknown-order element as an element of the
// known-order group g, provided the two share the same modulus. No
// cryptographic information is created or destroyed — the underlying
// integer is unchanged — this merely promotes the element into a context
// where CRT-accelerated arithmetic and exact QR decisions are available.
// Callers must already hold g (i.e. the factorisation trapdoor) for this
// to have meaning.
func (u *RSAGroupElement[X]) LearnOrder(g *RSAGroupKnownOrder) (*RSAGroupElementKnownOrder, error) {
	if g == nil {
		return nil, ErrIsNil.WithMessage("g")
	}
	if !u.v.Group().Modulus().Equal(g.zMod.Modulus()) {
		return nil, ErrValue.WithMessage("unit is not in the correct RSA group")
	}
	return &RSAGroupElementKnownOrder{
		UnitTrait: UnitTrait[*modular.OddPrimeFactors, *RSAGroupElementKnownOrder, RSAGroupElementKnownOrder]{
			v:     u.v.Clone(),
			arith: g.arith,
			n:     g.n,
		},
	}, nil
}

// ForgetOrder projects a known-order element to the unknown-order view,
// dropping all trapdoor-dependent arithmetic shortcuts. This is the
// canonical operation applied to any element a prover ships to a
// verifier: the verifier must see the element as a member of the
// unknown-order group so that no information about (p, q) leaks through
// typing.
func (u *RSAGroupElement[X]) ForgetOrder() *RSAGroupElementUnknownOrder {
	arith, ok := modular.NewSimple(u.v.Group().Modulus().ModulusCT())
	if ok == ct.False {
		panic(ErrFailed.WithMessage("failed to create SimpleModulus"))
	}
	return &RSAGroupElementUnknownOrder{
		UnitTrait: UnitTrait[*modular.SimpleModulus, *RSAGroupElementUnknownOrder, RSAGroupElementUnknownOrder]{
			v:     u.v.Clone(),
			arith: arith,
			n:     u.n,
		},
	}
}
