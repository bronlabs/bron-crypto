package pedersen

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
)

// Trapdoor extends a Pedersen Key with the secret λ such that h = g^λ.
// The trapdoor enables equivocation (opening one commitment to multiple
// messages) when wrapped in an EquivocableScheme, and must be kept secret
// outside of simulation contexts. lambda is carried as a *num.Uint so it
// embeds its own modulus q = ord(g), which is required for inversion mod q
// during equivocation.
type Trapdoor[E FiniteAbelianGroupElement[E, S], S algebra.RingElement[S]] struct {
	Key[E, S]

	lambda *num.Uint
}

type trapdoorDTO[E FiniteAbelianGroupElement[E, S], S algebra.RingElement[S]] struct {
	G      E         `cbor:"g"`
	Lambda *num.Uint `cbor:"lambda"`
}

// NewRingPedersenTrapdoorKey constructs a ring-Pedersen trapdoor from a
// caller-supplied generator g of QR(N̂) (carrying knowledge of p, q) and a
// trapdoor scalar λ ∈ Z_{φ(N̂)/4}. It enforces that lambda's modulus equals
// φ(N̂)/4 = p'·q' and that g is a generator of QR(N̂); the returned trapdoor
// forgets the order so the embedded Key behaves like a public CRS.
func NewRingPedersenTrapdoorKey(g *znstar.RSAGroupElementKnownOrder, lambda *num.Uint) (*Trapdoor[*znstar.RSAGroupElementUnknownOrder, *num.Int], error) { // The return type must be UnknownOrder for the CommitmentKey method to be secure.
	if g == nil {
		return nil, ErrInvalidArgument.WithMessage("generator cannot be nil")
	}
	if lambda == nil {
		return nil, ErrInvalidArgument.WithMessage("lambda cannot be nil")
	}
	p, err := num.NPlus().FromNatCT(g.Arithmetic().Params.PNat)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create p from arithmetic parameters")
	}
	q, err := num.NPlus().FromNatCT(g.Arithmetic().Params.QNat)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create q from arithmetic parameters")
	}
	phiNHatOver4 := p.Rsh(1).Mul(q.Rsh(1))
	if !lambda.Modulus().Equal(phiNHatOver4) {
		return nil, ErrInvalidArgument.WithMessage("lambda modulus must equal φ(NHat)/4")
	}
	if !g.Value().Decrement().Nat().Coprime(g.Modulus().Nat()) {
		return nil, ErrInvalidArgument.WithMessage("g is not a generator of QR(NHat)")
	}

	out, err := newTrapdoorKeyUnchecked(g.ForgetOrder(), lambda)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Pedersen trapdoor key")
	}
	return out, nil
}

// SampleRingPedersenTrapdoorKey generates a fresh ring-Pedersen trapdoor by
// sampling a safe-prime RSA modulus N̂ = pq of the requested bit length,
// drawing a generator t of QR(N̂) and a random λ, and returning (Key, λ).
// keyLen is the bit length of N̂; prng must be cryptographically secure.
func SampleRingPedersenTrapdoorKey(keyLen uint, prng io.Reader) (*Trapdoor[*znstar.RSAGroupElementUnknownOrder, *num.Int], error) { // The return type must be UnknownOrder for the CommitmentKey method to be secure.
	_, _, t, lambda, err := znstar.SamplePedersenParameters(keyLen, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to sample Pedersen parameters")
	}
	out, err := newTrapdoorKeyUnchecked(t, lambda)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Pedersen trapdoor key")
	}
	return out, nil
}

// NewPrimeGroupTrapdoorKey constructs a prime-group trapdoor from a generator g
// and a scalar λ. The lambda's modulus must match the group's scalar order so
// that h = g^λ has the expected discrete log relationship.
func NewPrimeGroupTrapdoorKey[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](g E, lambda S) (*Trapdoor[E, S], error) {
	if utils.IsNil(g) || utils.IsNil(lambda) {
		return nil, ErrInvalidArgument.WithMessage("generator and lambda cannot be nil")
	}
	group := algebra.StructureMustBeAs[algebra.PrimeGroup[E, S]](g.Structure())
	sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
	zModQ, err := num.NewZModFromCardinal(sf.Order())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create Z Mod ScalarFieldOrder")
	}
	lambdaUint, err := zModQ.FromBytesBE(lambda.BytesBE())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to convert lambda into ZModQ")
	}
	out, err := newTrapdoorKeyUnchecked(g, lambdaUint)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Pedersen trapdoor key")
	}
	return out, nil
}

// SamplePrimeGroupTrapdoorKey generates a fresh prime-group trapdoor by
// drawing a uniformly random non-zero λ from the scalar field and using
// basePoint as g. h is computed as g^λ inside the underlying constructor.
func SamplePrimeGroupTrapdoorKey[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](basePoint E, prng io.Reader) (*Trapdoor[E, S], error) {
	if utils.IsNil(basePoint) {
		return nil, ErrInvalidArgument.WithMessage("base point cannot be nil")
	}
	if prng == nil {
		return nil, ErrInvalidArgument.WithMessage("prng cannot be nil")
	}
	group := algebra.StructureMustBeAs[algebra.PrimeGroup[E, S]](basePoint.Structure())
	sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
	zModSFOrder, err := num.NewZModFromCardinal(sf.Order())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create Z Mod ScalarFieldOrder")
	}
	lambda, err := algebrautils.RandomNonIdentity(zModSFOrder, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to sample lambda")
	}
	out, err := newTrapdoorKeyUnchecked(basePoint, lambda)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Pedersen trapdoor key")
	}
	return out, nil
}

// newTrapdoorKeyUnchecked builds a Trapdoor without enforcing the group-specific
// preconditions on (g, λ). It rejects nil, identity-or-torsion generators,
// λ ≡ 1 (which would make h = g and violate Key's distinct-generators
// invariant), and λ that is not a unit modulo its own modulus. The unit check
// is load-bearing for the ring-Pedersen flavour where ord(g) = p'·q' is
// composite: a non-unit λ has no inverse (so Equivocate cannot recover r')
// and yields h = g^λ of order ord(g)/gcd(λ, ord(g)), i.e. h does not generate
// ⟨g⟩ — voiding the binding/hiding arguments. For prime-modulus flavours
// every non-zero λ is automatically a unit, so the check is trivial there.
// Callers above this layer remain responsible for the flavour-specific
// invariants on lambda's modulus and generator validity.
func newTrapdoorKeyUnchecked[E FiniteAbelianGroupElement[E, S], S algebra.RingElement[S]](g E, lambda *num.Uint) (*Trapdoor[E, S], error) {
	if utils.IsNil(g) || utils.IsNil(lambda) {
		return nil, ErrInvalidArgument.WithMessage("generator and trapdoor value cannot be nil")
	}
	if g.IsOpIdentity() || !g.IsTorsionFree() {
		return nil, ErrInvalidArgument.WithMessage("generator cannot be the identity element or have torsion")
	}
	if !lambda.IsUnit() {
		return nil, ErrInvalidArgument.WithMessage("trapdoor value must be a unit modulo its modulus")
	}
	if lambda.IsOne() {
		return nil, ErrInvalidArgument.WithMessage("trapdoor value cannot be one")
	}
	t := &Trapdoor[E, S]{
		Key: Key[E, S]{
			g: g,
			h: algebrautils.ScalarMul(g, lambda),
		},
		lambda: lambda,
	}
	return t, nil
}

// canonicalEquivocation computes the algebraic core of equivocation: given
// (message, witness) opening a commitment C and a target newMessage, it
// returns r₀ ∈ [0, q) such that
//
//	m + λr ≡ m' + λr₀  (mod q),  where q = ord(g) = lambda.Modulus().
//
// This is the unique residue mod q that re-opens C to newMessage; the
// scheme's equivocationLift then turns r₀ into a witness drawn from the
// honest distribution. Splitting along this seam keeps the trapdoor purely
// algebraic and lets the scheme own all flavour-specific re-randomisation
// (which is mandatory for the ring flavour — without it, equivocated
// witnesses are trivially distinguishable from honest ones).
func (t *Trapdoor[E, S]) canonicalEquivocation(message *Message[S], witness *Witness[S], newMessage *Message[S]) (*num.Uint, error) {
	if message == nil || witness == nil || newMessage == nil {
		return nil, ErrInvalidArgument.WithMessage("message, witness, and new message cannot be nil")
	}
	zModQ := t.lambda.Group()
	modulus := t.lambda.Modulus()

	m, err := scalarToZModQ(message.Value(), modulus, zModQ)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot reduce message into ZModQ")
	}
	r, err := scalarToZModQ(witness.Value(), modulus, zModQ)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot reduce witness into ZModQ")
	}
	mPrime, err := scalarToZModQ(newMessage.Value(), modulus, zModQ)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot reduce new message into ZModQ")
	}
	lambdaInv, err := t.lambda.TryInv()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot invert lambda")
	}
	return r.Add(lambdaInv.Mul(m.Sub(mPrime))), nil
}

// scalarToZModQ reduces a scalar of generic ring type S into Z/qZ where
// q = modulus. The byte encodings of *num.Int (sign-magnitude) and uint-like
// prime field elements (unsigned big-endian) are not interchangeable, so we
// dispatch on the concrete type of S.
func scalarToZModQ[S algebra.RingElement[S]](v S, modulus *num.NatPlus, zModQ *num.ZMod) (*num.Uint, error) {
	if intVal, ok := any(v).(*num.Int); ok {
		return intVal.Mod(modulus), nil
	}
	if u, ok := any(v).(algebra.UnsignedNumeric); ok {
		out, err := zModQ.FromBytesBEReduce(u.BytesBE())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to reduce unsigned scalar into ZModQ")
		}
		return out, nil
	}
	return nil, ErrInvalidArgument.WithMessage("unsupported scalar type for reduction into ZModQ")
}

// CommitmentKey returns a copy of the public Key half of the trapdoor, suitable
// for handing to non-trusted parties.
func (t *Trapdoor[E, S]) CommitmentKey() *Key[E, S] {
	return &Key[E, S]{
		g: t.g,
		h: t.h,
	}
}

// Lambda exposes the trapdoor scalar λ. Callers must treat the result as secret.
func (t *Trapdoor[E, S]) Lambda() *num.Uint {
	return t.lambda
}

// MarshalCBOR encodes the trapdoor (generator g and λ) into CBOR. h is omitted
// from the wire format because it is recomputed deterministically from g and λ
// during deserialisation, which also re-runs the constructor's invariants.
func (t *Trapdoor[E, S]) MarshalCBOR() ([]byte, error) {
	dto := &trapdoorDTO[E, S]{
		G:      t.g,
		Lambda: t.lambda,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal Pedersen trapdoor")
	}
	return data, nil
}

// UnmarshalCBOR decodes a CBOR-encoded trapdoor into the receiver, rebuilding
// h = g^λ from the decoded fields and re-running the constructor invariants.
func (t *Trapdoor[E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*trapdoorDTO[E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal Pedersen trapdoor")
	}
	t2, err := newTrapdoorKeyUnchecked(dto.G, dto.Lambda)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create Pedersen trapdoor")
	}
	*t = *t2
	return nil
}
