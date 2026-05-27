package intcom

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
)

// Name identifies the bounded integer (ring-Pedersen) commitment scheme of
// CGGMP21.
const Name commitments.Name = "Bounded Integer Commitment Scheme (CGGMP21)"

// SamplePedersenParameters generates a full ring-Pedersen setup for the
// CGGMP21 ZK proofs (Π^{prm}, Π^{enc}, Π^{aff-g}, range proofs, …).
// Concretely it:
//
//  1. Samples a safe-prime RSA group (Z/N̂Z)* with N̂ = p·q, p = 2p' + 1
//     and q = 2q' + 1. QR_{N̂} is then cyclic of prime order p'·q', which
//     is what makes the discrete-log assumption in QR_{N̂} plausibly hard
//     and the Π^{prm} proof sound.
//  2. Draws t uniformly from QR_{N̂}. Since QR_{N̂} has prime order, a
//     uniformly random QR is a generator except with probability
//     ≈ 2^{-|p|+1}; the gcd(t-1, N̂) = 1 guard rejects the rare case of
//     landing on a non-generator (which would collapse ⟨t⟩ to a proper
//     subgroup and leak information about p, q).
//  3. Samples λ ∈ [1, φ(N̂)/4) uniformly. φ(N̂)/4 = p'·q' is exactly the
//     order of QR_{N̂}, so s := t^λ is uniformly distributed over ⟨t⟩ =
//     QR_{N̂}.
//  4. Returns s, t as elements of the unknown-order view of the group;
//     external callers see only the public parameters. The raw primes
//     p, q and the trapdoor λ are returned alongside for callers that own
//     the setup and need them to accelerate their own proofs.
//
// SECURITY: the returned p, q, λ triple fully reveals the factorisation
// of N̂ and the ring-Pedersen trapdoor. Any party given these values can
// open arbitrary Pedersen commitments; they must be kept secret from
// every other protocol participant and zeroised as soon as they are no
// longer needed.
func SamplePedersenParameters(keyLen uint, prng io.Reader) (group *znstar.RSAGroupKnownOrder, s, t *znstar.RSAGroupElementUnknownOrder, lambda *num.Uint, err error) {
	if prng == nil {
		return nil, nil, nil, nil, commitments.ErrIsNil.WithMessage("prng")
	}
	rsaGroup, err := znstar.SampleSafeRSAGroup(keyLen, prng)
	if err != nil {
		return nil, nil, nil, nil, errs.Wrap(err).WithMessage("failed to sample RSA group with safe primes")
	}
	NHat := rsaGroup.Modulus()
	p, err := num.NPlus().FromNatCT(rsaGroup.Arithmetic().Params.PNat)
	if err != nil {
		return nil, nil, nil, nil, errs.Wrap(err).WithMessage("failed to create NatPlus from p")
	}
	q, err := num.NPlus().FromNatCT(rsaGroup.Arithmetic().Params.QNat)
	if err != nil {
		return nil, nil, nil, nil, errs.Wrap(err).WithMessage("failed to create NatPlus from q")
	}
	var tKnownOrder, sKnownOrder *znstar.RSAGroupElementKnownOrder
	for {
		tKnownOrder, err = rsaGroup.RandomQuadraticResidue(prng)
		if err != nil {
			return nil, nil, nil, nil, errs.Wrap(err).WithMessage("failed to sample t")
		}
		// Check that t is a generator of QR(NHat). The probability of it not being one is ~2^{-|p|+1}.
		// Let N = pq with p = 2p'+1, q = 2q'+1 (safe primes).
		// Then QR_N ≅ C_{p'} × C_{q'} with p', q' prime ⇒ QR_N is cyclic.
		//
		// We sample x = a^2 mod N ⇒ x ∈ QR_N.
		// In each component (mod p, mod q), order is either 1 or full.
		// So x generates QR_N ⇔ x ≠ 1 mod p AND x ≠ 1 mod q.
		//
		// Since N = pq, gcd(x-1, N) = 1 ⇔ p ∤ (x-1) and q ∤ (x-1)
		// ⇔ x ≠ 1 mod p AND x ≠ 1 mod q.
		//
		// Hence: x is a generator ⇔ gcd(x-1, N) = 1.
		if tKnownOrder.Value().Decrement().Nat().Coprime(NHat.Nat()) {
			break
		}
	}
	phiNHatOver4 := p.Rsh(1).Mul(q.Rsh(1))
	zModPhiNHatOver4, err := num.NewZMod(phiNHatOver4)
	if err != nil {
		return nil, nil, nil, nil, errs.Wrap(err).WithMessage("failed to create ZMod for sampling lambda")
	}
	// Rejection-sample λ until it is a unit mod p'q'. The probability of
	// hitting a non-unit (a multiple of p' or q') is ≈ 1/p' + 1/q', i.e.
	// negligible for safe-prime moduli, but a non-unit λ has no inverse
	// and yields s = t^λ of strictly smaller order than ⟨t⟩ — both of
	// which break the trapdoor downstream.
	for {
		lambda, err = algebrautils.RandomNonIdentity(zModPhiNHatOver4, prng)
		if err != nil {
			return nil, nil, nil, nil, errs.Wrap(err).WithMessage("failed to sample lambda")
		}
		if lambda.IsUnit() {
			break
		}
	}
	sKnownOrder = tKnownOrder.Exp(lambda.Abs())
	return rsaGroup, sKnownOrder.ForgetOrder(), tKnownOrder.ForgetOrder(), lambda, nil
}

// NewCommitment wraps an unknown-order RSA group element as a commitment value,
// rejecting nil. It is the canonical constructor and is used by the CBOR decoder.
func NewCommitment(v *znstar.RSAGroupElementUnknownOrder) (*Commitment, error) {
	if v == nil {
		return nil, commitments.ErrIsNil.WithMessage("commitment value must not be nil")
	}
	return &Commitment{
		v: v,
	}, nil
}

// Commitment is a ring-Pedersen commitment C = sᵐ·tʳ mod N̂, held as an element of
// QR(N̂) in the unknown-order view of the RSA group. It is public: it statistically
// hides m while the witness r is secret, and is computationally binding under the
// factoring/discrete-log assumption in QR(N̂).
type Commitment struct {
	v *znstar.RSAGroupElementUnknownOrder
}

type commitmentDTO struct {
	V *znstar.RSAGroupElementUnknownOrder `cbor:"v"`
}

// Value returns the underlying group element sᵐ·tʳ.
func (c *Commitment) Value() *znstar.RSAGroupElementUnknownOrder {
	return c.v
}

// Equal reports whether two commitments are the same group element and share the
// unknown-order representation, treating a nil commitment as equal only to another
// nil one. Commitments are public, so this need not be constant time.
func (c *Commitment) Equal(other *Commitment) bool {
	if c == nil || other == nil {
		return c == other
	}
	return c.v.Equal(other.v) && c.v.IsUnknownOrder() == other.v.IsUnknownOrder()
}

// HashCode returns a non-cryptographic hash of the commitment for use as a map key.
func (c *Commitment) HashCode() base.HashCode {
	return c.v.HashCode()
}

// Clone returns a deep copy of the commitment.
func (c *Commitment) Clone() *Commitment {
	return &Commitment{v: c.v.Clone()}
}

// MarshalCBOR encodes the commitment's group element.
func (c *Commitment) MarshalCBOR() ([]byte, error) {
	dto := &commitmentDTO{
		V: c.v,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal commitment to CBOR")
	}
	return out, nil
}

// UnmarshalCBOR decodes a commitment, rejecting a nil element via NewCommitment.
// This is a deserialization trust boundary; because the group order is unknown,
// membership of the element in QR(N̂) is not (and cannot be) fully verified here.
func (c *Commitment) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[commitmentDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal commitment from CBOR")
	}
	cc, err := NewCommitment(dto.V)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create commitment from unmarshaled data")
	}
	*c = *cc
	return nil
}

// NewWitness wraps a signed integer as commitment randomness, rejecting nil.
func NewWitness(v *num.Int) (*Witness, error) {
	if v == nil {
		return nil, commitments.ErrIsNil.WithMessage("witness value must not be nil")
	}
	return &Witness{r: v}, nil
}

// Witness is the secret randomness r in C = sᵐ·tʳ. It is a signed integer drawn
// from a range far wider than the (hidden) group order; that excess width is what
// makes the commitment statistically hiding. Keep it private until opening.
type Witness struct {
	r *num.Int
}

type witnessDTO struct {
	R *num.Int `cbor:"r"`
}

// Value returns the underlying integer r. The result is secret.
func (w *Witness) Value() *num.Int {
	return w.r
}

// Equal reports whether two witnesses hold the same integer, treating nil as equal
// only to nil. It delegates to integer comparison and is not guaranteed constant
// time, so avoid it on still-secret witnesses in timing-sensitive paths.
func (w *Witness) Equal(other *Witness) bool {
	if w == nil || other == nil {
		return w == other
	}
	return w.r.Equal(other.r)
}

// HashCode returns a non-cryptographic hash of the witness for use as a map key.
func (w *Witness) HashCode() base.HashCode {
	return w.r.HashCode()
}

// Clone returns a deep copy of the witness.
func (w *Witness) Clone() *Witness {
	return &Witness{r: w.r.Clone()}
}

// MarshalCBOR encodes the witness integer. The output is secret material.
func (w *Witness) MarshalCBOR() ([]byte, error) {
	dto := &witnessDTO{
		R: w.r,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal witness to CBOR")
	}
	return out, nil
}

// UnmarshalCBOR decodes a witness integer, rejecting nil via NewWitness. This is a
// deserialization trust boundary for secret material.
func (w *Witness) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[witnessDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal witness from CBOR")
	}
	ww, err := NewWitness(dto.R)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create witness from unmarshaled data")
	}
	*w = *ww
	return nil
}

// NewMessage wraps a signed integer as the committed value, rejecting nil.
func NewMessage(v *num.Int) (*Message, error) {
	if v == nil {
		return nil, commitments.ErrIsNil.WithMessage("message value must not be nil")
	}
	return &Message{m: v}, nil
}

// Message is the committed value m, an arbitrary (bounded) signed integer.
// Committing over the integers — rather than a finite field — is what makes this
// an integer commitment, suitable as the base for range proofs.
type Message struct {
	m *num.Int
}

type messageDTO struct {
	M *num.Int `cbor:"m"`
}

// Value returns the underlying integer m.
func (m *Message) Value() *num.Int {
	return m.m
}

// Equal reports whether two messages hold the same integer, treating nil as equal
// only to nil.
func (m *Message) Equal(other *Message) bool {
	if m == nil || other == nil {
		return m == other
	}
	return m.m.Equal(other.m)
}

// HashCode returns a non-cryptographic hash of the message for use as a map key.
func (m *Message) HashCode() base.HashCode {
	return m.m.HashCode()
}

// Clone returns a deep copy of the message.
func (m *Message) Clone() *Message {
	return &Message{m: m.m.Clone()}
}

// MarshalCBOR encodes the message integer.
func (m *Message) MarshalCBOR() ([]byte, error) {
	dto := &messageDTO{
		M: m.m,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal message to CBOR")
	}
	return out, nil
}

// UnmarshalCBOR decodes a message integer, rejecting nil via NewMessage.
func (m *Message) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[messageDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal message from CBOR")
	}
	mm, err := NewMessage(dto.M)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create message from unmarshaled data")
	}
	*m = *mm
	return nil
}
