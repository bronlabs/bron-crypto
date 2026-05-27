package intcom

import (
	"fmt"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/internal"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
)

// SampleCommitmentKey generates a fresh ring-Pedersen public key: it samples a
// safe-prime RSA group and two generators s = tλ of QR(N̂), then discards the
// trapdoor λ and the factorisation so the returned key is binding. keyLen is the
// bit length of the modulus N̂. Use SampleTrapdoorKey if you need to retain λ.
func SampleCommitmentKey(keyLen uint, prng io.Reader) (*CommitmentKey, error) {
	_, s, t, _, err := SamplePedersenParameters(keyLen, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to sample Pedersen parameters")
	}
	out, err := newCommitmentKey(s, t)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create Pedersen commitment key")
	}
	return out, nil
}

// ExtractCommitmentKey derives the two generators s and t deterministically from a
// public transcript (nothing-up-my-sleeve), so every party sharing the transcript
// obtains the same binding key with no trapdoor known to anyone. Each generator is
// the square of a hashed-to-group value — forcing it into QR(N̂) — and is rejected
// unless gcd(x−1, N̂) = 1, i.e. it generates QR(N̂); the label domain-separates the
// two. The derivation is intended to be reproducible: the same transcript and
// label must always yield the same key.
func ExtractCommitmentKey[A znstar.ArithmeticRSA](transcript ts.Transcript, label string, group *znstar.RSAGroup[A]) (*CommitmentKey, error) {
	if transcript == nil {
		return nil, commitments.ErrInvalidArgument.WithMessage("transcript cannot be nil")
	}
	if label == "" {
		return nil, commitments.ErrInvalidArgument.WithMessage("label cannot be empty")
	}
	if group == nil {
		return nil, commitments.ErrInvalidArgument.WithMessage("group cannot be nil")
	}
	var s, t *znstar.RSAGroupElement[A]

	counter := 0
	for {
		sSqrt, err := ts.Extract(transcript, fmt.Sprintf("s_%s_%d", label, counter), group)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to extract sSqrt for pedersen key")
		}
		s = sSqrt.Mul(sSqrt)
		if s.Value().Decrement().Nat().Coprime(group.Modulus().Nat()) {
			break
		}
		counter++
	}

	counter = 0
	for {
		tSqrt, err := ts.Extract(transcript, fmt.Sprintf("t_%s_%d", label, counter), group)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to extract tSqrt for pedersen key")
		}
		t = tSqrt.Mul(tSqrt)
		if t.Value().Decrement().Nat().Coprime(group.Modulus().Nat()) {
			break
		}
		counter++
	}

	out, err := newCommitmentKey(s.ForgetOrder(), t.ForgetOrder())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Pedersen commitment key")
	}
	return out, nil
}

func newCommitmentKey(s, t *znstar.RSAGroupElementUnknownOrder) (*CommitmentKey, error) {
	if s == nil || t == nil {
		return nil, commitments.ErrInvalidArgument.WithMessage("generators cannot be nil")
	}
	if s.Structure().Name() != t.Structure().Name() {
		return nil, commitments.ErrInvalidArgument.WithMessage("s and t must belong to the same group")
	}
	if s.Equal(t) {
		return nil, commitments.ErrInvalidArgument.WithMessage("s and t cannot be equal")
	}
	if s.IsOne() || t.IsOne() {
		return nil, commitments.ErrInvalidArgument.WithMessage("s or t cannot be the identity element")
	}
	// TorsionFree checks the jacobi symbol. This is necessary but not sufficient.
	// We can't check if they are in QR(N̂) due to not having the order.
	if !s.IsTorsionFree() || !t.IsTorsionFree() {
		return nil, commitments.ErrInvalidArgument.WithMessage("s and t must be torsion-free")
	}
	// If s and t are in QR(N̂), then they must be generators of QR(N̂).
	if !s.Value().Decrement().Nat().Coprime(s.Modulus().Nat()) {
		return nil, commitments.ErrInvalidArgument.WithMessage("s is not a generator of QR(NHat)")
	}
	if !t.Value().Decrement().Nat().Coprime(t.Modulus().Nat()) {
		return nil, commitments.ErrInvalidArgument.WithMessage("t is not a generator of QR(NHat)")
	}

	witnessUpper := s.Group().Modulus().Lsh(base.StatisticalSecurityBits).Lift()
	witnessLower := witnessUpper.Neg()

	return &CommitmentKey{
		s: s,
		t: t,

		witnessUpper: witnessUpper,
		witnessLower: witnessLower,
	}, nil
}

// CommitmentKey is a ring-Pedersen public key: two generators s, t of QR(N̂) in an
// RSA group of unknown order, with log_t(s) unknown. Committing computes sᵐ·tʳ mod
// N̂. Binding is computational (knowing log_t(s) breaks it); hiding is statistical,
// achieved by sampling the witness from the wide cached range [witnessLower,
// witnessUpper). The key is public and holds no trapdoor; its trapdoor counterpart
// is TrapdoorKey. Construct one with SampleCommitmentKey or ExtractCommitmentKey.
type CommitmentKey struct {
	s, t *znstar.RSAGroupElementUnknownOrder

	witnessUpper *num.Int
	witnessLower *num.Int
}

type commitmentKeyDTO struct {
	S *znstar.RSAGroupElementUnknownOrder `cbor:"s"`
	T *znstar.RSAGroupElementUnknownOrder `cbor:"t"`
}

// Type returns the scheme identifier Name.
func (*CommitmentKey) Type() commitments.Name {
	return Name
}

// SampleWitness draws r uniformly from [−N̂·2ᵏ, N̂·2ᵏ), where k is the statistical
// security parameter. Sampling from a range this much wider than the group order
// makes r mod ord(t) statistically close to uniform, which is the source of the
// scheme's statistical hiding; prng must be cryptographically secure.
func (k *CommitmentKey) SampleWitness(prng io.Reader) (*Witness, error) {
	if prng == nil {
		return nil, commitments.ErrIsNil.WithMessage("prng cannot be nil")
	}
	wv, err := num.Z().Random(k.witnessLower, k.witnessUpper, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to sample witness value")
	}
	witness, err := NewWitness(wv)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create witness from sampled value")
	}
	return witness, nil
}

// CommitWithWitness deterministically computes C = sᵐ·tʳ mod N̂. With log_t(s)
// unknown this binds m; with a wide-range secret r it statistically hides it. Both
// m and r are arbitrary signed integers.
func (k *CommitmentKey) CommitWithWitness(message *Message, witness *Witness) (*Commitment, error) {
	if message == nil || witness == nil {
		return nil, commitments.ErrIsNil.WithMessage("message and witness cannot be nil")
	}
	out, err := NewCommitment(k.s.ExpI(message.Value()).Mul(k.t.ExpI(witness.Value())).ForgetOrder())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create commitment from message and witness")
	}
	return out, nil
}

// Open verifies that (message, witness) opens commitment by recomputing sᵐ·tʳ and
// comparing, returning commitments.ErrVerificationFailed on mismatch. Binding
// ensures no second opening exists without knowledge of log_t(s).
func (k *CommitmentKey) Open(commitment *Commitment, message *Message, witness *Witness) error {
	if err := internal.GenericOpen(k, commitment, message, witness); err != nil {
		return errs.Wrap(err).WithMessage("failed to open commitment")
	}
	return nil
}

// WitnessOp adds witnesses over the integers. Adding the randomness of two
// commitments matches multiplying the commitments (CommitmentOp) — the additive
// homomorphism that keeps openings consistent.
func (k *CommitmentKey) WitnessOp(first, second *Witness, rest ...*Witness) (*Witness, error) {
	out, err := algebrautils.Op(NewWitness, k.WitnessGroup(), first, second, rest...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine witnesses")
	}
	return out, nil
}

// WitnessOpInv negates a witness over the integers, giving the randomness of the
// inverse commitment (CommitmentOpInv).
func (*CommitmentKey) WitnessOpInv(w *Witness) (*Witness, error) {
	if w == nil {
		return nil, commitments.ErrIsNil.WithMessage("witness cannot be nil")
	}
	out, err := NewWitness(w.Value().Neg())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new witness")
	}
	return out, nil
}

// WitnessScalarOp multiplies a witness by an integer scalar, matching the
// randomness of a commitment raised to that scalar (CommitmentScalarOp).
func (*CommitmentKey) WitnessScalarOp(w *Witness, scalar *num.Int) (*Witness, error) {
	if w == nil {
		return nil, commitments.ErrIsNil.WithMessage("witness cannot be nil")
	}
	if scalar == nil {
		return nil, commitments.ErrIsNil.WithMessage("scalar cannot be nil")
	}
	out, err := NewWitness(w.Value().Mul(scalar))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new witness")
	}
	return out, nil
}

// MessageOp adds committed values over the integers; by the homomorphism a
// commitment to the sum equals the CommitmentOp of the individual commitments.
func (k *CommitmentKey) MessageOp(first, second *Message, rest ...*Message) (*Message, error) {
	out, err := algebrautils.Op(NewMessage, k.MessageGroup(), first, second, rest...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine messages")
	}
	return out, nil
}

// MessageOpInv negates a committed value, matching CommitmentOpInv on its
// commitment.
func (*CommitmentKey) MessageOpInv(m *Message) (*Message, error) {
	if m == nil {
		return nil, commitments.ErrIsNil.WithMessage("message cannot be nil")
	}
	out, err := NewMessage(m.Value().Neg())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new message")
	}
	return out, nil
}

// MessageScalarOp multiplies a committed value by an integer scalar, matching
// CommitmentScalarOp on its commitment.
func (*CommitmentKey) MessageScalarOp(m *Message, scalar *num.Int) (*Message, error) {
	if m == nil {
		return nil, commitments.ErrIsNil.WithMessage("message cannot be nil")
	}
	if scalar == nil {
		return nil, commitments.ErrIsNil.WithMessage("scalar cannot be nil")
	}
	out, err := NewMessage(m.Value().Mul(scalar))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new message")
	}
	return out, nil
}

// CommitmentOp multiplies commitments in QR(N̂). By the homomorphism the product
// is a commitment to the sum of the messages under the sum of the witnesses.
func (k *CommitmentKey) CommitmentOp(first, second *Commitment, rest ...*Commitment) (*Commitment, error) {
	out, err := algebrautils.Op(NewCommitment, k.CommitmentGroup(), first, second, rest...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine commitments")
	}
	return out, nil
}

// CommitmentOpInv returns the multiplicative inverse of a commitment in QR(N̂),
// i.e. a commitment to the negated message under the negated witness. The
// commitment must lie in the commitment group.
func (k *CommitmentKey) CommitmentOpInv(c *Commitment) (*Commitment, error) {
	if c == nil {
		return nil, commitments.ErrIsNil.WithMessage("commitment cannot be nil")
	}
	if !k.CommitmentGroup().Contains(c.Value()) {
		return nil, commitments.ErrSubGroupMembership.WithMessage("commitment must be in commitment group")
	}
	out, err := NewCommitment(c.Value().Inv())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new commitment")
	}
	return out, nil
}

// CommitmentScalarOp raises a commitment to an integer scalar, scaling both the
// committed message and the witness by that scalar. The commitment must lie in the
// commitment group.
func (k *CommitmentKey) CommitmentScalarOp(c *Commitment, scalar *num.Int) (*Commitment, error) {
	if c == nil {
		return nil, commitments.ErrIsNil.WithMessage("commitment cannot be nil")
	}
	if scalar == nil {
		return nil, commitments.ErrIsNil.WithMessage("scalar cannot be nil")
	}
	if !k.CommitmentGroup().Contains(c.v) {
		return nil, commitments.ErrSubGroupMembership.WithMessage("commitment must be in commitment group")
	}
	out, err := NewCommitment(c.Value().ExpI(scalar))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new commitment")
	}
	return out, nil
}

// ReRandomise multiplies a commitment by t^witnessShift, yielding a commitment to
// the SAME message with witness r + witnessShift. For unlinkability the shift
// should be drawn from the full witness range (see SampleWitness), since the sum
// is not otherwise re-spread over that range.
func (k *CommitmentKey) ReRandomise(c *Commitment, witnessShift *Witness) (*Commitment, error) {
	if c == nil {
		return nil, commitments.ErrIsNil.WithMessage("commitment cannot be nil")
	}
	if witnessShift == nil {
		return nil, commitments.ErrIsNil.WithMessage("witness shift cannot be nil")
	}
	if !k.CommitmentGroup().Contains(c.Value()) {
		return nil, commitments.ErrSubGroupMembership.WithMessage("commitment must be in commitment group")
	}
	out, err := NewCommitment(c.Value().Mul(k.t.ExpI(witnessShift.Value())))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new commitment")
	}
	return out, nil
}

// Shift multiplies a commitment by s^message, yielding a commitment to the shifted
// value m + message under the SAME witness. The committed value changes; the
// randomness does not.
func (k *CommitmentKey) Shift(c *Commitment, message *Message) (*Commitment, error) {
	if c == nil {
		return nil, commitments.ErrIsNil.WithMessage("commitment cannot be nil")
	}
	if message == nil {
		return nil, commitments.ErrIsNil.WithMessage("message cannot be nil")
	}
	if !k.CommitmentGroup().Contains(c.Value()) {
		return nil, commitments.ErrSubGroupMembership.WithMessage("commitment must be in commitment group")
	}
	out, err := NewCommitment(c.Value().Mul(k.s.ExpI(message.Value())))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new commitment")
	}
	return out, nil
}

// MessageGroup returns ℤ, the domain of committed messages.
func (*CommitmentKey) MessageGroup() *num.Integers {
	return num.Z()
}

// WitnessGroup returns ℤ, the domain of witnesses (only the wide sub-range in
// SampleWitness is actually sampled).
func (*CommitmentKey) WitnessGroup() *num.Integers {
	return num.Z()
}

// CommitmentGroup returns the unknown-order RSA group in which commitments live.
func (k *CommitmentKey) CommitmentGroup() *znstar.RSAGroupUnknownOrder {
	return k.s.Group()
}

// S returns the generator s, the base for the message exponent.
func (k *CommitmentKey) S() *znstar.RSAGroupElementUnknownOrder {
	return k.s
}

// T returns the generator t, the base for the randomness exponent. log_t(s) must
// be unknown for binding to hold.
func (k *CommitmentKey) T() *znstar.RSAGroupElementUnknownOrder {
	return k.t
}

// Group returns the unknown-order RSA group of the key (same as CommitmentGroup).
func (k *CommitmentKey) Group() *znstar.RSAGroupUnknownOrder {
	return k.s.Group()
}

// Equal reports whether two keys have the same generators and order
// representation, treating a nil key as equal only to another nil one. Keys are
// public, so this need not be constant time.
func (k *CommitmentKey) Equal(other *CommitmentKey) bool {
	if k == nil || other == nil {
		return k == other
	}
	return k.s.Equal(other.s) &&
		k.t.Equal(other.t) &&
		k.s.IsUnknownOrder() == other.s.IsUnknownOrder()
}

// HashCode combines the two generators' hash codes for use as a map key.
func (k *CommitmentKey) HashCode() base.HashCode {
	return k.s.HashCode().Combine(k.t.HashCode())
}

// Clone returns a deep copy of the key, including its cached witness bounds.
func (k *CommitmentKey) Clone() *CommitmentKey {
	return &CommitmentKey{
		s:            k.s.Clone(),
		t:            k.t.Clone(),
		witnessUpper: k.witnessUpper.Clone(),
		witnessLower: k.witnessLower.Clone(),
	}
}

// MarshalCBOR encodes the two generators s and t.
func (k *CommitmentKey) MarshalCBOR() ([]byte, error) {
	dto := &commitmentKeyDTO{
		S: k.s,
		T: k.t,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal commitment key to CBOR")
	}
	return out, nil
}

// UnmarshalCBOR decodes a commitment key and revalidates it via newCommitmentKey
// (torsion-free and generator checks). This is a deserialization trust boundary:
// because the group order is unknown, full QR(N̂) membership of s and t cannot be
// verified here, so a key from an untrusted source must not be assumed binding
// without an accompanying Π^{prm}-style proof.
func (k *CommitmentKey) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[commitmentKeyDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal commitment key from CBOR")
	}
	kk, err := newCommitmentKey(dto.S, dto.T)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid commitment key parameters")
	}
	*k = *kk
	return nil
}
