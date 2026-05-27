package intcom

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
)

// SampleTrapdoorKey generates a ring-Pedersen key together with its trapdoor: the
// safe-prime factorisation (carried as the known-order group) and λ = log_t(s). A
// holder of λ can equivocate, so the result is secret material — share only the
// public key returned by Export. keyLen is the bit length of the modulus N̂.
func SampleTrapdoorKey(keyLen uint, prng io.Reader) (*TrapdoorKey, error) {
	group, s, t, lambda, err := SamplePedersenParameters(keyLen, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample pedersen parameters")
	}
	ck, err := newCommitmentKey(s, t)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create commitment key")
	}
	return &TrapdoorKey{
		CommitmentKey: *ck,
		group:         group,
		lambda:        lambda,
	}, nil
}

// NewTrapdoorKey rebuilds a trapdoor key from a known-order generator t and the
// trapdoor λ, deriving s = tλ. It rejects an identity / torsioned / non-generator
// t, and a λ whose modulus is not φ(N̂)/4, that is not a unit there, or that equals
// one (λ = 1 ⇒ s = t, which collapses binding). λ and the factorisation embedded
// in t are secret.
func NewTrapdoorKey(t *znstar.RSAGroupElementKnownOrder, lambda *num.Uint) (*TrapdoorKey, error) {
	if t == nil || lambda == nil {
		return nil, commitments.ErrIsNil.WithMessage("t and lambda must not be nil")
	}
	if t.IsOpIdentity() || !t.IsTorsionFree() {
		return nil, commitments.ErrInvalidArgument.WithMessage("t cannot be the identity element or have torsion")
	}
	if !t.Value().Decrement().Nat().Coprime(t.Modulus().Nat()) {
		return nil, commitments.ErrInvalidArgument.WithMessage("t is not a generator of QR(NHat)")
	}
	p, err := num.NPlus().FromNatCT(t.Arithmetic().Params.PNat)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create p from arithmetic parameters")
	}
	q, err := num.NPlus().FromNatCT(t.Arithmetic().Params.QNat)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create q from arithmetic parameters")
	}
	phiNHatOver4 := p.Rsh(1).Mul(q.Rsh(1))
	if !lambda.Modulus().Equal(phiNHatOver4) {
		return nil, commitments.ErrInvalidArgument.WithMessage("lambda modulus must equal φ(NHat)/4")
	}
	if lambda.IsOne() || !lambda.IsUnit() {
		return nil, commitments.ErrInvalidArgument.WithMessage("lambda must be a unit mod φ(NHat)/4 and not equal to one")
	}
	s := t.ExpI(lambda.Lift())
	ck, err := newCommitmentKey(s.ForgetOrder(), t.ForgetOrder())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create commitment key")
	}
	return &TrapdoorKey{
		CommitmentKey: *ck,
		group:         t.Group(),
		lambda:        lambda,
	}, nil
}

// TrapdoorKey is a CommitmentKey whose trapdoor λ = log_t(s) and modulus
// factorisation (carried as the known-order group) are KNOWN. Its holder can open
// any commitment to any message (Equivocate) and can run group operations faster
// using the known order, so the scheme is NOT binding against them. Share only the
// public, binding key obtained from Export.
type TrapdoorKey struct {
	CommitmentKey

	group  *znstar.RSAGroupKnownOrder
	lambda *num.Uint
}

type trapdoorKeyDTO struct {
	T      *znstar.RSAGroupElementKnownOrder `cbor:"t"`
	Lambda *num.Uint                         `cbor:"lambda"`
}

// CommitWithWitness computes the commitment as t^(λ·m + r), which equals sᵐ·tʳ
// because s = tλ. It produces the same commitment as the public key but folds the
// two exponentiations into one using the known group order.
func (t *TrapdoorKey) CommitWithWitness(message *Message, witness *Witness) (*Commitment, error) {
	if message == nil || witness == nil {
		return nil, commitments.ErrIsNil.WithMessage("message and witness cannot be nil")
	}
	tt, err := t.t.LearnOrder(t.group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order")
	}

	// s^m * t^r = t^(lambda*m + r)
	out, err := NewCommitment(tt.ExpI(message.m.Mul(t.lambda.Lift()).Add(witness.r)).ForgetOrder())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create commitment from message and witness")
	}
	return out, nil
}

// CommitmentOp multiplies commitments using the known group order for efficiency.
// The result equals the public CommitmentKey.CommitmentOp: a commitment to the sum
// of the messages under the sum of the witnesses.
func (t *TrapdoorKey) CommitmentOp(first, second *Commitment, rest ...*Commitment) (*Commitment, error) {
	if first == nil || second == nil {
		return nil, commitments.ErrIsNil.WithMessage("first and second commitments cannot be nil")
	}
	firstValue, err := first.Value().LearnOrder(t.group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order of first commitment value")
	}
	secondValue, err := second.Value().LearnOrder(t.group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order of second commitment value")
	}
	restValues, err := sliceutils.MapOrError(rest, func(w *Commitment) (*znstar.RSAGroupElementKnownOrder, error) {
		if utils.IsNil(w) {
			return nil, commitments.ErrIsNil.WithMessage("object must not be nil")
		}
		out, err := w.Value().LearnOrder(t.group)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not learn order of commitment value")
		}
		return out, nil
	})
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid commitment in rest commitments")
	}
	outValue, err := algebrautils.OpValues(t.group, firstValue, secondValue, restValues...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine commitment values")
	}
	out, err := NewCommitment(outValue.ForgetOrder())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new commitment from combined value")
	}
	return out, nil
}

// CommitmentOpInv returns the inverse of a commitment, computed with the known
// group order; equivalent to CommitmentKey.CommitmentOpInv.
func (t *TrapdoorKey) CommitmentOpInv(c *Commitment) (*Commitment, error) {
	if c == nil {
		return nil, commitments.ErrIsNil.WithMessage("commitment cannot be nil")
	}
	value, err := c.Value().LearnOrder(t.group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order of commitment value")
	}
	if !t.group.Contains(value) {
		return nil, commitments.ErrSubGroupMembership.WithMessage("commitment must be in commitment group")
	}
	out, err := NewCommitment(value.OpInv().ForgetOrder())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new commitment from inverse value")
	}
	return out, nil
}

// CommitmentScalarOp raises a commitment to an integer scalar, computed with the
// known group order; equivalent to CommitmentKey.CommitmentScalarOp.
func (t *TrapdoorKey) CommitmentScalarOp(c *Commitment, scalar *num.Int) (*Commitment, error) {
	if c == nil || scalar == nil {
		return nil, commitments.ErrIsNil.WithMessage("commitment and scalar cannot be nil")
	}
	value, err := c.Value().LearnOrder(t.group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order of commitment value")
	}
	if !t.group.Contains(value) {
		return nil, commitments.ErrSubGroupMembership.WithMessage("commitment must be in commitment group")
	}
	out, err := NewCommitment(value.ExpI(scalar).ForgetOrder())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new commitment from scalar multiplied value")
	}
	return out, nil
}

// Equivocate uses the trapdoor to find a witness r' that opens the same commitment
// to newMessage. The raw solution is r' = r + λ·(m − m'); since that shifts r'
// off the honest witness distribution, the method re-randomises r' within its
// residue class mod ord(t) so the returned witness is distributed like a freshly
// sampled opening of newMessage. That re-randomisation is why — unlike prime-order
// Pedersen — a prng is required here. Returns a clone of witness when m = m'.
func (t *TrapdoorKey) Equivocate(message *Message, witness *Witness, newMessage *Message, prng io.Reader) (*Witness, error) {
	if message == nil || witness == nil || newMessage == nil || prng == nil {
		return nil, commitments.ErrIsNil.WithMessage("message, witness, new message, and prng cannot be nil")
	}
	// s^m * t^r mod n = s^m' * t^r' mod n => t^(lambda*m + r) = t^(lambda*m' + r') => lambda*m + r = lambda*m' + r'
	// => r' = r + lambda*(m - m')
	// Note that the distribution of r' is different than r if m != m'.
	if message.Equal(newMessage) {
		return witness.Clone(), nil
	}
	rPrime := witness.r.Add(t.lambda.Lift().Mul(message.m.Sub(newMessage.m)))
	// r0 is now [0, Phi(NHat)/4)
	r0 := rPrime.Mod(t.lambda.Modulus())
	// We need to find a random number x so that r'' is in [k.witnessLower, k.witnessUpper)
	lowerInner, err := num.Q().New(t.witnessLower.Sub(r0.Lift()), (t.lambda.Modulus()))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create lowerInner from witnessLower and r0")
	}
	xMin, err := lowerInner.Ceil()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compute xMin")
	}

	upperInner, err := num.Q().New(t.witnessUpper.Sub(r0.Lift()).Decrement(), (t.lambda.Modulus()))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create upperInner from witnessUpper and r0")
	}
	xMax, err := upperInner.Floor()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compute xMax")
	}
	x, err := num.Z().Random(xMin, xMax.Increment(), prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to generate random x")
	}
	rDoublePrime := r0.Lift().Add(x.Mul(t.lambda.Modulus().Lift()))
	out, err := NewWitness(rDoublePrime)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new witness from rDoublePrime")
	}
	return out, nil
}

// Group returns the known-order RSA group, which encodes the secret factorisation
// of N̂.
func (t *TrapdoorKey) Group() *znstar.RSAGroupKnownOrder {
	return t.group
}

// Lambda returns the secret trapdoor λ = log_t(s). Exposing it lets anyone
// equivocate and thereby defeats binding.
func (t *TrapdoorKey) Lambda() *num.Uint {
	return t.lambda
}

// Export returns the public CommitmentKey, dropping λ and the factorisation so the
// result can be shared as a binding key.
func (t *TrapdoorKey) Export() *CommitmentKey {
	return t.Clone()
}

// Equal reports whether two trapdoor keys share the same generator t and trapdoor
// λ (s is determined by these), treating a nil key as equal only to another nil
// one.
func (t *TrapdoorKey) Equal(other *TrapdoorKey) bool {
	if t == nil || other == nil {
		return t == other
	}
	return t.t.Equal(other.t) && t.lambda.Equal(other.lambda)
}

// HashCode combines t and λ for use as a map key.
func (t *TrapdoorKey) HashCode() base.HashCode {
	return t.t.HashCode().Combine(t.lambda.HashCode())
}

// MarshalCBOR encodes the known-order generator t and the secret λ (s is
// recomputed on decode). The output contains the trapdoor and must be protected as
// secret material.
func (t *TrapdoorKey) MarshalCBOR() ([]byte, error) {
	learned, err := t.t.LearnOrder(t.group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order")
	}
	dto := &trapdoorKeyDTO{
		T:      learned,
		Lambda: t.lambda,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal trapdoor key")
	}
	return out, nil
}

// UnmarshalCBOR decodes a trapdoor key and revalidates it via NewTrapdoorKey,
// recomputing s = tλ. This is a deserialization trust boundary handling secret
// material.
func (t *TrapdoorKey) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[trapdoorKeyDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal trapdoor key")
	}
	kk, err := NewTrapdoorKey(dto.T, dto.Lambda)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid trapdoor key data")
	}
	*t = *kk
	return nil
}
