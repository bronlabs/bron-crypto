package boundedintcom

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/errs-go/errs"
)

func SampleCommitmentKey(keyLen uint, messageSlack int, prng io.Reader) (*CommitmentKey, error) {
	_, s, t, _, err := SamplePedersenParameters(keyLen, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to sample Pedersen parameters")
	}
	out, err := NewCommitmentKeyUnchecked(s, t, messageSlack)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create Pedersen commitment key")
	}
	return out, nil
}

// ExtractCommitmentKey deterministically derives a CGGMP21 ring-Pedersen
// CRS (s, t) ∈ QR(N̂)² from the supplied transcript. The two generators are
// extracted from the transcript labels and squared into the quadratic-residue
// subgroup; extraction repeats until both squares are coprime to N̂ to avoid
// the (negligibly probable) factor-leaking elements. The returned key forgets
// the order of the underlying RSA group.
// Note that messageSlack is the bit gap reserved between the accepted message size and the public modulus size: a message
// m is accepted iff |m|.AnnouncedLen() + messageSlack < |N̂|. Equivalently,
// the effective message bit budget is ℓ = |N̂| − messageSlack − 1.
// How to choose messageSlack:
//   - Strong-RSA binding alone needs only ℓ < |ord(t)| ≈ |N̂|−2, i.e.
//     messageSlack ≥ 2. Since ord(t) is hidden, this is the public floor.
//   - Consuming Σ-protocols (range proofs, Πenc, Πaff-g, …) extract
//     witnesses of size ≈ ℓ + |challenge| + σ; for that extraction not to
//     wrap mod ord(t), pick messageSlack ≥ |challenge| + σ + 2. In CGGMP21
//     with a λ-bit Fiat-Shamir challenge and σ = StatisticalSecurityBits,
//     this is λ + σ + 2.
//
// Setting messageSlack at the floor (2) keeps binding intact but voids the
// soundness of any Σ-protocol layered on top, since extracted witnesses can
// wrap mod ord(t).
func ExtractCommitmentKey[A znstar.ArithmeticRSA](transcript ts.Transcript, label string, group *znstar.RSAGroup[A], messageSlack int) (*CommitmentKey, error) {
	if transcript == nil {
		return nil, ErrInvalidArgument.WithMessage("transcript cannot be nil")
	}
	if label == "" {
		return nil, ErrInvalidArgument.WithMessage("label cannot be empty")
	}
	if group == nil {
		return nil, ErrInvalidArgument.WithMessage("group cannot be nil")
	}
	var s, t *znstar.RSAGroupElement[A]
	for {
		sSqrt, err := ts.Extract(transcript, fmt.Sprintf("s_%s", label), group)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to extract sSqrt for pedersen key")
		}
		tSqrt, err := ts.Extract(transcript, fmt.Sprintf("t_%s", label), group)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to extract tSqrt for pedersen key")
		}
		s = sSqrt.Mul(sSqrt)
		t = tSqrt.Mul(tSqrt)
		if s.Value().Decrement().Nat().Coprime(group.Modulus().Nat()) && t.Value().Decrement().Nat().Coprime(group.Modulus().Nat()) {
			break
		}
	}
	out, err := NewCommitmentKeyUnchecked(s.ForgetOrder(), t.ForgetOrder(), messageSlack)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Pedersen commitment key")
	}
	return out, nil
}

// NewCommitmentKeyUnchecked builds a Key directly from two generators without
// going through a transcript-based setup. It still rejects nil, identity, equal
// or torsion-bearing generators, but it does not enforce that the discrete log
// of h to base g is hidden from the caller — using this constructor outside of
// trusted setup or deserialisation may break binding.
// Note that messageSlack is the bit gap reserved between the accepted message size and the public modulus size: a message
// m is accepted iff |m|.AnnouncedLen() + messageSlack < |N̂|. Equivalently,
// the effective message bit budget is ℓ = |N̂| − messageSlack − 1.
// How to choose messageSlack:
//   - Strong-RSA binding alone needs only ℓ < |ord(t)| ≈ |N̂|−2, i.e.
//     messageSlack ≥ 2. Since ord(t) is hidden, this is the public floor.
//   - Consuming Σ-protocols (range proofs, Πenc, Πaff-g, …) extract
//     witnesses of size ≈ ℓ + |challenge| + σ; for that extraction not to
//     wrap mod ord(t), pick messageSlack ≥ |challenge| + σ + 2. In CGGMP21
//     with a λ-bit Fiat-Shamir challenge and σ = StatisticalSecurityBits,
//     this is λ + σ + 2.
//
// Setting messageSlack at the floor (2) keeps binding intact but voids the
// soundness of any Σ-protocol layered on top, since extracted witnesses can
// wrap mod ord(t).
func NewCommitmentKeyUnchecked(s, t *znstar.RSAGroupElementUnknownOrder, messageSlack int) (*CommitmentKey, error) {
	if s == nil || t == nil {
		return nil, ErrInvalidArgument.WithMessage("generators cannot be nil")
	}
	if s.Structure().Name() != t.Structure().Name() {
		return nil, ErrInvalidArgument.WithMessage("s and t must belong to the same group")
	}
	if s.Equal(t) {
		return nil, ErrInvalidArgument.WithMessage("s and t cannot be equal")
	}
	if s.IsOne() || t.IsOne() {
		return nil, ErrInvalidArgument.WithMessage("s or t cannot be the identity element")
	}
	// TorsionFree checks the jacobi symbol. This is necessary but not sufficient.
	// We can't check if they are in QR(N̂) due to not having the order.
	if !s.IsTorsionFree() || !t.IsTorsionFree() {
		return nil, ErrInvalidArgument.WithMessage("s and t must be torsion-free")
	}

	group := s.Group()

	nBits := group.ModulusCT().BitLen()
	witnessUpper := group.Modulus().Lsh(base.StatisticalSecurityBits).Lift()
	witnessLower := witnessUpper.Neg()

	// Slack of 2 is the public floor that keeps ℓ strictly below
	// |ord(t)| ≈ |N̂|−2. Soundness of consuming Σ-protocols requires more;
	// see the function comment for guidance on the correct value.
	if messageSlack < 2 {
		return nil, ErrInvalidArgument.WithMessage("messageSlack must be at least 2 to ensure binding")
	}
	if messageSlack >= nBits {
		return nil, ErrInvalidArgument.WithMessage("messageSlack must be less than the bit length of the group modulus")
	}

	return &CommitmentKey{
		KeyTrait: KeyTrait[*modular.SimpleModulus]{
			s: s,
			t: t,

			messageSlack: messageSlack,
			nBits:        nBits,
			witnessUpper: witnessUpper,
			witnessLower: witnessLower,
		},
	}, nil
}

type CommitmentKey struct {
	KeyTrait[*modular.SimpleModulus]
}

type commitmentKeyDTO struct {
	S            *znstar.RSAGroupElementUnknownOrder `cbor:"s"`
	T            *znstar.RSAGroupElementUnknownOrder `cbor:"t"`
	MessageSlack int                                 `cbor:"slack"`
}

func (k *CommitmentKey) Clone() *CommitmentKey {
	return &CommitmentKey{
		KeyTrait: KeyTrait[*modular.SimpleModulus]{
			s: k.s.Clone(),
			t: k.t.Clone(),
		},
	}
}

func (k *CommitmentKey) MarshalCBOR() ([]byte, error) {
	dto := &commitmentKeyDTO{
		S:            k.s,
		T:            k.t,
		MessageSlack: k.messageSlack,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal commitment key to CBOR")
	}
	return out, nil
}

func (k *CommitmentKey) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[commitmentKeyDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal commitment key from CBOR")
	}
	kk, err := NewCommitmentKeyUnchecked(dto.S, dto.T, dto.MessageSlack)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid commitment key parameters")
	}
	*k = *kk
	return nil
}
