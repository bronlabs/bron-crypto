package mrr21

import (
	"io"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

// popfHashLabel separates the POPF's random oracles H_0, H_1 from every other
// use of the group's hash-to-group function in this repository.
const popfHashLabel = "BRON_CRYPTO-MRR21-MASNY_RINDAL_POPF-"

// MasnyRindalPopf is a programmed Masny–Rindal 2-POPF φ = (s_0, s_1) over a
// prime-order group G (MRR21, Figure 6): Eval(φ, x) = s_x · H_x(s_{1−x}), where
// H_0, H_1 : G → G are random oracles instantiated by hash-to-group with the
// label popfHashLabel and the bit x; one pair of oracles serves a whole batch,
// whose instances MRR21 Figure 3 separates through the key-agreement tags.
// Programming on
// (x*, y*) samples s_{1−x*} uniformly and sets s_{x*} = y* · H_{x*}(s_{1−x*})⁻¹,
// so that Eval(φ, x*) = y* while Eval(φ, 1−x*) is a random group element whose
// discrete logarithm nobody knows (Theorem 14 of MRR21, in the random oracle
// model). φ is public: it is what the OT receiver sends to the sender. The
// programmed bit x* is hidden by φ (honest simulation), provided y* is uniform,
// which in MRR21 Figure 3 it is, being a key-agreement message.
//
// The programming is not constant time in x*: the branch chosen and the memory
// accessed depend on it.
type MasnyRindalPopf[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	s [2]G
}

type masnyRindalPopfDTO[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	S [2]G `cbor:"s"`
}

// NewMasnyRindalProgrammedPopf programs a POPF so that Eval(x) = y. x must be
// 0 or 1, y a non-identity group element and prng a cryptographically secure
// source, since the uniformity of s_{1−x} is what hides x.
func NewMasnyRindalProgrammedPopf[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](x byte, y G, prng io.Reader) (*MasnyRindalPopf[G, S], error) {
	if x > 1 {
		return nil, ot.ErrInvalidArgument.WithMessage("x must be 0 or 1, got %d", x)
	}
	if utils.IsNil(y) {
		return nil, ot.ErrInvalidArgument.WithMessage("programmed value must not be nil")
	}
	if y.IsOpIdentity() {
		return nil, ot.ErrInvalidArgument.WithMessage("programmed value must not be the identity")
	}
	if prng == nil {
		return nil, ot.ErrInvalidArgument.WithMessage("prng must not be nil")
	}

	group := algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](y.Structure())
	var s [2]G
	random, err := group.Random(prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot sample random group element")
	}
	if random.IsOpIdentity() {
		return nil, ot.ErrInvalidArgument.WithMessage("sampled group element is the identity")
	}
	s[1-x] = random

	hx, err := oracle(group, x, s[1-x])
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot evaluate random oracle H_%d", x)
	}
	s[x] = y.Op(hx.OpInv())
	if s[x].IsOpIdentity() {
		return nil, ot.ErrInvalidArgument.WithMessage("programmed element is the identity")
	}

	return &MasnyRindalPopf[G, S]{s: s}, nil
}

// Eval evaluates the POPF on x ∈ {0, 1} and returns s_x · H_x(s_{1−x}). On the
// programmed bit this is the programmed value; on the other bit it is a group
// element outside anyone's control. An evaluation that is the identity is
// reported as ErrValidation: it is a property of the received POPF, which
// only its author can arrange.
func (popf *MasnyRindalPopf[G, S]) Eval(x byte) (G, error) {
	var nilG G
	if x > 1 {
		return nilG, ot.ErrInvalidArgument.WithMessage("x must be 0 or 1, got %d", x)
	}
	if popf == nil {
		return nilG, ot.ErrInvalidArgument.WithMessage("popf must not be nil")
	}
	if err := popf.validate(); err != nil {
		return nilG, errs.Wrap(err).WithMessage("invalid popf")
	}

	group := algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](popf.s[0].Structure())
	hx, err := oracle(group, x, popf.s[1-x])
	if err != nil {
		return nilG, errs.Wrap(err).WithMessage("cannot evaluate random oracle H_%d", x)
	}
	y := popf.s[x].Op(hx)
	if y.IsOpIdentity() {
		return nilG, ot.ErrValidation.WithMessage("evaluation is the identity")
	}
	return y, nil
}

// MarshalCBOR encodes the pair (s_0, s_1).
func (popf *MasnyRindalPopf[G, S]) MarshalCBOR() ([]byte, error) {
	if popf == nil {
		return nil, ot.ErrInvalidArgument.WithMessage("popf must not be nil")
	}
	if err := popf.validate(); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid popf")
	}
	out, err := serde.MarshalCBOR(&masnyRindalPopfDTO[G, S]{S: popf.s})
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal popf")
	}
	return out, nil
}

// UnmarshalCBOR decodes a pair (s_0, s_1) received from the other party and
// rejects nil and identity elements; subgroup membership is enforced by the
// element type's own decoder, G being a prime-order group. This is a
// deserialisation trust boundary: a POPF comes from the OT receiver, who may be
// malicious.
func (popf *MasnyRindalPopf[G, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[masnyRindalPopfDTO[G, S]](data)
	if err != nil {
		return errs.Join(ot.ErrSerialisation, errs.Wrap(err)).WithMessage("failed to unmarshal popf")
	}
	decoded := &MasnyRindalPopf[G, S]{s: dto.S}
	if err := decoded.validate(); err != nil {
		return errs.Wrap(err).WithMessage("invalid popf in unmarshalled data")
	}
	*popf = *decoded
	return nil
}

// validate checks that both elements are present and not the identity.
func (popf *MasnyRindalPopf[G, S]) validate() error {
	for i, si := range popf.s {
		if utils.IsNil(si) {
			return ot.ErrInvalidArgument.WithMessage("s_%d must not be nil", i)
		}
		if si.IsOpIdentity() {
			return ot.ErrInvalidArgument.WithMessage("s_%d must not be the identity", i)
		}
	}
	return nil
}

// oracle evaluates H_x(u) as hash-to-group over the label, the bit x and the
// fixed-length encoding of the element u.
func oracle[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](group algebra.PrimeGroup[G, S], x byte, u G) (G, error) {
	var nilG G

	input := slices.Concat(
		[]byte(popfHashLabel),
		[]byte{x},
		u.Bytes(),
	)
	h, err := group.Hash(input)
	if err != nil {
		return nilG, errs.Wrap(err).WithMessage("hash to group failed")
	}
	return h, nil
}
