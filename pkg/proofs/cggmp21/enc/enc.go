package enc

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const (
	// Name identifies the CGGMP21 Paillier encryption-in-range sigma protocol.
	Name sigma.Name = "CGGMP21_PAILLIER_ENCRYPTION_IN_RANGE"

	// challengeBitsLength is a 128-bit challenge domain. This fixes the
	// soundness target for this implementation rather than using the curve-order
	// challenge domain from CGGMP21 Figure 11.
	challengeBitsLength  = 1 << base.ComputationalSecurityLog2Ceil
	challengeBytesLength = challengeBitsLength / 8
	specialSoundness     = 2
)

// Statement is the common input K, a Paillier ciphertext whose plaintext is
// claimed to be in the configured signed range.
type Statement struct {
	k *paillier.Ciphertext
}

type statementDTO struct {
	K *paillier.Ciphertext `cbor:"k"`
}

// NewStatement constructs a Paillier encryption-in-range statement.
func NewStatement(k *paillier.Ciphertext) (*Statement, error) {
	if k == nil || k.Value() == nil {
		return nil, ErrInvalidArgument.WithMessage("K must not be nil")
	}
	return &Statement{k: k}, nil
}

// MarshalCBOR serialises the statement to CBOR format.
func (s *Statement) MarshalCBOR() ([]byte, error) {
	dto := &statementDTO{
		K: s.k,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal statement to CBOR")
	}
	return data, nil
}

// UnmarshalCBOR deserialises the statement from CBOR format.
func (s *Statement) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*statementDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal statement from CBOR")
	}
	if dto == nil {
		return ErrInvalidArgument.WithMessage("statement DTO must not be nil")
	}
	ss, err := NewStatement(dto.K)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid statement data")
	}
	*s = *ss
	return nil
}

// Bytes serialises the statement for transcript binding.
func (s *Statement) Bytes() []byte {
	out := []byte{}
	return sliceutils.AppendLengthPrefixed(out, s.k.Bytes())
}

// Witness is the prover's secret opening (k, rho) for K = Enc(k; rho).
type Witness struct {
	k   *paillier.Plaintext
	rho *paillier.Nonce
}

// NewWitness constructs a Paillier encryption-in-range witness.
func NewWitness(k *paillier.Plaintext, rho *paillier.Nonce) (*Witness, error) {
	if k == nil || rho == nil || k.Value() == nil || rho.Value() == nil {
		return nil, ErrInvalidArgument.WithMessage("k and rho must not be nil")
	}
	return &Witness{k: k, rho: rho}, nil
}

// Commitment is the prover's first message (S, A, C) from CGGMP21 Figure 11.
type Commitment struct {
	s *intcom.Commitment
	a *paillier.Ciphertext
	c *intcom.Commitment
}

type commitmentDTO struct {
	S *intcom.Commitment   `cbor:"S"`
	A *paillier.Ciphertext `cbor:"A"`
	C *intcom.Commitment   `cbor:"C"`
}

// NewCommitment constructs a Paillier encryption-in-range commitment.
func NewCommitment(s *intcom.Commitment, a *paillier.Ciphertext, c *intcom.Commitment) (*Commitment, error) {
	if s == nil || a == nil || c == nil || s.Value() == nil || a.Value() == nil || c.Value() == nil {
		return nil, ErrInvalidArgument.WithMessage("S, A, and C must not be nil")
	}
	return &Commitment{
		s: s,
		a: a,
		c: c,
	}, nil
}

// MarshalCBOR serialises the commitment to CBOR format.
func (c *Commitment) MarshalCBOR() ([]byte, error) {
	dto := &commitmentDTO{
		S: c.s,
		A: c.a,
		C: c.c,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal commitment to CBOR")
	}
	return data, nil
}

// UnmarshalCBOR deserialises the commitment from CBOR format.
func (c *Commitment) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*commitmentDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal commitment from CBOR")
	}
	if dto == nil {
		return ErrInvalidArgument.WithMessage("commitment DTO must not be nil")
	}
	cc, err := NewCommitment(dto.S, dto.A, dto.C)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid commitment data")
	}
	*c = *cc
	return nil
}

// Bytes serialises the commitment for transcript binding.
func (c *Commitment) Bytes() []byte {
	out := []byte{}
	out = sliceutils.AppendLengthPrefixed(out, c.s.Value().Bytes())
	out = sliceutils.AppendLengthPrefixed(out, c.a.Bytes())
	out = sliceutils.AppendLengthPrefixed(out, c.c.Value().Bytes())
	return out
}

// State stores the prover's sampled alpha, mu, r, and gamma between rounds.
type State struct {
	alpha *paillier.Plaintext
	mu    *intcom.Witness
	r     *paillier.Nonce
	gamma *intcom.Witness
}

// NewState constructs the prover state retained between sigma rounds.
func NewState(alpha *paillier.Plaintext, mu *intcom.Witness, r *paillier.Nonce, gamma *intcom.Witness) (*State, error) {
	if alpha == nil || mu == nil || r == nil || gamma == nil ||
		alpha.Value() == nil || mu.Value() == nil || r.Value() == nil || gamma.Value() == nil {

		return nil, ErrInvalidArgument.WithMessage("alpha, mu, r, and gamma must not be nil")
	}
	return &State{
		alpha: alpha,
		mu:    mu,
		r:     r,
		gamma: gamma,
	}, nil
}

// Response is the prover's final message (z1, z2, z3).
type Response struct {
	z1 *paillier.Plaintext
	z2 *paillier.Nonce
	z3 *intcom.Witness
}

type responseDTO struct {
	Z1 *paillier.Plaintext `cbor:"z1"`
	Z2 *paillier.Nonce     `cbor:"z2"`
	Z3 *intcom.Witness     `cbor:"z3"`
}

// NewResponse constructs a Paillier encryption-in-range response.
func NewResponse(z1 *paillier.Plaintext, z2 *paillier.Nonce, z3 *intcom.Witness) (*Response, error) {
	if z1 == nil || z2 == nil || z3 == nil || z1.Value() == nil || z2.Value() == nil || z3.Value() == nil {
		return nil, ErrInvalidArgument.WithMessage("z1, z2, and z3 must not be nil")
	}
	return &Response{
		z1: z1,
		z2: z2,
		z3: z3,
	}, nil
}

// MarshalCBOR serialises the response to CBOR format.
func (r *Response) MarshalCBOR() ([]byte, error) {
	dto := &responseDTO{
		Z1: r.z1,
		Z2: r.z2,
		Z3: r.z3,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal response to CBOR")
	}
	return data, nil
}

// UnmarshalCBOR deserialises the response from CBOR format.
func (r *Response) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*responseDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal response from CBOR")
	}
	if dto == nil {
		return ErrInvalidArgument.WithMessage("response DTO must not be nil")
	}
	rr, err := NewResponse(dto.Z1, dto.Z2, dto.Z3)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid response data")
	}
	*r = *rr
	return nil
}

// Bytes serialises the response for transcript binding.
func (r *Response) Bytes() []byte {
	out := []byte{}
	out = sliceutils.AppendLengthPrefixed(out, r.z1.Bytes())
	out = sliceutils.AppendLengthPrefixed(out, r.z2.Bytes())
	out = sliceutils.AppendLengthPrefixed(out, r.z3.Value().Bytes())
	return out
}
