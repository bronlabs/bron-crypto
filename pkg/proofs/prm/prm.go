package prm

import (
	"encoding/binary"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const (
	// Name identifies the Pedersen parameters proof.
	Name sigma.Name = "CGGMP21_PedersenParameters"

	challengeBytes = base.ComputationalSecurityBytesCeil
	m              = challengeBytes * 8
)

// Statement is the public statement for the proof.
//
// The public input in Figure 13 is the Pedersen parameter tuple (N, s, t).
// This implementation carries it as an intcom commitment key.
type Statement struct {
	commitmentKey *intcom.CommitmentKey
}

type statementDTO struct {
	CommitmentKey *intcom.CommitmentKey `cbor:"commitmentKey"`
}

// NewStatement constructs a Pedersen parameters statement.
func NewStatement(commitmentKey *intcom.CommitmentKey) (*Statement, error) {
	if err := validateCommitmentKey(commitmentKey); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid statement")
	}
	return &Statement{commitmentKey: commitmentKey}, nil
}

// MarshalCBOR serialises the statement to CBOR format.
func (s *Statement) MarshalCBOR() ([]byte, error) {
	dto := &statementDTO{
		CommitmentKey: s.commitmentKey,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal statement to CBOR")
	}
	return out, nil
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
	statement, err := NewStatement(dto.CommitmentKey)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid statement data")
	}
	*s = *statement
	return nil
}

// Bytes serialises the statement for transcript binding.
func (s *Statement) Bytes() []byte {
	ss := s.commitmentKey.S()
	t := s.commitmentKey.T()

	out := []byte{}
	out = sliceutils.AppendLengthPrefixed(out, ss.Group().Modulus().Bytes())
	out = sliceutils.AppendLengthPrefixed(out, ss.Bytes())
	out = sliceutils.AppendLengthPrefixed(out, t.Bytes())
	return out
}

// Witness contains the Pedersen parameters trapdoor.
type Witness struct {
	trapdoorKey *intcom.TrapdoorKey
}

// NewWitness constructs a Pedersen parameters witness.
func NewWitness(trapdoorKey *intcom.TrapdoorKey) (*Witness, error) {
	if trapdoorKey == nil {
		return nil, ErrInvalidArgument.WithMessage("trapdoorKey must not be nil")
	}
	if trapdoorKey.Group() == nil {
		return nil, ErrInvalidArgument.WithMessage("trapdoor group must not be nil")
	}
	if trapdoorKey.Lambda() == nil {
		return nil, ErrInvalidArgument.WithMessage("lambda must not be nil")
	}
	if trapdoorKey.S() == nil || trapdoorKey.T() == nil {
		return nil, ErrInvalidArgument.WithMessage("trapdoor public parameters must not be nil")
	}
	return &Witness{trapdoorKey: trapdoorKey}, nil
}

// Commitment holds the prover's first-round values.
type Commitment struct {
	a [m]*znstar.RSAGroupElementUnknownOrder
}

type commitmentDTO struct {
	A [m]*znstar.RSAGroupElementUnknownOrder `cbor:"a"`
}

// NewCommitment constructs a Pedersen parameters commitment.
func NewCommitment(a ...*znstar.RSAGroupElementUnknownOrder) (*Commitment, error) {
	if len(a) != m {
		return nil, ErrInvalidArgument.WithMessage("commitment must contain %d elements", m)
	}
	out := &Commitment{}
	for i, item := range a {
		if item == nil {
			return nil, ErrInvalidArgument.WithMessage("commitment element %d must not be nil", i)
		}
		out.a[i] = item
	}
	return out, nil
}

// MarshalCBOR serialises the commitment to CBOR format.
func (c *Commitment) MarshalCBOR() ([]byte, error) {
	dto := &commitmentDTO{
		A: c.a,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal commitment to CBOR")
	}
	return out, nil
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
	commitment, err := NewCommitment(dto.A[:]...)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid commitment data")
	}
	*c = *commitment
	return nil
}

// Bytes serialises the commitment for transcript binding.
func (c *Commitment) Bytes() []byte {
	out := binary.LittleEndian.AppendUint64(nil, uint64(len(c.a)))
	for _, a := range &c.a {
		out = sliceutils.AppendLengthPrefixed(out, a.Bytes())
	}
	return out
}

// State stores the prover's internal randomness between rounds.
type State struct {
	alpha [m]*num.Uint
}

type stateDTO struct {
	Alpha [m]*num.Uint `cbor:"alpha"`
}

// NewState constructs prover state retained between sigma rounds.
func NewState(alpha ...*num.Uint) (*State, error) {
	if len(alpha) != m {
		return nil, ErrInvalidArgument.WithMessage("state must contain %d alpha values", m)
	}
	out := &State{}
	for i, item := range alpha {
		if item == nil {
			return nil, ErrInvalidArgument.WithMessage("state alpha %d must not be nil", i)
		}
		out.alpha[i] = item
	}
	return out, nil
}

// MarshalCBOR serialises the state to CBOR format. The output contains prover
// state and must not be sent to the verifier.
func (s *State) MarshalCBOR() ([]byte, error) {
	dto := &stateDTO{
		Alpha: s.alpha,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal state to CBOR")
	}
	return out, nil
}

// UnmarshalCBOR deserialises the state from CBOR format.
func (s *State) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*stateDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal state from CBOR")
	}
	if dto == nil {
		return ErrInvalidArgument.WithMessage("state DTO must not be nil")
	}
	state, err := NewState(dto.Alpha[:]...)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid state data")
	}
	*s = *state
	return nil
}

// Response holds the prover responses.
type Response struct {
	z [m]*num.Int
}

type responseDTO struct {
	Z [m]*num.Int `cbor:"z"`
}

// NewResponse constructs a Pedersen parameters response.
func NewResponse(z ...*num.Int) (*Response, error) {
	if len(z) != m {
		return nil, ErrInvalidArgument.WithMessage("response must contain %d values", m)
	}
	out := &Response{}
	for i, item := range z {
		if item == nil {
			return nil, ErrInvalidArgument.WithMessage("response z %d must not be nil", i)
		}
		out.z[i] = item
	}
	return out, nil
}

// MarshalCBOR serialises the response to CBOR format.
func (r *Response) MarshalCBOR() ([]byte, error) {
	dto := &responseDTO{
		Z: r.z,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal response to CBOR")
	}
	return out, nil
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
	response, err := NewResponse(dto.Z[:]...)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid response data")
	}
	*r = *response
	return nil
}

// Bytes serialises the response for transcript binding.
func (r *Response) Bytes() []byte {
	out := binary.LittleEndian.AppendUint64(nil, uint64(len(r.z)))
	for _, z := range &r.z {
		out = sliceutils.AppendLengthPrefixed(out, z.TwosComplementBytesBE())
	}
	return out
}
