package blummod

import (
	"encoding/binary"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
)

const (
	// Name identifies the Paillier-Blum modulus proof.
	Name = "CGGMP21_PaillierBlumModulus"

	challengeBytes      = base.CollisionResistanceBytesCeil
	challengeBlockBytes = base.CollisionResistanceBytesCeil
	m                   = 129
)

// Statement is the public statement for the proof.
//
// The public input in Figure 12 is the Paillier modulus N. This implementation
// carries N as a Paillier public key so callers can reuse the repository's
// Paillier key and group APIs.
type Statement struct {
	publicKey *paillier.PublicKey
}

type statementDTO struct {
	PublicKey *paillier.PublicKey `cbor:"publicKey"`
}

// NewStatement constructs a Paillier-Blum modulus statement.
func NewStatement(publicKey *paillier.PublicKey) (*Statement, error) {
	if publicKey == nil || publicKey.Group() == nil {
		return nil, ErrInvalidArgument.WithMessage("publicKey must not be nil")
	}
	if err := validatePublicModulus(publicKey.Group().N()); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid Paillier modulus")
	}
	return &Statement{publicKey: publicKey}, nil
}

// MarshalCBOR serialises the statement to CBOR format.
func (s *Statement) MarshalCBOR() ([]byte, error) {
	dto := &statementDTO{
		PublicKey: s.publicKey,
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
	statement, err := NewStatement(dto.PublicKey)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid statement data")
	}
	*s = *statement
	return nil
}

// Bytes serialises the statement for transcript binding.
func (s *Statement) Bytes() []byte {
	out := []byte{}
	out = sliceutils.AppendLengthPrefixed(out, s.publicKey.Group().N().Bytes())
	return out
}

// Witness contains the Paillier trapdoor used by the prover.
//
// NewWitness does not check that the trapdoor is Paillier-Blum; a prover with
// a wrong trapdoor is allowed to attempt the proof and fail during response
// generation.
type Witness struct {
	secretKey *paillier.SecretKey
}

// NewWitness constructs a Paillier modulus witness.
func NewWitness(secretKey *paillier.SecretKey) (*Witness, error) {
	if secretKey == nil || secretKey.Group() == nil {
		return nil, ErrInvalidArgument.WithMessage("secretKey must not be nil")
	}
	return &Witness{secretKey: secretKey}, nil
}

// Commitment holds the prover's first-round value w.
type Commitment struct {
	w *paillier.Nonce
}

type commitmentDTO struct {
	W *paillier.Nonce `cbor:"w"`
}

// NewCommitment constructs a Paillier-Blum modulus commitment.
func NewCommitment(w *paillier.Nonce) (*Commitment, error) {
	if w == nil || w.Value() == nil {
		return nil, ErrInvalidArgument.WithMessage("w must not be nil")
	}
	return &Commitment{w: w}, nil
}

// MarshalCBOR serialises the commitment to CBOR format.
func (c *Commitment) MarshalCBOR() ([]byte, error) {
	dto := &commitmentDTO{
		W: c.w,
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
	commitment, err := NewCommitment(dto.W)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid commitment data")
	}
	*c = *commitment
	return nil
}

// Bytes serialises the commitment for transcript binding.
func (c *Commitment) Bytes() []byte {
	out := []byte{}
	out = sliceutils.AppendLengthPrefixed(out, c.w.Bytes())
	return out
}

// State stores the prover's internal state between rounds.
type State struct {
	s *znstar.RSAGroupElementKnownOrder
}

type stateDTO struct {
	S *znstar.RSAGroupElementKnownOrder `cbor:"s"`
}

// NewState constructs the prover state retained between sigma rounds.
func NewState(s *znstar.RSAGroupElementKnownOrder) (*State, error) {
	if s == nil {
		return nil, ErrInvalidArgument.WithMessage("s must not be nil")
	}
	return &State{s: s}, nil
}

// MarshalCBOR serialises the state to CBOR format. The output contains prover
// state and must not be sent to the verifier.
func (s *State) MarshalCBOR() ([]byte, error) {
	dto := &stateDTO{
		S: s.s,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal state to CBOR")
	}
	return data, nil
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
	state, err := NewState(dto.S)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid state data")
	}
	*s = *state
	return nil
}

// ResponseItem holds the answer for one verifier challenge element.
type ResponseItem struct {
	x *paillier.Nonce
	a uint8
	b uint8
	z *paillier.Nonce
}

type responseItemDTO struct {
	X *paillier.Nonce `cbor:"x"`
	A uint8           `cbor:"a"`
	B uint8           `cbor:"b"`
	Z *paillier.Nonce `cbor:"z"`
}

// NewResponseItem constructs one Paillier-Blum modulus response item.
func NewResponseItem(x *paillier.Nonce, a, b uint8, z *paillier.Nonce) (*ResponseItem, error) {
	if x == nil || z == nil || x.Value() == nil || z.Value() == nil {
		return nil, ErrInvalidArgument.WithMessage("x and z must not be nil")
	}
	if a > 1 || b > 1 {
		return nil, ErrInvalidArgument.WithMessage("a and b must be bits")
	}
	return &ResponseItem{
		x: x,
		a: a,
		b: b,
		z: z,
	}, nil
}

// MarshalCBOR serialises the response item to CBOR format.
func (r *ResponseItem) MarshalCBOR() ([]byte, error) {
	dto := &responseItemDTO{
		X: r.x,
		A: r.a,
		B: r.b,
		Z: r.z,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal response item to CBOR")
	}
	return data, nil
}

// UnmarshalCBOR deserialises the response item from CBOR format.
func (r *ResponseItem) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*responseItemDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal response item from CBOR")
	}
	if dto == nil {
		return ErrInvalidArgument.WithMessage("response item DTO must not be nil")
	}
	item, err := NewResponseItem(dto.X, dto.A, dto.B, dto.Z)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid response item data")
	}
	*r = *item
	return nil
}

// Response is the prover's third-round message.
type Response struct {
	items [m]*ResponseItem
}

type responseDTO struct {
	Items [m]*ResponseItem `cbor:"items"`
}

// NewResponse constructs a Paillier-Blum modulus response.
func NewResponse(items ...*ResponseItem) (*Response, error) {
	if len(items) != m {
		return nil, ErrInvalidArgument.WithMessage("response must contain %d items", m)
	}
	out := &Response{}
	for i, item := range items {
		if item == nil {
			return nil, ErrInvalidArgument.WithMessage("response item %d must not be nil", i)
		}
		out.items[i] = item
	}
	return out, nil
}

// MarshalCBOR serialises the response to CBOR format.
func (r *Response) MarshalCBOR() ([]byte, error) {
	dto := &responseDTO{
		Items: r.items,
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
	response, err := NewResponse(dto.Items[:]...)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid response data")
	}
	*r = *response
	return nil
}

// Bytes serialises the response for transcript binding.
func (r *Response) Bytes() []byte {
	out := binary.LittleEndian.AppendUint64(nil, uint64(len(r.items)))
	for _, item := range &r.items {
		out = sliceutils.AppendLengthPrefixed(out, item.x.Bytes())
		out = append(out, item.a, item.b)
		out = sliceutils.AppendLengthPrefixed(out, item.z.Bytes())
	}
	return out
}
