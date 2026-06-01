package fac

import (
	"encoding/binary"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const (
	// Name identifies the CGGMP21 small-factor proof.
	Name sigma.Name = "CGGMP21_SMALL_FACTOR"
)

// Statement is the public input for the small-factor proof.
type Statement struct {
	publicKey *paillier.PublicKey
}

type statementDTO struct {
	PublicKey *paillier.PublicKey `cbor:"publicKey"`
}

// NewStatement constructs a small-factor statement.
func NewStatement(publicKey *paillier.PublicKey) (*Statement, error) {
	if err := validatePublicKey(publicKey); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid statement")
	}
	return &Statement{publicKey: publicKey}, nil
}

// MarshalCBOR serialises the statement to CBOR format.
func (s *Statement) MarshalCBOR() ([]byte, error) {
	dto := &statementDTO{
		PublicKey: s.publicKey,
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

// Witness contains the secret Paillier key for the statement public key.
type Witness struct {
	secretKey *paillier.SecretKey
}

// NewWitness constructs a small-factor witness from a Paillier secret key.
func NewWitness(secretKey *paillier.SecretKey) (*Witness, error) {
	if secretKey == nil || secretKey.Group() == nil {
		return nil, ErrInvalidArgument.WithMessage("secret key must not be nil")
	}
	return &Witness{secretKey: secretKey}, nil
}

// Commitment holds the prover's first-round values (P, Q, A, B, T).
type Commitment struct {
	p *intcom.Commitment
	q *intcom.Commitment
	a *intcom.Commitment
	b *intcom.Commitment
	t *intcom.Commitment
}

type commitmentDTO struct {
	P *intcom.Commitment `cbor:"p"`
	Q *intcom.Commitment `cbor:"q"`
	A *intcom.Commitment `cbor:"a"`
	B *intcom.Commitment `cbor:"b"`
	T *intcom.Commitment `cbor:"t"`
}

// NewCommitment constructs a small-factor commitment.
func NewCommitment(
	p *intcom.Commitment,
	q *intcom.Commitment,
	a *intcom.Commitment,
	b *intcom.Commitment,
	t *intcom.Commitment,
) (*Commitment, error) {
	for _, elem := range []*intcom.Commitment{p, q, a, b, t} {
		if elem == nil || elem.Value() == nil {
			return nil, ErrInvalidArgument.WithMessage("commitment values must not be nil")
		}
	}
	return &Commitment{
		p: p,
		q: q,
		a: a,
		b: b,
		t: t,
	}, nil
}

// MarshalCBOR serialises the commitment to CBOR format.
func (c *Commitment) MarshalCBOR() ([]byte, error) {
	dto := &commitmentDTO{
		P: c.p,
		Q: c.q,
		A: c.a,
		B: c.b,
		T: c.t,
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
	commitment, err := NewCommitment(dto.P, dto.Q, dto.A, dto.B, dto.T)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid commitment data")
	}
	*c = *commitment
	return nil
}

// Bytes serialises the commitment for transcript binding.
func (c *Commitment) Bytes() []byte {
	out := binary.LittleEndian.AppendUint64(nil, 5)
	for _, elem := range []*intcom.Commitment{c.p, c.q, c.a, c.b, c.t} {
		out = sliceutils.AppendLengthPrefixed(out, elem.Value().Bytes())
	}
	return out
}

// Equal reports whether two commitments contain the same group elements.
func (c *Commitment) Equal(rhs *Commitment) bool {
	if c == nil || rhs == nil {
		return c == rhs
	}

	left := []*intcom.Commitment{c.p, c.q, c.a, c.b, c.t}
	right := []*intcom.Commitment{rhs.p, rhs.q, rhs.a, rhs.b, rhs.t}
	for i := range left {
		if !left[i].Equal(right[i]) {
			return false
		}
	}
	return true
}

// State stores the prover's internal randomness between rounds.
type State struct {
	alpha *num.Int
	beta  *num.Int
	mu    *num.Int
	nu    *num.Int
	r     *num.Int
	x     *num.Int
	y     *num.Int
}

// NewState constructs the prover state retained between sigma rounds.
func NewState(alpha, beta, mu, nu, r, x, y *num.Int) (*State, error) {
	for _, elem := range []*num.Int{alpha, beta, mu, nu, r, x, y} {
		if elem == nil {
			return nil, ErrInvalidArgument.WithMessage("state values must not be nil")
		}
	}
	return &State{
		alpha: alpha,
		beta:  beta,
		mu:    mu,
		nu:    nu,
		r:     r,
		x:     x,
		y:     y,
	}, nil
}

// Response holds the prover response (z1, z2, w1, w2, v).
type Response struct {
	z1 *num.Int
	z2 *num.Int
	w1 *num.Int
	w2 *num.Int
	v  *num.Int
}

type responseDTO struct {
	Z1 *num.Int `cbor:"z1"`
	Z2 *num.Int `cbor:"z2"`
	W1 *num.Int `cbor:"w1"`
	W2 *num.Int `cbor:"w2"`
	V  *num.Int `cbor:"v"`
}

// NewResponse constructs a small-factor response.
func NewResponse(z1, z2, w1, w2, v *num.Int) (*Response, error) {
	for _, elem := range []*num.Int{z1, z2, w1, w2, v} {
		if elem == nil {
			return nil, ErrInvalidArgument.WithMessage("response values must not be nil")
		}
	}
	return &Response{
		z1: z1,
		z2: z2,
		w1: w1,
		w2: w2,
		v:  v,
	}, nil
}

// MarshalCBOR serialises the response to CBOR format.
func (r *Response) MarshalCBOR() ([]byte, error) {
	dto := &responseDTO{
		Z1: r.z1,
		Z2: r.z2,
		W1: r.w1,
		W2: r.w2,
		V:  r.v,
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
	response, err := NewResponse(dto.Z1, dto.Z2, dto.W1, dto.W2, dto.V)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid response data")
	}
	*r = *response
	return nil
}

// Bytes serialises the response for transcript binding.
func (r *Response) Bytes() []byte {
	out := binary.LittleEndian.AppendUint64(nil, 5)
	for _, z := range []*num.Int{r.z1, r.z2, r.w1, r.w2, r.v} {
		out = sliceutils.AppendLengthPrefixed(out, z.Bytes())
	}
	return out
}
