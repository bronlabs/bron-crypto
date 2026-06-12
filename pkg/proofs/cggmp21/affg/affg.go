package affg

import (
	"encoding/binary"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const (
	// Name identifies the CGGMP21 Paillier affine operation with group commitment proof.
	Name sigma.Name = "CGGMP21_PAILLIER_AFFINE_OP_WITH_COMMITMENT"
)

// Statement is the public input (N0, N1, C, D, Y, X) for CGGMP21 Figure 25.
type Statement[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	n0 *paillier.PublicKey
	n1 *paillier.PublicKey
	c  *paillier.Ciphertext
	d  *paillier.Ciphertext
	y  *paillier.Ciphertext
	x  G
}

type statementDTO[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	N0 *paillier.PublicKey  `cbor:"n0"`
	N1 *paillier.PublicKey  `cbor:"n1"`
	C  *paillier.Ciphertext `cbor:"c"`
	D  *paillier.Ciphertext `cbor:"d"`
	Y  *paillier.Ciphertext `cbor:"y"`
	X  G                    `cbor:"x"`
}

// NewStatement constructs a Paillier affine statement.
func NewStatement[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	n0 *paillier.PublicKey,
	n1 *paillier.PublicKey,
	c *paillier.Ciphertext,
	d *paillier.Ciphertext,
	y *paillier.Ciphertext,
	x G,
) (*Statement[G, B, S], error) {
	if n0 == nil || n1 == nil || c == nil || d == nil || y == nil || utils.IsNil(x) {
		return nil, ErrInvalidArgument.WithMessage("statement values must not be nil")
	}
	return &Statement[G, B, S]{
		n0: n0,
		n1: n1,
		c:  c,
		d:  d,
		y:  y,
		x:  x,
	}, nil
}

// MarshalCBOR serialises the statement to CBOR format.
func (s *Statement[G, B, S]) MarshalCBOR() ([]byte, error) {
	dto := &statementDTO[G, B, S]{
		N0: s.n0,
		N1: s.n1,
		C:  s.c,
		D:  s.d,
		Y:  s.y,
		X:  s.x,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal statement to CBOR")
	}
	return out, nil
}

// UnmarshalCBOR deserialises the statement from CBOR format.
func (s *Statement[G, B, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*statementDTO[G, B, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal statement from CBOR")
	}
	if dto == nil {
		return ErrInvalidArgument.WithMessage("statement DTO must not be nil")
	}
	statement, err := NewStatement(dto.N0, dto.N1, dto.C, dto.D, dto.Y, dto.X)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid statement data")
	}
	*s = *statement
	return nil
}

// Bytes serialises the statement for transcript binding.
func (s *Statement[G, B, S]) Bytes() []byte {
	out := binary.LittleEndian.AppendUint64(nil, 6)
	out = sliceutils.AppendLengthPrefixed(out, s.n0.Group().N().Bytes())
	out = sliceutils.AppendLengthPrefixed(out, s.n1.Group().N().Bytes())
	out = sliceutils.AppendLengthPrefixed(out, s.c.Bytes())
	out = sliceutils.AppendLengthPrefixed(out, s.d.Bytes())
	out = sliceutils.AppendLengthPrefixed(out, s.y.Bytes())
	out = sliceutils.AppendLengthPrefixed(out, s.x.Bytes())
	return out
}

// Witness is the secret input (x, y, rho, rhoY) from CGGMP21 Figure 25.
type Witness struct {
	x    *num.Int
	y    *paillier.Plaintext
	rho  *paillier.Nonce
	rhoY *paillier.Nonce
}

// NewWitness constructs a Paillier affine witness.
func NewWitness(x *num.Int, y *paillier.Plaintext, rho, rhoY *paillier.Nonce) (*Witness, error) {
	if x == nil || y == nil || rho == nil || rhoY == nil {
		return nil, ErrInvalidArgument.WithMessage("witness values must not be nil")
	}
	return &Witness{
		x:    x.Clone(),
		y:    y,
		rho:  rho,
		rhoY: rhoY,
	}, nil
}

// State stores the prover's sampled randomness between sigma rounds.
type State struct {
	alpha *num.Int
	beta  *num.Int
	gamma *num.Int
	m     *num.Int
	delta *num.Int
	mu    *num.Int
	r     *paillier.Nonce
	ry    *paillier.Nonce
}

// NewState constructs the prover state retained between sigma rounds.
func NewState(alpha, beta, gamma, m, delta, mu *num.Int, r, ry *paillier.Nonce) (*State, error) {
	for _, elem := range []*num.Int{alpha, beta, gamma, m, delta, mu} {
		if elem == nil {
			return nil, ErrInvalidArgument.WithMessage("state integers must not be nil")
		}
	}
	if r == nil || ry == nil {
		return nil, ErrInvalidArgument.WithMessage("state nonces must not be nil")
	}
	return &State{
		alpha: alpha,
		beta:  beta,
		gamma: gamma,
		m:     m,
		delta: delta,
		mu:    mu,
		r:     r,
		ry:    ry,
	}, nil
}

// Commitment is the prover's first message (A, Bx, By, E, F, S, T).
type Commitment[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	a  *paillier.Ciphertext
	bx G
	by *paillier.Ciphertext
	e  *intcom.Commitment
	f  *intcom.Commitment
	s  *intcom.Commitment
	t  *intcom.Commitment
}

type commitmentDTO[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	A  *paillier.Ciphertext `cbor:"a"`
	BX G                    `cbor:"bx"`
	BY *paillier.Ciphertext `cbor:"by"`
	E  *intcom.Commitment   `cbor:"e"`
	F  *intcom.Commitment   `cbor:"f"`
	S  *intcom.Commitment   `cbor:"s"`
	T  *intcom.Commitment   `cbor:"t"`
}

// NewCommitment constructs a Paillier affine commitment.
func NewCommitment[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	a *paillier.Ciphertext,
	bx G,
	by *paillier.Ciphertext,
	e *intcom.Commitment,
	f *intcom.Commitment,
	s *intcom.Commitment,
	t *intcom.Commitment,
) (*Commitment[G, B, S], error) {
	if a == nil || by == nil || e == nil || f == nil || s == nil || t == nil || utils.IsNil(bx) {
		return nil, ErrInvalidArgument.WithMessage("commitment values must not be nil")
	}
	return &Commitment[G, B, S]{
		a:  a,
		bx: bx,
		by: by,
		e:  e,
		f:  f,
		s:  s,
		t:  t,
	}, nil
}

// MarshalCBOR serialises the commitment to CBOR format.
func (c *Commitment[G, B, S]) MarshalCBOR() ([]byte, error) {
	dto := &commitmentDTO[G, B, S]{
		A:  c.a,
		BX: c.bx,
		BY: c.by,
		E:  c.e,
		F:  c.f,
		S:  c.s,
		T:  c.t,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal commitment to CBOR")
	}
	return out, nil
}

// UnmarshalCBOR deserialises the commitment from CBOR format.
func (c *Commitment[G, B, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*commitmentDTO[G, B, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal commitment from CBOR")
	}
	if dto == nil {
		return ErrInvalidArgument.WithMessage("commitment DTO must not be nil")
	}
	commitment, err := NewCommitment(dto.A, dto.BX, dto.BY, dto.E, dto.F, dto.S, dto.T)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid commitment data")
	}
	*c = *commitment
	return nil
}

// Bytes serialises the commitment for transcript binding.
func (c *Commitment[G, B, S]) Bytes() []byte {
	out := binary.LittleEndian.AppendUint64(nil, 7)
	out = sliceutils.AppendLengthPrefixed(out, c.a.Bytes())
	out = sliceutils.AppendLengthPrefixed(out, c.bx.Bytes())
	out = sliceutils.AppendLengthPrefixed(out, c.by.Bytes())
	out = sliceutils.AppendLengthPrefixed(out, c.e.Value().Bytes())
	out = sliceutils.AppendLengthPrefixed(out, c.f.Value().Bytes())
	out = sliceutils.AppendLengthPrefixed(out, c.s.Value().Bytes())
	out = sliceutils.AppendLengthPrefixed(out, c.t.Value().Bytes())
	return out
}

// Response is the prover's final message (z1, z2, z3, z4, w, wy).
type Response struct {
	z1 *num.Int
	z2 *num.Int
	z3 *num.Int
	z4 *num.Int
	w  *paillier.Nonce
	wy *paillier.Nonce
}

type responseDTO struct {
	Z1 *num.Int        `cbor:"z1"`
	Z2 *num.Int        `cbor:"z2"`
	Z3 *num.Int        `cbor:"z3"`
	Z4 *num.Int        `cbor:"z4"`
	W  *paillier.Nonce `cbor:"w"`
	WY *paillier.Nonce `cbor:"wy"`
}

// NewResponse constructs a Paillier affine response.
func NewResponse(z1, z2, z3, z4 *num.Int, w, wy *paillier.Nonce) (*Response, error) {
	for _, elem := range []*num.Int{z1, z2, z3, z4} {
		if elem == nil {
			return nil, ErrInvalidArgument.WithMessage("response integers must not be nil")
		}
	}
	if w == nil || wy == nil {
		return nil, ErrInvalidArgument.WithMessage("response nonces must not be nil")
	}
	return &Response{
		z1: z1,
		z2: z2,
		z3: z3,
		z4: z4,
		w:  w,
		wy: wy,
	}, nil
}

// MarshalCBOR serialises the response to CBOR format.
func (r *Response) MarshalCBOR() ([]byte, error) {
	dto := &responseDTO{
		Z1: r.z1,
		Z2: r.z2,
		Z3: r.z3,
		Z4: r.z4,
		W:  r.w,
		WY: r.wy,
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
	response, err := NewResponse(dto.Z1, dto.Z2, dto.Z3, dto.Z4, dto.W, dto.WY)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid response data")
	}
	*r = *response
	return nil
}

// Bytes serialises the response for transcript binding.
func (r *Response) Bytes() []byte {
	out := binary.LittleEndian.AppendUint64(nil, 6)
	for _, z := range []*num.Int{r.z1, r.z2, r.z3, r.z4} {
		out = sliceutils.AppendLengthPrefixed(out, z.Bytes())
	}
	out = sliceutils.AppendLengthPrefixed(out, r.w.Bytes())
	out = sliceutils.AppendLengthPrefixed(out, r.wy.Bytes())
	return out
}
