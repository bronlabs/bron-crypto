package affgstar

import (
	"encoding/binary"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const (
	// Name identifies the CGGMP21 setup-less Paillier affine operation with group commitment proof.
	Name sigma.Name = "CGGMP21_SETUPLESS_PAILLIER_AFFINE_OP_WITH_GROUP_COMMITMENT"
)

// Statement is the public input (N0, N1, C, D, Y, X) for CGGMP21 Figure 27.
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

// NewStatement constructs a setup-less Paillier affine statement.
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

// Witness is the secret input (x, y, rho, rhoY) from CGGMP21 Figure 27.
type Witness struct {
	x    *num.Int
	y    *paillier.Plaintext
	rho  *paillier.Nonce
	rhoY *paillier.Nonce
}

// NewWitness constructs a setup-less Paillier affine witness.
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

// State stores the prover's per-repetition sampled randomness between sigma rounds.
type State struct {
	alpha []*num.Int
	beta  []*num.Int
	r     []*paillier.Nonce
	s     []*paillier.Nonce
}

// NewState constructs the prover state retained between sigma rounds.
func NewState(alpha, beta []*num.Int, r, s []*paillier.Nonce) (*State, error) {
	if err := validateIntSlice("state alpha", alpha); err != nil {
		return nil, err
	}
	if err := validateIntSlice("state beta", beta); err != nil {
		return nil, err
	}
	if err := validateNonceSlice("state r", r); err != nil {
		return nil, err
	}
	if err := validateNonceSlice("state s", s); err != nil {
		return nil, err
	}
	return &State{
		alpha: alpha,
		beta:  beta,
		r:     r,
		s:     s,
	}, nil
}

// Commitment is the prover's first message (A_j, B_j, R_j) for each repetition.
type Commitment[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	a []*paillier.Ciphertext
	b []*paillier.Ciphertext
	r []G
}

type commitmentDTO[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	A []*paillier.Ciphertext `cbor:"a"`
	B []*paillier.Ciphertext `cbor:"b"`
	R []G                    `cbor:"r"`
}

// NewCommitment constructs a setup-less Paillier affine commitment.
func NewCommitment[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	a []*paillier.Ciphertext,
	b []*paillier.Ciphertext,
	r []G,
) (*Commitment[G, B, S], error) {
	if err := validateCiphertextSlice("commitment A", a); err != nil {
		return nil, err
	}
	if err := validateCiphertextSlice("commitment B", b); err != nil {
		return nil, err
	}
	if len(r) != challengeBitsLength {
		return nil, ErrInvalidArgument.WithMessage("commitment R must have length %d", challengeBitsLength)
	}
	for _, elem := range r {
		if utils.IsNil(elem) {
			return nil, ErrInvalidArgument.WithMessage("commitment R values must not be nil")
		}
	}
	return &Commitment[G, B, S]{
		a: a,
		b: b,
		r: r,
	}, nil
}

// MarshalCBOR serialises the commitment to CBOR format.
func (c *Commitment[G, B, S]) MarshalCBOR() ([]byte, error) {
	dto := &commitmentDTO[G, B, S]{
		A: c.a,
		B: c.b,
		R: c.r,
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
	commitment, err := NewCommitment(dto.A, dto.B, dto.R)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid commitment data")
	}
	*c = *commitment
	return nil
}

// Bytes serialises the commitment for transcript binding.
func (c *Commitment[G, B, S]) Bytes() []byte {
	out := binary.LittleEndian.AppendUint64(nil, uint64(len(c.a)))
	for i := range c.a {
		out = sliceutils.AppendLengthPrefixed(out, c.a[i].Bytes())
		out = sliceutils.AppendLengthPrefixed(out, c.b[i].Bytes())
		out = sliceutils.AppendLengthPrefixed(out, c.r[i].Bytes())
	}
	return out
}

// Response is the prover's final message (z_j, z'_j, w_j, lambda_j) for each repetition.
type Response struct {
	z      []*num.Int
	zPrime []*num.Int
	w      []*paillier.Nonce
	lambda []*paillier.Nonce
}

type responseDTO struct {
	Z      []*num.Int        `cbor:"z"`
	ZPrime []*num.Int        `cbor:"zPrime"`
	W      []*paillier.Nonce `cbor:"w"`
	Lambda []*paillier.Nonce `cbor:"lambda"`
}

// NewResponse constructs a setup-less Paillier affine response.
func NewResponse(z, zPrime []*num.Int, w, lambda []*paillier.Nonce) (*Response, error) {
	if err := validateIntSlice("response z", z); err != nil {
		return nil, err
	}
	if err := validateIntSlice("response zPrime", zPrime); err != nil {
		return nil, err
	}
	if err := validateNonceSlice("response w", w); err != nil {
		return nil, err
	}
	if err := validateNonceSlice("response lambda", lambda); err != nil {
		return nil, err
	}
	return &Response{
		z:      z,
		zPrime: zPrime,
		w:      w,
		lambda: lambda,
	}, nil
}

// MarshalCBOR serialises the response to CBOR format.
func (r *Response) MarshalCBOR() ([]byte, error) {
	dto := &responseDTO{
		Z:      r.z,
		ZPrime: r.zPrime,
		W:      r.w,
		Lambda: r.lambda,
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
	response, err := NewResponse(dto.Z, dto.ZPrime, dto.W, dto.Lambda)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid response data")
	}
	*r = *response
	return nil
}

// Bytes serialises the response for transcript binding.
func (r *Response) Bytes() []byte {
	out := binary.LittleEndian.AppendUint64(nil, uint64(len(r.z)))
	for i := range r.z {
		out = sliceutils.AppendLengthPrefixed(out, r.z[i].Bytes())
		out = sliceutils.AppendLengthPrefixed(out, r.zPrime[i].Bytes())
		out = sliceutils.AppendLengthPrefixed(out, r.w[i].Bytes())
		out = sliceutils.AppendLengthPrefixed(out, r.lambda[i].Bytes())
	}
	return out
}
