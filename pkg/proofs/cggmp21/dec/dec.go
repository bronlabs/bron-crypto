package dec

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
	// Name identifies the CGGMP21 Paillier special decryption in the exponent proof.
	Name sigma.Name = "CGGMP21_PAILLIER_SPECIAL_DECRYPTION_IN_EXPONENT"
)

// Statement is the public input (N0, K, X, D, S) for CGGMP21 Figure 28.
type Statement[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	n0 *paillier.PublicKey
	k  *paillier.Ciphertext
	x  G
	d  *paillier.Ciphertext
	s  G
}

type statementDTO[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	N0 *paillier.PublicKey  `cbor:"n0"`
	K  *paillier.Ciphertext `cbor:"k"`
	X  G                    `cbor:"x"`
	D  *paillier.Ciphertext `cbor:"d"`
	S  G                    `cbor:"s"`
}

// NewStatement constructs a Paillier special decryption-in-the-exponent statement.
func NewStatement[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	n0 *paillier.PublicKey,
	k *paillier.Ciphertext,
	x G,
	d *paillier.Ciphertext,
	s G,
) (*Statement[G, B, S], error) {
	if n0 == nil || k == nil || d == nil || utils.IsNil(x) || utils.IsNil(s) {
		return nil, ErrInvalidArgument.WithMessage("statement values must not be nil")
	}
	return &Statement[G, B, S]{
		n0: n0,
		k:  k,
		x:  x,
		d:  d,
		s:  s,
	}, nil
}

// MarshalCBOR serialises the statement to CBOR format.
func (s *Statement[G, B, S]) MarshalCBOR() ([]byte, error) {
	dto := &statementDTO[G, B, S]{
		N0: s.n0,
		K:  s.k,
		X:  s.x,
		D:  s.d,
		S:  s.s,
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
	statement, err := NewStatement(dto.N0, dto.K, dto.X, dto.D, dto.S)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid statement data")
	}
	*s = *statement
	return nil
}

// Bytes serialises the statement for transcript binding.
func (s *Statement[G, B, S]) Bytes() []byte {
	out := binary.LittleEndian.AppendUint64(nil, 5)
	out = sliceutils.AppendLengthPrefixed(out, s.n0.Group().N().Bytes())
	out = sliceutils.AppendLengthPrefixed(out, s.k.Bytes())
	out = sliceutils.AppendLengthPrefixed(out, s.x.Bytes())
	out = sliceutils.AppendLengthPrefixed(out, s.d.Bytes())
	out = sliceutils.AppendLengthPrefixed(out, s.s.Bytes())
	return out
}

// Witness is the secret input (x, y, rho) from CGGMP21 Figure 28.
type Witness struct {
	x   *num.Int
	y   *num.Int
	rho *paillier.Nonce
}

// NewWitness constructs a Paillier special decryption-in-the-exponent witness.
func NewWitness(x, y *num.Int, rho *paillier.Nonce) (*Witness, error) {
	if x == nil || y == nil || rho == nil {
		return nil, ErrInvalidArgument.WithMessage("witness values must not be nil")
	}
	return &Witness{
		x:   x.Clone(),
		y:   y.Clone(),
		rho: rho,
	}, nil
}

// State stores the prover's per-repetition sampled randomness between sigma rounds.
type State struct {
	alpha []*num.Int
	beta  []*num.Int
	r     []*paillier.Nonce
}

// NewState constructs the prover state retained between sigma rounds.
func NewState(alpha, beta []*num.Int, r []*paillier.Nonce) (*State, error) {
	if err := validateIntSlice("state alpha", alpha); err != nil {
		return nil, err
	}
	if err := validateIntSlice("state beta", beta); err != nil {
		return nil, err
	}
	if err := validateNonceSlice("state r", r); err != nil {
		return nil, err
	}
	return &State{
		alpha: alpha,
		beta:  beta,
		r:     r,
	}, nil
}

// Commitment is the prover's first message (A_j, B_j, C_j) for each repetition.
type Commitment[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	a []*paillier.Ciphertext
	b []G
	c []G
}

type commitmentDTO[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	A []*paillier.Ciphertext `cbor:"a"`
	B []G                    `cbor:"b"`
	C []G                    `cbor:"c"`
}

// NewCommitment constructs a Paillier special decryption-in-the-exponent commitment.
func NewCommitment[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	a []*paillier.Ciphertext,
	b []G,
	c []G,
) (*Commitment[G, B, S], error) {
	if err := validateCiphertextSlice("commitment A", a); err != nil {
		return nil, err
	}
	if len(b) != challengeBitsLength || len(c) != challengeBitsLength {
		return nil, ErrInvalidArgument.WithMessage("commitment point slices must have length %d", challengeBitsLength)
	}
	for _, elem := range b {
		if utils.IsNil(elem) {
			return nil, ErrInvalidArgument.WithMessage("commitment B values must not be nil")
		}
	}
	for _, elem := range c {
		if utils.IsNil(elem) {
			return nil, ErrInvalidArgument.WithMessage("commitment C values must not be nil")
		}
	}
	return &Commitment[G, B, S]{
		a: a,
		b: b,
		c: c,
	}, nil
}

// MarshalCBOR serialises the commitment to CBOR format.
func (c *Commitment[G, B, S]) MarshalCBOR() ([]byte, error) {
	dto := &commitmentDTO[G, B, S]{
		A: c.a,
		B: c.b,
		C: c.c,
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
	commitment, err := NewCommitment(dto.A, dto.B, dto.C)
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
		out = sliceutils.AppendLengthPrefixed(out, c.c[i].Bytes())
	}
	return out
}

// Response is the prover's final message (z_j, w_j, nu_j) for each repetition.
type Response struct {
	z  []*num.Int
	w  []*num.Int
	nu []*paillier.Nonce
}

type responseDTO struct {
	Z  []*num.Int        `cbor:"z"`
	W  []*num.Int        `cbor:"w"`
	Nu []*paillier.Nonce `cbor:"nu"`
}

// NewResponse constructs a Paillier special decryption-in-the-exponent response.
func NewResponse(z, w []*num.Int, nu []*paillier.Nonce) (*Response, error) {
	if err := validateIntSlice("response z", z); err != nil {
		return nil, err
	}
	if err := validateIntSlice("response w", w); err != nil {
		return nil, err
	}
	if err := validateNonceSlice("response nu", nu); err != nil {
		return nil, err
	}
	return &Response{
		z:  z,
		w:  w,
		nu: nu,
	}, nil
}

// MarshalCBOR serialises the response to CBOR format.
func (r *Response) MarshalCBOR() ([]byte, error) {
	dto := &responseDTO{
		Z:  r.z,
		W:  r.w,
		Nu: r.nu,
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
	response, err := NewResponse(dto.Z, dto.W, dto.Nu)
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
		out = sliceutils.AppendLengthPrefixed(out, r.w[i].Bytes())
		out = sliceutils.AppendLengthPrefixed(out, r.nu[i].Bytes())
	}
	return out
}
