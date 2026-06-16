package encelg

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
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const (
	// Name identifies the CGGMP21 range proof with ElGamal-style group commitment.
	Name sigma.Name = "CGGMP21_RANGE_PROOF_WITH_ELGAMAL_COMMITMENT"
)

// Statement is the public input (N0, C, A, (B, X)) for CGGMP21 Figure 24.
type Statement[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	n0 *paillier.PublicKey
	c  *paillier.Ciphertext
	a  *elgamal.PublicKey[G, S]
	bx *elgamal.Ciphertext[G, S]
}

type statementDTO[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	N0 *paillier.PublicKey       `cbor:"n0"`
	C  *paillier.Ciphertext      `cbor:"c"`
	A  *elgamal.PublicKey[G, S]  `cbor:"a"`
	BX *elgamal.Ciphertext[G, S] `cbor:"bx"`
}

// NewStatement constructs an enc-elg statement.
func NewStatement[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	n0 *paillier.PublicKey,
	c *paillier.Ciphertext,
	a *elgamal.PublicKey[G, S],
	bx *elgamal.Ciphertext[G, S],
) (*Statement[G, B, S], error) {
	if n0 == nil || c == nil || a == nil || bx == nil {
		return nil, ErrInvalidArgument.WithMessage("statement values must not be nil")
	}
	return &Statement[G, B, S]{
		n0: n0,
		c:  c,
		a:  a,
		bx: bx,
	}, nil
}

// MarshalCBOR serialises the statement to CBOR format.
func (s *Statement[G, B, S]) MarshalCBOR() ([]byte, error) {
	dto := &statementDTO[G, B, S]{
		N0: s.n0,
		C:  s.c,
		A:  s.a,
		BX: s.bx,
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
	statement, err := NewStatement(dto.N0, dto.C, dto.A, dto.BX)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid statement data")
	}
	*s = *statement
	return nil
}

// Bytes serialises the statement for transcript binding.
func (s *Statement[G, B, S]) Bytes() []byte {
	out := binary.LittleEndian.AppendUint64(nil, 4)
	out = sliceutils.AppendLengthPrefixed(out, s.n0.Group().N().Bytes())
	out = sliceutils.AppendLengthPrefixed(out, s.c.Bytes())
	out = sliceutils.AppendLengthPrefixed(out, s.a.Value().Bytes())
	for _, component := range s.bx.Value().Components() {
		out = sliceutils.AppendLengthPrefixed(out, component.Bytes())
	}
	return out
}

// Witness is the secret input (x, rho, a, bx) for CGGMP21 Figure 24.
type Witness[G elgamal.FiniteCyclicGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	x   *num.Int
	rho *paillier.Nonce
	a   *elgamal.SecretKey[G, S]
	bx  *elgamal.Nonce[S]
}

// NewWitness constructs an enc-elg witness.
func NewWitness[G elgamal.FiniteCyclicGroupElement[G, S], S algebra.PrimeFieldElement[S]](
	x *num.Int,
	rho *paillier.Nonce,
	a *elgamal.SecretKey[G, S],
	bx *elgamal.Nonce[S],
) (*Witness[G, S], error) {
	if x == nil || rho == nil || a == nil || bx == nil {
		return nil, ErrInvalidArgument.WithMessage("witness values must not be nil")
	}
	return &Witness[G, S]{
		x:   x.Clone(),
		rho: rho,
		a:   a,
		bx:  bx,
	}, nil
}

// State stores the prover's sampled randomness between sigma rounds.
type State[S algebra.PrimeFieldElement[S]] struct {
	alpha *num.Int
	beta  S
	mu    *num.Int
	r     *paillier.Nonce
	gamma *num.Int
}

// NewState constructs the prover state retained between sigma rounds.
func NewState[S algebra.PrimeFieldElement[S]](alpha *num.Int, beta S, mu *num.Int, r *paillier.Nonce, gamma *num.Int) (*State[S], error) {
	if alpha == nil || mu == nil || r == nil || gamma == nil || utils.IsNil(beta) {
		return nil, ErrInvalidArgument.WithMessage("state values must not be nil")
	}
	return &State[S]{
		alpha: alpha,
		beta:  beta,
		mu:    mu,
		r:     r,
		gamma: gamma,
	}, nil
}

// Commitment is the prover's first message (S, T, D, (Z, Y)).
type Commitment[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	s  *intcom.Commitment
	t  *intcom.Commitment
	d  *paillier.Ciphertext
	yz *elgamal.Ciphertext[G, S]
}

type commitmentDTO[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	S  *intcom.Commitment        `cbor:"s"`
	T  *intcom.Commitment        `cbor:"t"`
	D  *paillier.Ciphertext      `cbor:"d"`
	YZ *elgamal.Ciphertext[G, S] `cbor:"yz"`
}

// NewCommitment constructs an enc-elg commitment.
func NewCommitment[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	s *intcom.Commitment,
	t *intcom.Commitment,
	d *paillier.Ciphertext,
	yz *elgamal.Ciphertext[G, S],
) (*Commitment[G, B, S], error) {
	if s == nil || t == nil || d == nil || yz == nil {
		return nil, ErrInvalidArgument.WithMessage("commitment values must not be nil")
	}
	return &Commitment[G, B, S]{
		s:  s,
		t:  t,
		d:  d,
		yz: yz,
	}, nil
}

// MarshalCBOR serialises the commitment to CBOR format.
func (c *Commitment[G, B, S]) MarshalCBOR() ([]byte, error) {
	dto := &commitmentDTO[G, B, S]{
		S:  c.s,
		T:  c.t,
		D:  c.d,
		YZ: c.yz,
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
	commitment, err := NewCommitment(dto.S, dto.T, dto.D, dto.YZ)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid commitment data")
	}
	*c = *commitment
	return nil
}

// Bytes serialises the commitment for transcript binding.
func (c *Commitment[G, B, S]) Bytes() []byte {
	out := binary.LittleEndian.AppendUint64(nil, 4)
	out = sliceutils.AppendLengthPrefixed(out, c.s.Value().Bytes())
	out = sliceutils.AppendLengthPrefixed(out, c.t.Value().Bytes())
	out = sliceutils.AppendLengthPrefixed(out, c.d.Bytes())
	for _, component := range c.yz.Value().Components() {
		out = sliceutils.AppendLengthPrefixed(out, component.Bytes())
	}
	return out
}

// Response is the prover's final message (z1, z2, z3, w).
type Response[S algebra.PrimeFieldElement[S]] struct {
	z1 *num.Int
	z2 *paillier.Nonce
	z3 *num.Int
	w  S
}

type responseDTO[S algebra.PrimeFieldElement[S]] struct {
	Z1 *num.Int        `cbor:"z1"`
	Z2 *paillier.Nonce `cbor:"z2"`
	Z3 *num.Int        `cbor:"z3"`
	W  S               `cbor:"w"`
}

// NewResponse constructs an enc-elg response.
func NewResponse[S algebra.PrimeFieldElement[S]](z1 *num.Int, z2 *paillier.Nonce, z3 *num.Int, w S) (*Response[S], error) {
	if z1 == nil || z2 == nil || z3 == nil || utils.IsNil(w) {
		return nil, ErrInvalidArgument.WithMessage("response values must not be nil")
	}
	return &Response[S]{
		z1: z1,
		z2: z2,
		z3: z3,
		w:  w,
	}, nil
}

// MarshalCBOR serialises the response to CBOR format.
func (r *Response[S]) MarshalCBOR() ([]byte, error) {
	dto := &responseDTO[S]{
		Z1: r.z1,
		Z2: r.z2,
		Z3: r.z3,
		W:  r.w,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal response to CBOR")
	}
	return out, nil
}

// UnmarshalCBOR deserialises the response from CBOR format.
func (r *Response[S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*responseDTO[S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal response from CBOR")
	}
	if dto == nil {
		return ErrInvalidArgument.WithMessage("response DTO must not be nil")
	}
	response, err := NewResponse(dto.Z1, dto.Z2, dto.Z3, dto.W)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid response data")
	}
	*r = *response
	return nil
}

// Bytes serialises the response for transcript binding.
func (r *Response[S]) Bytes() []byte {
	out := binary.LittleEndian.AppendUint64(nil, 4)
	out = sliceutils.AppendLengthPrefixed(out, r.z1.Bytes())
	out = sliceutils.AppendLengthPrefixed(out, r.z2.Bytes())
	out = sliceutils.AppendLengthPrefixed(out, r.z3.Bytes())
	out = sliceutils.AppendLengthPrefixed(out, r.w.Bytes())
	return out
}
