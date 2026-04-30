package blummod

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const (
	// Name identifies the Paillier-Blum modulus proof.
	Name sigma.Name = "PAILLIER_BLUM_MODULUS"

	// M is the number of repetitions. This gives soundness at most 2^{-m+1}.
	// This has to be kept larger than 128 so the non-interactive protocols won't reject it,
	// and the smallest multiple of 8 bigger than 128 is 136
	M = 128 + 8

	challengeBytesLength = M / 8
	challengeHashLabel   = "BRON_CRYPTO_SIGMA_PAILLIER_BLUM_MODULUS_CHALLENGE"
)

// Statement is the public Paillier modulus N.
type Statement struct {
	X *paillier.PublicKey `cbor:"x"`
}

// Bytes serialises the statement for transcript binding.
func (x *Statement) Bytes() []byte {
	if x == nil || x.X == nil || x.X.Group() == nil || x.X.Group().N() == nil {
		return nil
	}
	return sliceutils.AppendLengthPrefixed([]byte{}, x.X.Group().N().BytesBE())
}

// Witness is the Paillier private key carrying the factorisation N = pq.
type Witness struct {
	W *paillier.PrivateKey `cbor:"w"`
}

// Bytes serialises the witness. Witness bytes are not placed in public transcripts.
func (w *Witness) Bytes() []byte {
	if w == nil || w.W == nil || w.W.Group() == nil {
		return nil
	}
	arith := w.W.Arithmetic().CrtModN
	out := sliceutils.AppendLengthPrefixed([]byte{}, arith.Params.PNat.BytesBE())
	return sliceutils.AppendLengthPrefixed(out, arith.Params.QNat.BytesBE())
}

// State holds the prover's first-round value with the factorisation-aware type.
type State struct {
	S *znstar.RSAGroupElementKnownOrder `cbor:"s"`
}

// Bytes serialises the prover state for diagnostics.
func (s *State) Bytes() []byte {
	if s == nil || s.S == nil {
		return nil
	}
	return sliceutils.AppendLengthPrefixed([]byte{}, s.S.Bytes())
}

// Commitment is the first message w sent by the prover.
type Commitment struct {
	A *znstar.RSAGroupElementUnknownOrder `cbor:"a"`
}

// Bytes serialises the commitment for transcript binding.
func (a *Commitment) Bytes() []byte {
	if a == nil || a.A == nil {
		return nil
	}
	return sliceutils.AppendLengthPrefixed([]byte{}, a.A.Bytes())
}

// Response is the prover's Figure 12 response ((x_i, a_i, b_i), z_i) for i in [M].
type Response struct {
	X []*znstar.RSAGroupElementUnknownOrder `cbor:"x"`
	A []byte                                `cbor:"a"`
	B []byte                                `cbor:"b"`
	Z []*znstar.RSAGroupElementUnknownOrder `cbor:"z"`
}

// Bytes serialises the response for transcript binding.
func (z *Response) Bytes() []byte {
	if z == nil {
		return nil
	}

	out := sliceutils.AppendLengthPrefixedSlices([]byte{}, groupElementsBytes(z.X)...)
	out = sliceutils.AppendLengthPrefixed(out, z.A)
	out = sliceutils.AppendLengthPrefixed(out, z.B)
	return sliceutils.AppendLengthPrefixedSlices(out, groupElementsBytes(z.Z)...)
}

// Protocol implements the Paillier-Blum modulus proof from CGGMP Figure 12.
type Protocol struct {
	prng io.Reader
}

// NewProtocol constructs a Paillier-Blum modulus proof protocol.
func NewProtocol(prng io.Reader) (*Protocol, error) {
	if prng == nil {
		return nil, ErrInvalidArgument.WithMessage("prng is nil")
	}
	return &Protocol{prng: prng}, nil
}

// Name returns the protocol identifier.
func (p *Protocol) Name() sigma.Name {
	return Name
}

// ComputeProverCommitment samples w with Jacobi symbol -1 and sends it as the first message.
func (p *Protocol) ComputeProverCommitment(statement *Statement, witness *Witness) (*Commitment, *State, error) {
	if p == nil || p.prng == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("protocol PRNG is nil")
	}
	if err := p.ValidateStatement(statement, witness); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid statement")
	}

	rsaGroup, err := rsaGroupFromWitness(witness)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create RSA group")
	}
	w, err := rsaGroup.RandomWithJacobi(-1, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample w")
	}

	return &Commitment{A: w.ForgetOrder()}, &State{S: w}, nil
}

// ComputeProverResponse answers the verifier challenge expanded to y_i values.
func (p *Protocol) ComputeProverResponse(statement *Statement, witness *Witness, commitment *Commitment, state *State, challenge sigma.ChallengeBytes) (*Response, error) {
	if err := p.ValidateStatement(statement, witness); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid statement")
	}
	if commitment == nil || commitment.A == nil {
		return nil, ErrInvalidArgument.WithMessage("commitment is nil")
	}
	if state == nil || state.S == nil {
		return nil, ErrInvalidArgument.WithMessage("state is nil")
	}
	if len(challenge) != challengeBytesLength {
		return nil, ErrInvalidArgument.WithMessage("invalid challenge length")
	}
	if !state.S.ForgetOrder().Equal(commitment.A) {
		return nil, ErrInvalidArgument.WithMessage("commitment and state mismatch")
	}

	rsaGroup, err := rsaGroupFromWitness(witness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create RSA group")
	}
	ys, err := deriveChallengeElements(statement, challenge)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot derive challenge elements")
	}

	minusOne, err := minusOneKnown(rsaGroup)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create -1")
	}
	nInv, err := nInverseModPhi(witness.W)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute N inverse modulo phi(N)")
	}
	fourthRootExp, err := fourthRootExponent(witness.W)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute fourth-root exponent")
	}

	response := &Response{
		X: make([]*znstar.RSAGroupElementUnknownOrder, M),
		A: make([]byte, M),
		B: make([]byte, M),
		Z: make([]*znstar.RSAGroupElementUnknownOrder, M),
	}

	for i, y := range ys {
		yKnown, err := y.LearnOrder(rsaGroup)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot learn challenge element order")
		}

		yPrime := yKnown
		j, err := yKnown.Jacobi()
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot compute Jacobi symbol")
		}
		switch j {
		case 1:
			response.B[i] = 0
		case -1:
			response.B[i] = 1
			yPrime = yPrime.Mul(state.S)
		default:
			return nil, ErrFailed.WithMessage("challenge element is not a unit")
		}

		isQR, err := rsaGroup.IsQuadraticResidue(yPrime)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot test quadratic residuosity")
		}
		if !isQR {
			response.A[i] = 1
			yPrime = yPrime.Mul(minusOne)
		}
		isQR, err = rsaGroup.IsQuadraticResidue(yPrime)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot test adjusted quadratic residuosity")
		}
		if !isQR {
			return nil, ErrFailed.WithMessage("cannot adjust challenge element into QR_N")
		}

		response.X[i] = yPrime.Exp(fourthRootExp).ForgetOrder()
		response.Z[i] = yKnown.Exp(nInv).ForgetOrder()
	}

	return response, nil
}

// Verify checks a Paillier-Blum modulus proof transcript.
func (p *Protocol) Verify(statement *Statement, commitment *Commitment, challenge sigma.ChallengeBytes, response *Response) error {
	rsaGroup, err := rsaGroupFromStatement(statement)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid statement")
	}
	if err := validatePublicModulus(rsaGroup.Modulus()); err != nil {
		return errs.Wrap(err).WithMessage("invalid modulus")
	}
	if commitment == nil || commitment.A == nil {
		return ErrInvalidArgument.WithMessage("commitment is nil")
	}
	if response == nil {
		return ErrInvalidArgument.WithMessage("response is nil")
	}
	if len(challenge) != challengeBytesLength {
		return ErrInvalidArgument.WithMessage("invalid challenge length")
	}
	if !elementInGroup(commitment.A, rsaGroup) {
		return ErrVerificationFailed.WithMessage("commitment has wrong modulus")
	}
	j, err := commitment.A.Jacobi()
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot compute Jacobi symbol")
	}
	if j != -1 {
		return ErrVerificationFailed.WithMessage("verification failed")
	}
	if err := validateResponseShape(response, rsaGroup); err != nil {
		return errs.Wrap(err).WithMessage("invalid response")
	}

	ys, err := deriveChallengeElements(statement, challenge)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot derive challenge elements")
	}
	minusOne, err := minusOneUnknown(rsaGroup)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create -1")
	}
	n := rsaGroup.Modulus().Nat()

	for i, y := range ys {
		if !response.Z[i].Exp(n).Equal(y) {
			return ErrVerificationFailed.WithMessage("verification failed")
		}

		rhs := y
		if response.B[i] == 1 {
			rhs = rhs.Mul(commitment.A)
		}
		if response.A[i] == 1 {
			rhs = rhs.Mul(minusOne)
		}
		x4 := response.X[i].Square().Square()
		if !x4.Equal(rhs) {
			return ErrVerificationFailed.WithMessage("verification failed")
		}
	}

	return nil
}

// RunSimulator is not available for this protocol with a fixed opaque challenge.
func (p *Protocol) RunSimulator(statement *Statement, challenge sigma.ChallengeBytes) (*Commitment, *Response, error) {
	if _, err := rsaGroupFromStatement(statement); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid statement")
	}
	if len(challenge) != challengeBytesLength {
		return nil, nil, ErrInvalidArgument.WithMessage("invalid challenge length")
	}
	return nil, nil, ErrFailed.WithMessage("Paillier-Blum modulus simulation requires programmable y_i challenges")
}

// SpecialSoundness returns the number of accepting transcripts needed for extraction.
func (p *Protocol) SpecialSoundness() uint {
	return 2
}

// SoundnessError returns the protocol soundness in bits.
func (p *Protocol) SoundnessError() uint {
	return M - 1
}

// GetChallengeBytesLength returns the seed length used to derive the y_i challenges.
func (p *Protocol) GetChallengeBytesLength() int {
	return challengeBytesLength
}

// ValidateStatement checks that the public key matches a Paillier-Blum factorisation.
func (p *Protocol) ValidateStatement(statement *Statement, witness *Witness) error {
	if _, err := rsaGroupFromStatement(statement); err != nil {
		return errs.Wrap(err)
	}
	if witness == nil || witness.W == nil || witness.W.Group() == nil {
		return ErrInvalidArgument.WithMessage("witness is nil")
	}
	if !statement.X.Equal(witness.W.PublicKey()) {
		return ErrValidationFailed.WithMessage("paillier keys mismatch")
	}

	arith := witness.W.Arithmetic().CrtModN
	if !isThreeModFour(arith.Params.PNat) || !isThreeModFour(arith.Params.QNat) {
		return ErrValidationFailed.WithMessage("factors are not Blum primes")
	}
	if arith.N.Nat().Coprime(arith.Phi.Nat()) != ct.True {
		return ErrValidationFailed.WithMessage("gcd(N, phi(N)) != 1")
	}
	return nil
}
