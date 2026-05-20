package blummod

import (
	"crypto/hkdf"
	"crypto/sha3"
	"encoding/binary"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
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
	PublicKey *paillier.PublicKey
}

// NewStatement constructs a Paillier-Blum modulus statement.
func NewStatement(publicKey *paillier.PublicKey) (*Statement, error) {
	if publicKey == nil {
		return nil, ErrInvalidArgument.WithMessage("publicKey must not be nil")
	}
	if err := validatePublicModulus(publicKey.Group().N()); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid Paillier modulus")
	}
	return &Statement{PublicKey: publicKey}, nil
}

// Bytes serialises the statement for transcript binding.
func (s *Statement) Bytes() []byte {
	if s == nil || s.PublicKey == nil {
		return nil
	}
	out := []byte{}
	out = sliceutils.AppendLengthPrefixed(out, s.PublicKey.Group().N().Bytes())
	return out
}

// Witness contains the Paillier trapdoor used by the prover.
//
// NewWitness does not check that the trapdoor is Paillier-Blum; a prover with
// a wrong trapdoor is allowed to attempt the proof and fail during response
// generation.
type Witness struct {
	SecretKey *paillier.SecretKey
}

// NewWitness constructs a Paillier modulus witness.
func NewWitness(secretKey *paillier.SecretKey) (*Witness, error) {
	if secretKey == nil {
		return nil, ErrInvalidArgument.WithMessage("secretKey must not be nil")
	}
	return &Witness{SecretKey: secretKey}, nil
}

// Bytes serialises the witness for transcript binding.
func (w *Witness) Bytes() []byte {
	if w == nil || w.SecretKey == nil {
		return nil
	}
	return w.SecretKey.PlaintextGroup().Modulus().Bytes()
}

// Commitment holds the prover's first-round value w.
type Commitment struct {
	W *paillier.Nonce
}

// Bytes serialises the commitment for transcript binding.
func (c *Commitment) Bytes() []byte {
	if c == nil {
		return nil
	}
	if c.W == nil {
		return sliceutils.AppendLengthPrefixed([]byte{}, []byte(nil))
	}
	out := []byte{}
	out = sliceutils.AppendLengthPrefixed(out, c.W.Bytes())
	return out
}

// State stores the prover's internal state between rounds.
type State struct {
	S *znstar.RSAGroupElementKnownOrder
}

// ResponseItem holds the answer for one verifier challenge element.
type ResponseItem struct {
	X *paillier.Nonce `cbor:"x"`
	A uint8           `cbor:"a"`
	B uint8           `cbor:"b"`
	Z *paillier.Nonce `cbor:"z"`
}

// Response is the prover's third-round message.
type Response struct {
	Items [m]*ResponseItem `cbor:"items"`
}

// Bytes serialises the response for transcript binding.
func (r *Response) Bytes() []byte {
	if r == nil {
		return nil
	}
	out := binary.LittleEndian.AppendUint64(nil, uint64(len(r.Items)))
	for _, item := range &r.Items {
		if item == nil {
			out = sliceutils.AppendLengthPrefixed(out, []byte(nil))
			out = append(out, 0, 0)
			out = sliceutils.AppendLengthPrefixed(out, []byte(nil))
			continue
		}
		var xBytes []byte
		if item.X != nil {
			xBytes = item.X.Bytes()
		}
		out = sliceutils.AppendLengthPrefixed(out, xBytes)
		out = append(out, item.A, item.B)
		var zBytes []byte
		if item.Z != nil {
			zBytes = item.Z.Bytes()
		}
		out = sliceutils.AppendLengthPrefixed(out, zBytes)
	}
	return out
}

// Protocol implements the CGGMP21 Paillier-Blum modulus proof.
type Protocol struct {
	prng io.Reader
}

// NewProtocol constructs a CGGMP21 Paillier-Blum modulus proof instance.
//
// The amplification parameter from Figure 12 is fixed to m = 129, giving
// 128-bit statistical soundness under the paper's 2^{-m+1} bound.
func NewProtocol(prng io.Reader) (*Protocol, error) {
	if prng == nil {
		return nil, ErrInvalidArgument.WithMessage("prng must not be nil")
	}

	return &Protocol{prng: prng}, nil
}

// Name returns the protocol identifier.
func (*Protocol) Name() sigma.Name {
	return Name
}

// ComputeProverCommitment generates the first prover message.
func (p *Protocol) ComputeProverCommitment(statement *Statement, witness *Witness) (*Commitment, *State, error) {
	if err := p.ValidateStatement(statement, witness); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid statement or witness")
	}

	rsaGroup, err := rsaGroupFromWitness(witness)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create RSA group")
	}
	wValue, err := rsaGroup.RandomWithJacobi(-1, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample w")
	}
	w, err := paillier.NewNonceFromGroupElement(wValue.ForgetOrder())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create commitment")
	}
	return &Commitment{W: w}, &State{S: wValue}, nil
}

// ComputeProverResponse generates the prover response for a fixed challenge.
func (p *Protocol) ComputeProverResponse(
	statement *Statement,
	witness *Witness,
	commitment *Commitment,
	state *State,
	challenge sigma.ChallengeBytes,
) (*Response, error) {
	if err := p.ValidateStatement(statement, witness); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid statement or witness")
	}
	if commitment == nil || commitment.W == nil {
		return nil, ErrInvalidArgument.WithMessage("commitment is invalid")
	}
	if state == nil || state.S == nil {
		return nil, ErrInvalidArgument.WithMessage("state must not be nil")
	}
	if len(challenge) != p.GetChallengeBytesLength() {
		return nil, ErrInvalidArgument.WithMessage("invalid challenge length")
	}

	rsaGroup, err := rsaGroupFromWitness(witness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create RSA group")
	}
	if !statement.PublicKey.NonceGroup().Contains(commitment.W.Value()) {
		return nil, ErrValidationFailed.WithMessage("w is not in the nonce group")
	}
	if !rsaGroup.Contains(state.S) {
		return nil, ErrValidationFailed.WithMessage("state is not in the witness RSA group")
	}
	if !state.S.ForgetOrder().Equal(commitment.W.Value()) {
		return nil, ErrValidationFailed.WithMessage("commitment and state mismatch")
	}
	jacobi, err := commitment.W.Value().Jacobi()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute Jacobi symbol of w")
	}
	if jacobi != -1 {
		return nil, ErrValidationFailed.WithMessage("w must have Jacobi symbol -1")
	}

	ys, err := p.mapToChallenge(statement, challenge)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not derive challenge elements")
	}

	minusOne, err := minusOneKnown(rsaGroup)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create -1")
	}
	nInv, err := nInverseModPhi(witness.SecretKey)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute N inverse mod phi(N)")
	}
	fourthRootExp, err := fourthRootExponent(witness.SecretKey)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute fourth-root exponent")
	}

	response := &Response{}
	for i, y := range &ys {
		yKnown, err := y.Value().LearnOrder(rsaGroup)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not learn challenge element order")
		}

		yPrime := yKnown
		j, err := yKnown.Jacobi()
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not compute Jacobi symbol")
		}

		b := uint8(0)
		switch j {
		case 1:
		case -1:
			b = 1
			yPrime = yPrime.Mul(state.S)
		default:
			return nil, ErrFailed.WithMessage("challenge element is not a unit")
		}

		a := uint8(0)
		isQR, err := rsaGroup.IsQuadraticResidue(yPrime)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not test quadratic residuosity")
		}
		if !isQR {
			a = 1
			yPrime = yPrime.Mul(minusOne)
		}
		isQR, err = rsaGroup.IsQuadraticResidue(yPrime)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not test adjusted quadratic residuosity")
		}
		if !isQR {
			return nil, ErrFailed.WithMessage("could not adjust challenge element into QR_N")
		}

		x, err := paillier.NewNonceFromGroupElement(yPrime.Exp(fourthRootExp).ForgetOrder())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not create x")
		}
		z, err := paillier.NewNonceFromGroupElement(yKnown.Exp(nInv).ForgetOrder())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not create z")
		}

		response.Items[i] = &ResponseItem{
			X: x,
			A: a,
			B: b,
			Z: z,
		}
	}
	return response, nil
}

// Verify checks a prover response against the statement and commitment.
func (p *Protocol) Verify(statement *Statement, commitment *Commitment, challenge sigma.ChallengeBytes, response *Response) error {
	if err := validateStatementPublicKey(statement); err != nil {
		return errs.Wrap(err).WithMessage("invalid statement")
	}
	if commitment == nil || commitment.W == nil {
		return ErrInvalidArgument.WithMessage("commitment is invalid")
	}
	if response == nil {
		return ErrInvalidArgument.WithMessage("response must not be nil")
	}
	if len(challenge) != p.GetChallengeBytesLength() {
		return ErrInvalidArgument.WithMessage("invalid challenge length")
	}
	nonceGroup := statement.PublicKey.NonceGroup()
	if !nonceGroup.Contains(commitment.W.Value()) {
		return ErrVerificationFailed.WithMessage("w is not in the nonce group")
	}
	jacobi, err := commitment.W.Value().Jacobi()
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute Jacobi symbol of w")
	}
	if jacobi != -1 {
		return ErrVerificationFailed.WithMessage("w must have Jacobi symbol -1")
	}

	ys, err := p.mapToChallenge(statement, challenge)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not derive challenge elements")
	}
	minusOne, err := minusOne(statement.PublicKey)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create -1")
	}
	n := statement.PublicKey.PlaintextGroup().Modulus()
	for i, item := range &response.Items {
		if item == nil || item.X == nil || item.Z == nil {
			return ErrVerificationFailed.WithMessage("response item is invalid")
		}
		if item.A > 1 || item.B > 1 {
			return ErrVerificationFailed.WithMessage("a and b must be bits")
		}
		if !nonceGroup.Contains(item.X.Value()) || !nonceGroup.Contains(item.Z.Value()) {
			return ErrVerificationFailed.WithMessage("response values are not in the nonce group")
		}

		if !item.Z.Value().Exp(n.Nat()).Equal(ys[i].Value()) {
			return ErrVerificationFailed.WithMessage("z^N does not match challenge")
		}

		lhs := item.X.Value().Square().Square()
		rhs := ys[i].Value()
		if item.B == 1 {
			rhs = commitment.W.Value().Mul(rhs)
		}
		if item.A == 1 {
			rhs = minusOne.Value().Mul(rhs)
		}
		if !lhs.Equal(rhs) {
			return ErrVerificationFailed.WithMessage("x^4 does not match adjusted challenge")
		}
	}
	return nil
}

// RunSimulator is not supported for the fixed-challenge sigma interface.
//
// Figure 12 gives an honest-verifier simulator that samples w and the
// verifier's challenge elements together. The repo sigma interface fixes the
// challenge bytes before RunSimulator is called; simulating an accepting
// transcript for an arbitrary fixed challenge would require extracting roots
// without the factorisation.
func (p *Protocol) RunSimulator(statement *Statement, challenge sigma.ChallengeBytes) (*Commitment, *Response, error) {
	if err := validateStatementPublicKey(statement); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid statement")
	}
	if len(challenge) != p.GetChallengeBytesLength() {
		return nil, nil, ErrInvalidArgument.WithMessage("invalid challenge length")
	}
	return nil, nil, ErrUnsupported.WithMessage("fixed-challenge simulator is not available for this protocol")
}

// SpecialSoundness returns the protocol extraction parameter.
//
// CGGMP21 extracts the factorisation from one accepting transcript whose
// challenge was programmed with known square roots as described in Section
// 5.2.1. The statistical accepting probability for unprogrammed challenges is
// reported separately by SoundnessError.
func (*Protocol) SpecialSoundness() uint {
	return 1
}

// SoundnessError returns the statistical soundness error in bits.
func (*Protocol) SoundnessError() uint {
	return m - 1
}

// GetChallengeBytesLength returns the challenge size in bytes.
func (*Protocol) GetChallengeBytesLength() int {
	return challengeBytes
}

// ValidateStatement checks that the public modulus is well-formed and that the
// witness secret key is present and has the same modulus.
//
// It intentionally does not check whether the secret key is Paillier-Blum:
// that is the relation the prover is trying to demonstrate.
func (*Protocol) ValidateStatement(statement *Statement, witness *Witness) error {
	if err := validateStatementPublicKey(statement); err != nil {
		return errs.Wrap(err).WithMessage("invalid statement")
	}
	if witness == nil {
		return ErrInvalidArgument.WithMessage("witness must not be nil")
	}
	if err := validateWitness(statement, witness); err != nil {
		return errs.Wrap(err).WithMessage("invalid witness")
	}
	return nil
}

func (p *Protocol) mapToChallenge(
	statement *Statement,
	challenge sigma.ChallengeBytes,
) ([m]*paillier.Nonce, error) {
	if err := validateStatementPublicKey(statement); err != nil {
		return [m]*paillier.Nonce{}, errs.Wrap(err).WithMessage("invalid statement")
	}
	if len(challenge) != p.GetChallengeBytesLength() {
		return [m]*paillier.Nonce{}, ErrInvalidArgument.WithMessage("invalid challenge length")
	}
	key, err := hkdf.Extract(sha3.New256, challenge, []byte(Name))
	if err != nil {
		return [m]*paillier.Nonce{}, errs.Wrap(err).WithMessage("could not HKDF-extract challenge seed")
	}
	info := []byte(Name)
	info = sliceutils.AppendLengthPrefixed(info, statement.PublicKey.Group().N().Bytes())
	expanded, err := hkdf.Expand(sha3.New256, key, string(info), m*challengeBlockBytes)
	if err != nil {
		return [m]*paillier.Nonce{}, errs.Wrap(err).WithMessage("could not HKDF-expand challenge seed")
	}

	nonceGroup := statement.PublicKey.NonceGroup()
	var out [m]*paillier.Nonce
	for i := range out {
		start := i * challengeBlockBytes
		yValue, err := nonceGroup.Hash(expanded[start : start+challengeBlockBytes])
		if err != nil {
			return [m]*paillier.Nonce{}, errs.Wrap(err).WithMessage("could not hash challenge block to nonce")
		}
		out[i], err = paillier.NewNonceFromGroupElement(yValue)
		if err != nil {
			return [m]*paillier.Nonce{}, errs.Wrap(err).WithMessage("could not create challenge nonce")
		}
	}
	return out, nil
}
