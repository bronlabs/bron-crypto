package blummod

import (
	"crypto/hkdf"
	"crypto/sha3"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

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
	commitment, err := NewCommitment(w)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create commitment")
	}
	state, err := NewState(wValue)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create state")
	}
	return commitment, state, nil
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
	if len(challenge) != p.GetChallengeBytesLength() {
		return nil, ErrInvalidArgument.WithMessage("invalid challenge length")
	}

	rsaGroup, err := rsaGroupFromWitness(witness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create RSA group")
	}
	if !statement.publicKey.NonceGroup().Contains(commitment.w.Value()) {
		return nil, ErrValidationFailed.WithMessage("w is not in the nonce group")
	}
	if !rsaGroup.Contains(state.s) {
		return nil, ErrValidationFailed.WithMessage("state is not in the witness RSA group")
	}
	if !state.s.ForgetOrder().Equal(commitment.w.Value()) {
		return nil, ErrValidationFailed.WithMessage("commitment and state mismatch")
	}
	jacobi, err := commitment.w.Value().Jacobi()
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
	nInv, err := nInverseModPhi(witness.secretKey)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute N inverse mod phi(N)")
	}
	fourthRootExp, err := fourthRootExponent(witness.secretKey)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute fourth-root exponent")
	}

	var items [m]*ResponseItem
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
			yPrime = yPrime.Mul(state.s)
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

		item, err := NewResponseItem(x, a, b, z)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not create response item")
		}
		items[i] = item
	}
	response, err := NewResponse(items[:]...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create response")
	}
	return response, nil
}

// Verify checks a prover response against the statement and commitment.
func (p *Protocol) Verify(statement *Statement, commitment *Commitment, challenge sigma.ChallengeBytes, response *Response) error {
	if len(challenge) != p.GetChallengeBytesLength() {
		return ErrInvalidArgument.WithMessage("invalid challenge length")
	}
	nonceGroup := statement.publicKey.NonceGroup()
	if !nonceGroup.Contains(commitment.w.Value()) {
		return ErrVerificationFailed.WithMessage("w is not in the nonce group")
	}
	jacobi, err := commitment.w.Value().Jacobi()
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
	minusOne, err := minusOne(statement.publicKey)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create -1")
	}
	n := statement.publicKey.PlaintextGroup().Modulus()
	for i, item := range &response.items {
		if !nonceGroup.Contains(item.x.Value()) || !nonceGroup.Contains(item.z.Value()) {
			return ErrVerificationFailed.WithMessage("response values are not in the nonce group")
		}

		if !item.z.Value().Exp(n.Nat()).Equal(ys[i].Value()) {
			return ErrVerificationFailed.WithMessage("z^N does not match challenge")
		}

		lhs := item.x.Value().Square().Square()
		rhs := ys[i].Value()
		if item.b == 1 {
			rhs = commitment.w.Value().Mul(rhs)
		}
		if item.a == 1 {
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
	if err := validateWitness(statement, witness); err != nil {
		return errs.Wrap(err).WithMessage("invalid witness")
	}
	return nil
}

func (p *Protocol) mapToChallenge(
	statement *Statement,
	challenge sigma.ChallengeBytes,
) ([m]*paillier.Nonce, error) {
	if len(challenge) != p.GetChallengeBytesLength() {
		return [m]*paillier.Nonce{}, ErrInvalidArgument.WithMessage("invalid challenge length")
	}
	key, err := hkdf.Extract(sha3.New256, challenge, []byte(Name))
	if err != nil {
		return [m]*paillier.Nonce{}, errs.Wrap(err).WithMessage("could not HKDF-extract challenge seed")
	}
	info := []byte(Name)
	info = sliceutils.AppendLengthPrefixed(info, statement.publicKey.Group().N().Bytes())
	expanded, err := hkdf.Expand(sha3.New256, key, string(info), m*challengeBlockBytes)
	if err != nil {
		return [m]*paillier.Nonce{}, errs.Wrap(err).WithMessage("could not HKDF-expand challenge seed")
	}

	nonceGroup := statement.publicKey.NonceGroup()
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
