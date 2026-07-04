package fac

import (
	"fmt"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

// Protocol implements the CGGMP21 small-factor proof from Figure 26.
type Protocol struct {
	name            sigma.Name
	ringPedersenKey *intcom.CommitmentKey
	l               int
	epsilon         int
	challengeBytes  int
	prng            io.Reader
}

// NewProtocol constructs a CGGMP21 small-factor proof instance.
//
// The commitment key is the auxiliary Pedersen setup (Nhat, s, t) from
// Figure 26.
//
// The range parameter is ell from Figure 26 and must provide at least 128 bits
// of soundness for Fiat-Shamir use. The slack parameter is epsilon; this
// implementation requires epsilon >= 2*ell so that the documented response
// bounds contain honest transcripts for the full factor range.
func NewProtocol(commitmentKey *intcom.CommitmentKey, rangeBits, slackBits int, prng io.Reader) (*Protocol, error) {
	if err := validateCommitmentKey(commitmentKey); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid commitment key")
	}
	if rangeBits%8 != 0 || slackBits%8 != 0 {
		return nil, ErrInvalidArgument.WithMessage("rangeBits and slackBits must be byte-aligned")
	}
	ringPedersenCommitmentKeyBitLen := commitmentKey.Group().Modulus().TrueLen()
	if ringPedersenCommitmentKeyBitLen%8 != 0 {
		return nil, ErrInvalidArgument.WithMessage("commitment key modulus bit length must be byte-aligned")
	}
	if rangeBits < base.ComputationalSecurityBits || (4*rangeBits) >= ringPedersenCommitmentKeyBitLen {
		return nil, ErrInvalidArgument.WithMessage("rangeBits out of range")
	}
	if slackBits < 2*rangeBits || slackBits > ringPedersenCommitmentKeyBitLen {
		return nil, ErrInvalidArgument.WithMessage("slackBits out of range")
	}
	if prng == nil {
		return nil, ErrInvalidArgument.WithMessage("prng must not be nil")
	}

	return &Protocol{
		name:            sigma.Name(fmt.Sprintf("%s_L=%d_EPS=%d_CK=%s", Name, rangeBits, slackBits, commitmentKeyDigest(commitmentKey))),
		ringPedersenKey: commitmentKey,
		l:               rangeBits,
		epsilon:         slackBits,
		challengeBytes:  rangeBits / 8,
		prng:            prng,
	}, nil
}

// Name returns the protocol identifier.
func (p *Protocol) Name() sigma.Name {
	return p.name
}

// ComputeProverCommitment generates the first prover message.
func (p *Protocol) ComputeProverCommitment(statement *Statement, witness *Witness) (*Commitment, *State, error) {
	if err := p.ValidateStatement(statement, witness); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid statement or witness")
	}

	state, err := p.sampleState(statement)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample prover state")
	}
	commitment, err := p.computeCommitment(witness, state)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute prover commitment")
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
	if commitment == nil {
		return nil, ErrInvalidArgument.WithMessage("commitment must not be nil")
	}
	if state == nil {
		return nil, ErrInvalidArgument.WithMessage("state must not be nil")
	}
	if err := p.validateCommitment(commitment); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid commitment")
	}
	expected, err := p.computeCommitment(witness, state)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute expected commitment")
	}
	if !commitment.Equal(expected) {
		return nil, ErrValidationFailed.WithMessage("commitment and state mismatch")
	}
	e, err := p.mapChallenge(challenge)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid challenge")
	}

	pFactor, qFactor, err := paillierKeyFactors(witness.secretKey)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not extract witness factors")
	}
	response, err := NewResponse(
		state.alpha.Add(e.Mul(pFactor)),
		state.beta.Add(e.Mul(qFactor)),
		state.x.Add(e.Mul(state.mu)),
		state.y.Add(e.Mul(state.nu)),
		state.r.Sub(e.Mul(state.nu).Mul(pFactor)),
	)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create response")
	}
	return response, nil
}

// Verify checks a prover response against the statement and commitment.
func (p *Protocol) Verify(statement *Statement, commitment *Commitment, challenge sigma.ChallengeBytes, response *Response) error {
	if statement == nil {
		return ErrInvalidArgument.WithMessage("statement must not be nil")
	}
	if commitment == nil {
		return ErrInvalidArgument.WithMessage("commitment must not be nil")
	}
	if response == nil {
		return ErrInvalidArgument.WithMessage("response must not be nil")
	}
	if err := p.validateStatement(statement); err != nil {
		return errs.Wrap(err).WithMessage("invalid statement")
	}
	if err := p.validateCommitment(commitment); err != nil {
		return errs.Wrap(err).WithMessage("invalid commitment")
	}
	e, err := p.mapChallenge(challenge)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid challenge")
	}

	n0BitLen := statement.publicKey.PlaintextGroup().Modulus().TrueLen()
	nDashBitLen := p.ringPedersenKey.Group().Modulus().TrueLen()
	zBitLenBound := n0BitLen/2 + p.l + p.epsilon
	if !intInSignedBitRange(response.z1, zBitLenBound) || !intInSignedBitRange(response.z2, zBitLenBound) {
		return ErrVerificationFailed.WithMessage("factor responses are out of range")
	}
	// Figure 26 only range-checks z1, z2. w1, w2, v are bounded here as a
	// defensive sanity guard against pathologically large parsed exponents;
	// the +1 admits one bit of carry from honest sums like w1 = x + e*mu
	// where |x| < 2^(l+eps+|Nhat|) and |e*mu| can reach 2^(l-1) * 2^(l+|Nhat|).
	wBitLenBound := nDashBitLen + p.l + p.epsilon + 1
	vBitLenBound := n0BitLen + nDashBitLen + p.l + p.epsilon + 1
	if !intInSignedBitRange(response.w1, wBitLenBound) ||
		!intInSignedBitRange(response.w2, wBitLenBound) ||
		!intInSignedBitRange(response.v, vBitLenBound) {

		return ErrVerificationFailed.WithMessage("randomness responses are out of range")
	}

	pe, err := p.ringPedersenKey.CommitmentScalarOp(commitment.p, e)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not exponentiate P commitment")
	}
	firstCommitment, err := p.ringPedersenKey.CommitmentOp(commitment.a, pe)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute first verification commitment")
	}
	z1Message, err := intcom.NewMessage(response.z1)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create first verification message")
	}
	w1Witness, err := intcom.NewWitness(response.w1)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create first verification witness")
	}
	if err := p.ringPedersenKey.Open(firstCommitment, z1Message, w1Witness); err != nil {
		return errs.Join(ErrVerificationFailed.WithStackFrame(), errs.Wrap(err).WithMessage("first commitment equation failed"))
	}

	qe, err := p.ringPedersenKey.CommitmentScalarOp(commitment.q, e)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not exponentiate Q commitment")
	}
	secondCommitment, err := p.ringPedersenKey.CommitmentOp(commitment.b, qe)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute second verification commitment")
	}
	z2Message, err := intcom.NewMessage(response.z2)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create second verification message")
	}
	w2Witness, err := intcom.NewWitness(response.w2)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create second verification witness")
	}
	if err := p.ringPedersenKey.Open(secondCommitment, z2Message, w2Witness); err != nil {
		return errs.Join(ErrVerificationFailed.WithStackFrame(), errs.Wrap(err).WithMessage("second commitment equation failed"))
	}

	qz1, err := p.ringPedersenKey.CommitmentScalarOp(commitment.q, response.z1)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not exponentiate Q by z1")
	}
	qz1Inv, err := p.ringPedersenKey.CommitmentOpInv(qz1)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not invert Q to the z1")
	}
	modulusCommitment, err := p.commit(statement.publicKey.Group().N().Lift(), num.Z().Zero())
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute statement modulus commitment")
	}
	modulusCommitmentE, err := p.ringPedersenKey.CommitmentScalarOp(modulusCommitment, e)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not exponentiate statement modulus commitment")
	}
	productCommitment, err := p.ringPedersenKey.CommitmentOp(commitment.t, modulusCommitmentE, qz1Inv)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute product verification commitment")
	}
	zeroMessage, err := intcom.NewMessage(num.Z().Zero())
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create product verification message")
	}
	vWitness, err := intcom.NewWitness(response.v)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create product verification witness")
	}
	if err := p.ringPedersenKey.Open(productCommitment, zeroMessage, vWitness); err != nil {
		return errs.Join(ErrVerificationFailed.WithStackFrame(), errs.Wrap(err).WithMessage("product commitment equation failed"))
	}

	return nil
}

// RunSimulator creates an honest-verifier simulated transcript for a fixed challenge.
func (p *Protocol) RunSimulator(statement *Statement, challenge sigma.ChallengeBytes) (*Commitment, *Response, error) {
	if statement == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("statement must not be nil")
	}
	if err := p.validateStatement(statement); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid statement")
	}
	e, err := p.mapChallenge(challenge)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid challenge")
	}

	zBitLenBound := statement.publicKey.PlaintextGroup().Modulus().TrueLen()/2 + p.l + p.epsilon
	wBitLenBound := p.ringPedersenKey.Group().Modulus().TrueLen() + p.l + p.epsilon
	vBitLenBound := statement.publicKey.PlaintextGroup().Modulus().TrueLen() + p.ringPedersenKey.Group().Modulus().TrueLen() + p.l + p.epsilon
	sigmaBitLenBound := statement.publicKey.PlaintextGroup().Modulus().TrueLen() + p.ringPedersenKey.Group().Modulus().TrueLen() + p.l

	sigmaP, err := intSampleRangeSymmetricBits(sigmaBitLenBound, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample P exponent")
	}
	sigmaQ, err := intSampleRangeSymmetricBits(sigmaBitLenBound, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample Q exponent")
	}

	z1, err := intSampleRangeSymmetricBits(zBitLenBound, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample z1")
	}
	z2, err := intSampleRangeSymmetricBits(zBitLenBound, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample z2")
	}
	w1, err := intSampleRangeSymmetricBits(wBitLenBound, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample w1")
	}
	w2, err := intSampleRangeSymmetricBits(wBitLenBound, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample w2")
	}
	v, err := intSampleRangeSymmetricBits(vBitLenBound, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample v")
	}
	response, err := NewResponse(z1, z2, w1, w2, v)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create response")
	}

	pCommitment, err := p.commit(num.Z().Zero(), sigmaP)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated P")
	}
	qCommitment, err := p.commit(num.Z().Zero(), sigmaQ)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated Q")
	}

	eNeg := e.Neg()
	z1Commitment, err := p.commit(response.z1, response.w1)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated A response commitment")
	}
	pNegE, err := p.ringPedersenKey.CommitmentScalarOp(pCommitment, eNeg)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not exponentiate simulated P")
	}
	aCommitment, err := p.ringPedersenKey.CommitmentOp(z1Commitment, pNegE)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated A")
	}

	z2Commitment, err := p.commit(response.z2, response.w2)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated B response commitment")
	}
	qNegE, err := p.ringPedersenKey.CommitmentScalarOp(qCommitment, eNeg)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not exponentiate simulated Q")
	}
	bCommitment, err := p.ringPedersenKey.CommitmentOp(z2Commitment, qNegE)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated B")
	}

	qz1, err := p.ringPedersenKey.CommitmentScalarOp(qCommitment, response.z1)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not exponentiate simulated Q by z1")
	}
	tv, err := p.commit(num.Z().Zero(), response.v)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated product randomness commitment")
	}
	modulusCommitment, err := p.commit(statement.publicKey.Group().N().Lift(), num.Z().Zero())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute statement modulus commitment")
	}
	modulusNegE, err := p.ringPedersenKey.CommitmentScalarOp(modulusCommitment, eNeg)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not exponentiate statement modulus commitment")
	}
	tCommitment, err := p.ringPedersenKey.CommitmentOp(qz1, tv, modulusNegE)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute simulated T")
	}

	commitment, err := NewCommitment(pCommitment, qCommitment, aCommitment, bCommitment, tCommitment)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create commitment")
	}
	return commitment, response, nil
}

// SpecialSoundness returns the protocol extraction parameter.
func (*Protocol) SpecialSoundness() uint {
	return 2
}

// SoundnessError returns the statistical soundness error in bits.
func (p *Protocol) SoundnessError() uint {
	return uint(p.l)
}

// GetChallengeBytesLength returns the challenge size in bytes.
func (p *Protocol) GetChallengeBytesLength() int {
	return p.challengeBytes
}

// ValidateStatement checks that the public modulus and witness factors match.
func (p *Protocol) ValidateStatement(statement *Statement, witness *Witness) error {
	if statement == nil {
		return ErrInvalidArgument.WithMessage("statement must not be nil")
	}
	if witness == nil {
		return ErrInvalidArgument.WithMessage("witness must not be nil")
	}
	if err := p.validateStatement(statement); err != nil {
		return errs.Wrap(err).WithMessage("invalid statement")
	}
	if err := p.validateWitness(statement, witness); err != nil {
		return errs.Wrap(err).WithMessage("invalid witness")
	}
	return nil
}

func (p *Protocol) sampleState(statement *Statement) (*State, error) {
	nDashBitLen := p.ringPedersenKey.Group().Modulus().TrueLen()
	n0BitLen := statement.publicKey.PlaintextGroup().Modulus().TrueLen()

	alpha, err := intSampleRangeSymmetricBits(p.l+p.epsilon+n0BitLen/2, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample alpha")
	}
	beta, err := intSampleRangeSymmetricBits(p.l+p.epsilon+n0BitLen/2, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample beta")
	}
	mu, err := intSampleRangeSymmetricBits(p.l+nDashBitLen, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample mu")
	}
	nu, err := intSampleRangeSymmetricBits(p.l+nDashBitLen, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample nu")
	}
	r, err := intSampleRangeSymmetricBits(p.l+p.epsilon+n0BitLen+nDashBitLen, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample r")
	}
	x, err := intSampleRangeSymmetricBits(p.l+p.epsilon+nDashBitLen, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample x")
	}
	y, err := intSampleRangeSymmetricBits(p.l+p.epsilon+nDashBitLen, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample y")
	}

	state, err := NewState(alpha, beta, mu, nu, r, x, y)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create state")
	}
	return state, nil
}

func (p *Protocol) computeCommitment(witness *Witness, state *State) (*Commitment, error) {
	pInt, qInt, err := paillierKeyFactors(witness.secretKey)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not extract witness factors")
	}
	pCommitment, err := p.commit(pInt, state.mu)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute P commitment")
	}
	qCommitment, err := p.commit(qInt, state.nu)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute Q commitment")
	}
	aCommitment, err := p.commit(state.alpha, state.x)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute A commitment")
	}
	bCommitment, err := p.commit(state.beta, state.y)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute B commitment")
	}
	qAlpha, err := p.ringPedersenKey.CommitmentScalarOp(qCommitment, state.alpha)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not exponentiate Q commitment")
	}
	tR, err := p.commit(num.Z().Zero(), state.r)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute T randomness commitment")
	}
	tCommitment, err := p.ringPedersenKey.CommitmentOp(qAlpha, tR)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute T commitment")
	}

	commitment, err := NewCommitment(pCommitment, qCommitment, aCommitment, bCommitment, tCommitment)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create commitment")
	}
	return commitment, nil
}

func (p *Protocol) commit(messageValue, witnessValue *num.Int) (*intcom.Commitment, error) {
	message, err := intcom.NewMessage(messageValue)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create commitment message")
	}
	witness, err := intcom.NewWitness(witnessValue)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create commitment witness")
	}
	commitment, err := p.ringPedersenKey.CommitWithWitness(message, witness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not commit")
	}
	return commitment, nil
}

func (p *Protocol) mapChallenge(challenge sigma.ChallengeBytes) (*num.Int, error) {
	if len(challenge) != p.challengeBytes {
		return nil, ErrInvalidArgument.WithMessage("invalid challenge length")
	}

	// Fiat-Shamir supplies exactly ell bits. Interpreting those bytes as a
	// signed integer gives a byte-aligned challenge space of cardinality 2^ell.
	out, err := num.Z().FromTwosComplementBytesBE(challenge)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not parse challenge")
	}
	return out, nil
}

func validatePublicKey(publicKey *paillier.PublicKey) error {
	if publicKey == nil || publicKey.Group() == nil {
		return ErrInvalidArgument.WithMessage("public key must not be nil")
	}
	if publicKey.PlaintextGroup().Modulus().TrueLen()%8 != 0 {
		return ErrValidationFailed.WithMessage("public key modulus bit length must be byte-aligned")
	}
	return nil
}

func (p *Protocol) validateStatement(statement *Statement) error {
	if statement.publicKey.PlaintextGroup().Modulus().TrueLen() <= 4*p.l {
		return ErrValidationFailed.WithMessage("public key modulus too small")
	}
	return nil
}

func validateCommitmentKey(commitmentKey *intcom.CommitmentKey) error {
	if commitmentKey == nil {
		return ErrInvalidArgument.WithMessage("commitment key must not be nil")
	}
	s := commitmentKey.S()
	t := commitmentKey.T()
	if s == nil || t == nil {
		return ErrInvalidArgument.WithMessage("s and t must not be nil")
	}
	group := s.Group()
	if group == nil || t.Group() == nil {
		return ErrInvalidArgument.WithMessage("s and t groups must not be nil")
	}
	if !group.Contains(t) {
		return ErrValidationFailed.WithMessage("s and t must belong to the same RSA group")
	}
	if s.Equal(t) {
		return ErrValidationFailed.WithMessage("s and t must be distinct")
	}
	if s.IsOne() || t.IsOne() {
		return ErrValidationFailed.WithMessage("s and t must not be the identity")
	}
	if !s.IsTorsionFree() || !t.IsTorsionFree() {
		return ErrValidationFailed.WithMessage("s and t must be torsion-free")
	}
	if !s.Value().Decrement().Nat().Coprime(s.Modulus().Nat()) {
		return ErrValidationFailed.WithMessage("s - 1 must be coprime to Nhat")
	}
	if !t.Value().Decrement().Nat().Coprime(t.Modulus().Nat()) {
		return ErrValidationFailed.WithMessage("t - 1 must be coprime to Nhat")
	}
	return nil
}

func (*Protocol) validateWitness(statement *Statement, witness *Witness) error {
	if !witness.secretKey.Public().Equal(statement.publicKey) {
		return ErrValidationFailed.WithMessage("secret key does not match statement")
	}

	pFactor, qFactor, err := paillierKeyFactors(witness.secretKey)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not extract witness factors")
	}
	product, err := num.NPlus().FromNat(pFactor.Abs().Mul(qFactor.Abs()))
	if err != nil {
		return errs.Wrap(err).WithMessage("could not compute factor product")
	}
	if !product.Equal(statement.publicKey.Group().N()) {
		return ErrValidationFailed.WithMessage("p and q do not factor the statement modulus")
	}

	// paillier.SecretKey wraps a known-order Paillier group whose factors have
	// equal bit length. Once p*q=N0 is checked, that balanced shape satisfies
	// Figure 26's |p|,|q| < sqrt(N0)*2^ell factor bound for this protocol's ell.
	return nil
}

func (p *Protocol) validateCommitment(commitment *Commitment) error {
	group := p.ringPedersenKey.CommitmentGroup()
	for _, elem := range []*intcom.Commitment{commitment.p, commitment.q, commitment.a, commitment.b, commitment.t} {
		if !group.Contains(elem.Value()) {
			return ErrValidationFailed.WithMessage("commitment element is not in the statement group")
		}
	}
	return nil
}
