package lp

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/nthroots"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compose/sigand"
)

func (verifier *Verifier) Round1() (output *Round1Output, err error) {
	if verifier.Round != 1 {
		return nil, errs.NewRound("%d != 1", verifier.Round)
	}

	rootTranscript := verifier.Transcript.Clone()

	zero, err := verifier.paillierPublicKey.PlaintextSpace().New(numct.NatZero())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create plaintext zero")
	}
	// V picks x = y^N mod N^2 which is the Paillier encryption of zero (N being the Paillier public-key)
	zeros := sliceutils.Repeat[[]*paillier.Plaintext](zero, verifier.k)
	ciphertexts, nonces, err := verifier.enc.EncryptMany(zeros, verifier.paillierPublicKey, verifier.Prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "encryption failed")
	}

	verifier.state.x = sigand.ComposeStatements(slices.Collect(iterutils.Map(slices.Values(ciphertexts), func(x *paillier.Ciphertext) *nthroots.Statement {
		// TODO: simplify once Unit is an interface
		el := nthroots.GroupElement(*x)
		return nthroots.NewStatement(&el)
	}))...)
	verifier.state.y = sigand.ComposeWitnesses(slices.Collect(iterutils.Map(slices.Values(nonces), func(y *paillier.Nonce) *nthroots.Witness {
		el := nthroots.Scalar(*y)
		return nthroots.NewWitness(&el)
	}))...)
	verifier.state.rootsProver, err = sigma.NewProver(verifier.SessionId, rootTranscript.Clone(), verifier.multiNthRootsProtocol, verifier.state.x, verifier.state.y)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create sigma protocol prover")
	}

	nthRootProverRound1Output, err := verifier.state.rootsProver.Round1()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run round 1 of Nth root prover")
	}

	verifier.Round += 2
	return &Round1Output{
		NthRootsProverOutput: nthRootProverRound1Output,
		X:                    verifier.state.x,
	}, nil
}

func (prover *Prover) Round2(input *Round1Output) (output *Round2Output, err error) {
	if prover.Round != 2 {
		return nil, errs.NewRound("%d != 2", prover.Round)
	}
	if err := input.Validate(prover.k); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 2 input")
	}

	prover.state.x = input.X
	rootTranscript := prover.Transcript.Clone()
	prover.state.rootsVerifier, err = sigma.NewVerifier(prover.SessionId, rootTranscript.Clone(), prover.multiNthRootsProtocol, prover.state.x, prover.Prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Nth root verifier")
	}

	nthRootVerifierRound2Output, err := prover.state.rootsVerifier.Round2(input.NthRootsProverOutput)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run round 2 of Nth root verifier")
	}

	prover.Round += 2
	return &Round2Output{
		NthRootsVerifierOutput: nthRootVerifierRound2Output,
	}, nil
}

func (verifier *Verifier) Round3(input *Round2Output) (output *Round3Output, err error) {
	if verifier.Round != 3 {
		return nil, errs.NewRound("%d != 3", verifier.Round)
	}
	nthRootProverRound3Output, err := verifier.state.rootsProver.Round3(input.NthRootsVerifierOutput)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run round 3 of Nth root prover")
	}

	verifier.Round += 2
	return &Round3Output{
		NthRootsProverOutput: nthRootProverRound3Output,
	}, nil
}

func (prover *Prover) Round4(input *Round3Output) (output *Round4Output, err error) {
	if prover.Round != 4 {
		return nil, errs.NewRound("%d != 4", prover.Round)
	}
	// round 4 of proving the knowledge of y
	if err := prover.state.rootsVerifier.Verify(input.NthRootsProverOutput); err != nil {
		return nil, errs.WrapVerification(err, "cannot verify knowledge of Nth root from Verifier")
	}

	// P calculates a y', the Nth root of x
	// see: Yehuda Lindell's answer (https://crypto.stackexchange.com/a/46745) for reference
	var m numct.Nat
	prover.paillierSecretKey.Arithmetic().CrtModN.Phi.ModInv(&m, prover.paillierSecretKey.Group().N().Value())

	var yPrime []*numct.Nat
	prover.paillierSecretKey.Arithmetic().CrtModN.MultiBaseExp(
		yPrime,
		sliceutils.Map[[]*numct.Nat](prover.state.x, func(s *nthroots.Statement) *numct.Nat { return s.X.Value().Value() }),
		&m,
	)

	// P returns a y'
	prover.Round += 2
	return &Round4Output{
		YPrime: yPrime,
	}, nil
}

func (verifier *Verifier) Round5(input *Round4Output) (err error) {
	// Validation
	if verifier.Round != 5 {
		return errs.NewRound("%d != 5", verifier.Round)
	}
	if err := input.Validate(verifier.k); err != nil {
		return errs.WrapValidation(err, "invalid round 5 input")
	}

	for i := 0; i < verifier.k; i++ {
		if input.YPrime[i].Equal(verifier.state.y[i].W.Value().Value()) == 0 {
			// V rejects if y != y'
			return errs.NewVerification("failed to verify Paillier public key")
		}
	}

	// V accepts if every y_i == y'_i
	verifier.Round += 2
	return nil
}
