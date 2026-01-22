package lp

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/nthroot"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compose/sigand"
)

// Round1 executes the verifier's first round.
func (verifier *Verifier) Round1() (output *Round1Output, err error) {
	if verifier.Round != 1 {
		return nil, ErrRound.WithMessage("%d != 1", verifier.Round)
	}

	rootTranscript := verifier.Transcript.Clone()

	zero, err := verifier.paillierPublicKey.PlaintextSpace().FromNat(numct.NatZero())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create plaintext zero")
	}
	// V picks x = y^N mod N^2 which is the Paillier encryption of zero (N being the Paillier public-key)
	zeros := sliceutils.Repeat[[]*paillier.Plaintext](zero, verifier.k)
	ciphertexts, nonces, err := verifier.enc.EncryptMany(zeros, verifier.paillierPublicKey, verifier.Prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("encryption failed")
	}

	verifier.state.x = sigand.ComposeStatements(slices.Collect(iterutils.Map(slices.Values(ciphertexts), func(x *paillier.Ciphertext) *nthroot.Statement[*modular.SimpleModulus] {
		return nthroot.NewStatement(x.Value())
	}))...)
	verifier.state.y = sigand.ComposeWitnesses(slices.Collect(iterutils.Map(slices.Values(nonces), func(y *paillier.Nonce) *nthroot.Witness[*modular.SimpleModulus] {
		embeddedNonce, err := verifier.paillierPublicKey.Group().EmbedRSA(y.Value())
		if err != nil {
			panic(err)
		}
		return nthroot.NewWitness(embeddedNonce)
	}))...)
	verifier.state.rootsProver, err = sigma.NewProver(verifier.SessionID, rootTranscript.Clone(), verifier.multiNthRootsProtocol, verifier.state.x, verifier.state.y)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create sigma protocol prover")
	}

	nthRootProverRound1Output, err := verifier.state.rootsProver.Round1()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 1 of Nth root prover")
	}

	verifier.Round += 2
	return &Round1Output{
		NthRootsProverOutput: nthRootProverRound1Output,
		X:                    verifier.state.x,
	}, nil
}

// Round2 executes the prover's second round.
func (prover *Prover) Round2(input *Round1Output) (output *Round2Output, err error) {
	if prover.Round != 2 {
		return nil, ErrRound.WithMessage("%d != 2", prover.Round)
	}
	if err := input.Validate(prover.k); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid round 2 input")
	}

	// prover.state.x = input.X
	prover.state.x = make([]*nthroot.Statement[*modular.OddPrimeSquareFactors], prover.k)
	for i, x := range input.X {
		prover.state.x[i], err = nthRootStatementLearnOrder(x, prover.paillierSecretKey.Group())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create statement with known order")
		}
	}
	rootTranscript := prover.Transcript.Clone()
	prover.state.rootsVerifier, err = sigma.NewVerifier(prover.SessionID, rootTranscript.Clone(), prover.multiNthRootsProtocol, prover.state.x, prover.Prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Nth root verifier")
	}

	commitments := make([]*nthroot.Commitment[*modular.OddPrimeSquareFactors], prover.k)
	for i, a := range input.NthRootsProverOutput {
		commitments[i], err = nthRootCommitmentLearnOrder(a, prover.paillierSecretKey.Group())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create commitment with known order")
		}
	}
	nthRootVerifierRound2Output, err := prover.state.rootsVerifier.Round2(commitments)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 2 of Nth root verifier")
	}

	prover.Round += 2
	return &Round2Output{
		NthRootsVerifierOutput: nthRootVerifierRound2Output,
	}, nil
}

// Round3 executes the verifier's third round.
func (verifier *Verifier) Round3(input *Round2Output) (output *Round3Output, err error) {
	if verifier.Round != 3 {
		return nil, ErrRound.WithMessage("%d != 3", verifier.Round)
	}
	nthRootProverRound3Output, err := verifier.state.rootsProver.Round3(input.NthRootsVerifierOutput)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 3 of Nth root prover")
	}

	verifier.Round += 2
	return &Round3Output{
		NthRootsProverOutput: nthRootProverRound3Output,
	}, nil
}

// Round4 executes the prover's fourth round.
func (prover *Prover) Round4(input *Round3Output) (output *Round4Output, err error) {
	if prover.Round != 4 {
		return nil, ErrRound.WithMessage("%d != 4", prover.Round)
	}
	// round 4 of proving the knowledge of y
	responses := make([]*nthroot.Response[*modular.OddPrimeSquareFactors], prover.k)
	for i, z := range input.NthRootsProverOutput {
		responses[i], err = nthRootResponseLearnOrder(z, prover.paillierSecretKey.Group())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create response with known order")
		}
	}
	if err := prover.state.rootsVerifier.Verify(responses); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot verify knowledge of Nth root from Verifier")
	}

	// P calculates a y', the Nth root of x
	// Computing in (Z/NZ)* using CrtModN, with exponent = N^(-1) mod φ(N)
	// see: Yehuda Lindell's answer (https://crypto.stackexchange.com/a/46745) for reference
	var m numct.Nat
	prover.paillierSecretKey.Arithmetic().CrtModN.Phi.ModInv(&m, prover.paillierSecretKey.Group().N().Value())

	// TODO: clean up and put in a helper
	yPrime := make([]*numct.Nat, prover.k)
	for i := range yPrime {
		yPrime[i] = numct.NewNat(0)
	}
	prover.paillierSecretKey.Arithmetic().CrtModN.MultiBaseExp(
		yPrime,
		sliceutils.MapCast[[]*numct.Nat](prover.state.x, func(s *nthroot.Statement[*modular.OddPrimeSquareFactors]) *numct.Nat { return s.X.Value().Value() }),
		&m,
	)

	// P returns a y'
	prover.Round += 2
	return &Round4Output{
		YPrime: yPrime,
	}, nil
}

// Round5 executes the verifier's final round.
func (verifier *Verifier) Round5(input *Round4Output) (err error) {
	// Validation
	if verifier.Round != 5 {
		return ErrRound.WithMessage("%d != 5", verifier.Round)
	}
	if err := input.Validate(verifier.k); err != nil {
		return errs.Wrap(err).WithMessage("invalid round 5 input")
	}

	ok := ct.True
	for i := range verifier.k {
		// Reduce y mod N for comparison (yPrime is computed mod N, but y is in (Z/N²Z)*)
		var yModN numct.Nat
		verifier.paillierPublicKey.N().Mod(&yModN, verifier.state.y[i].W.Value().Value())
		ok &= input.YPrime[i].Equal(&yModN)
	}
	if ok == ct.False {
		return ErrVerificationFailed.WithMessage("failed to verify Paillier public key")
	}

	// V accepts if every y_i == y'_i
	verifier.Round += 2
	return nil
}
