package gennaro

import (
	"encoding/binary"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/batch_schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/okamoto"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compose/sigand"
	"github.com/bronlabs/errs-go/errs"
)

const (
	batchOkamotoProverIDLabel = "BRON_CRYPTO_DKG_GENNARO_BATCH_OKAMOTO_PROVER_ID-"
	batchSchnorrProverIDLabel = "BRON_CRYPTO_DKG_GENNARO_BATCH_SCHNORR_PROVER_ID-"
)

// Round1 runs the dealer step and broadcasts the Pedersen verification vector.
func (p *Participant[E, S]) Round1() (*Round1Broadcast[E, S], network.OutgoingUnicasts[*Round1Unicast[E, S], *Participant[E, S]], error) {
	if p.round != 1 {
		return nil, nil, ErrRound.WithMessage("expected round 1, got %d", p.round)
	}

	// Pedersen VSS dealing
	var err error
	p.state.localPedersenDealerOutput, p.state.localSecret, p.state.pedersenDealerFunc, err = p.state.pedersenVSS.DealRandomAndRevealDealerFunc(p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to deal random and reveal dealer function")
	}
	secretsPolynomial, blindingPolynomial := p.state.pedersenDealerFunc.Components()[0], p.state.pedersenDealerFunc.Components()[1]
	pedersenVerificationVector := p.state.localPedersenDealerOutput.VerificationVector()

	// My own local share
	var ok bool
	p.state.localShare, ok = p.state.localPedersenDealerOutput.Shares().Get(p.ctx.HolderID())
	if !ok {
		return nil, nil, ErrFailed.WithMessage("failed to get my pedersen share")
	}

	// Other people's shares
	r1uo := hashmap.NewComparable[sharing.ID, *Round1Unicast[E, S]]()
	for pid := range p.ctx.OtherPartiesOrdered() {
		shareForThisParty, exists := p.state.localPedersenDealerOutput.Shares().Get(pid)
		if !exists {
			return nil, nil, ErrFailed.WithMessage("missing pedersen share for party %d", pid)
		}
		r1uo.Put(pid, &Round1Unicast[E, S]{
			Share: shareForThisParty,
		})
	}

	// Proof of knowledge of opening
	okamotoProtocol, err := okamoto.NewProtocol([]E{p.state.key.G(), p.state.key.H()}, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to create okamoto protocol")
	}
	batchOkamotoProtocol, err := sigand.Compose(okamotoProtocol, uint(secretsPolynomial.Degree()+1))
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to compose okamoto protocol")
	}
	niBatchOkamoto, err := compiler.Compile(p.niCompilerName, batchOkamotoProtocol, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to compile okamoto protocol to non-interactive")
	}
	proverCtx := p.ctx.Clone()
	proverCtx.Transcript().AppendBytes(batchOkamotoProverIDLabel, binary.LittleEndian.AppendUint64(nil, uint64(p.ctx.HolderID())))
	prover, err := niBatchOkamoto.NewProver(proverCtx)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to create okamoto prover")
	}
	secretsPolynomialCoeffs := secretsPolynomial.Coefficients()
	blindingPolynomialCoeffs := blindingPolynomial.Coefficients()
	witnesses := make([]*okamoto.Witness[S], len(secretsPolynomialCoeffs))
	statements := make([]*okamoto.Statement[E, S], len(secretsPolynomialCoeffs))
	for i, ci := range secretsPolynomialCoeffs {
		bi := blindingPolynomialCoeffs[i]
		witnesses[i], err = okamoto.NewWitness(ci, bi)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("failed to create okamoto witness for coefficient %d", i)
		}
		statements[i] = okamoto.NewStatement(pedersenVerificationVector.Coefficients()[i])
	}
	witness := sigand.ComposeWitnesses(witnesses...)
	statement := sigand.ComposeStatements(statements...)
	proof, err := prover.Prove(statement, witness)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to create okamoto proof")
	}

	p.round++
	return &Round1Broadcast[E, S]{
		PedersenVerificationVector: pedersenVerificationVector,
		Proof:                      proof,
	}, r1uo.Freeze(), nil
}

// Round2 shares Pedersen openings privately and proves correctness of Feldman vector.
func (p *Participant[E, S]) Round2(r2bin network.RoundMessages[*Round1Broadcast[E, S], *Participant[E, S]], r2uin network.RoundMessages[*Round1Unicast[E, S], *Participant[E, S]]) (*Round2Broadcast[E, S], error) {
	if p.round != 2 {
		return nil, ErrRound.WithMessage("expected round 2, got %d", p.round)
	}
	if errB := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), r2bin); errB != nil {
		return nil, errs.Wrap(errB)
	}
	if errU := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), r2uin); errU != nil {
		return nil, errs.Wrap(errU)
	}

	localSecretsPolynomial := p.state.pedersenDealerFunc.Components()[0]
	var err error
	p.state.summedShareValue = p.state.localShare.Value()
	for pid := range p.ctx.OtherPartiesOrdered() {
		inB, _ := r2bin.Get(pid)
		inU, _ := r2uin.Get(pid)

		// Verify Okamoto proof of knowledge of opening
		okamotoProtocol, err := okamoto.NewProtocol([]E{p.state.key.G(), p.state.key.H()}, p.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create okamoto protocol")
		}
		batchOkamotoProtocol, err := sigand.Compose(okamotoProtocol, uint(localSecretsPolynomial.Degree()+1))
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to compose okamoto protocol")
		}
		niBatchOkamoto, err := compiler.Compile(p.niCompilerName, batchOkamotoProtocol, p.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to compile okamoto protocol to non-interactive")
		}
		verifierCtx := p.ctx.Clone()
		verifierCtx.Transcript().AppendBytes(batchOkamotoProverIDLabel, binary.LittleEndian.AppendUint64(nil, uint64(pid)))
		verifier, err := niBatchOkamoto.NewVerifier(verifierCtx)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create okamoto verifier")
		}
		if err := verifier.Verify(
			sigand.ComposeStatements(sliceutils.Map(inB.PedersenVerificationVector.Coefficients(), okamoto.NewStatement)...),
			inB.Proof,
		); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pid).WithMessage("failed to verify okamoto proof of knowledge of opening from party %d", pid)
		}

		// Verify Share
		if err := p.state.pedersenVSS.Verify(inU.Share, inB.PedersenVerificationVector); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pid).WithMessage("failed to verify pedersen share from party %d", pid)
		}
		p.state.receivedShares[pid] = inU.Share

		// Accumulate shares for final key material
		p.state.summedShareValue = p.state.summedShareValue.Add(inU.Share.Value())
	}

	// Produce Feldman verification vector for the same polynomial
	p.state.localFeldmanVerificationVector, err = polynomials.LiftPolynomial(localSecretsPolynomial, p.state.key.G())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to lift pedersen dealer function to exponent")
	}

	// Produce batch schnorr proof of knowledge of Feldman verification vector's coefficients' dlog.
	batchSchnorrProtocol, err := batch_schnorr.NewProtocol(int(p.AccessStructure().Threshold()), p.state.key.Group(), p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create batch schnorr protocol")
	}
	niBatchSchnorr, err := compiler.Compile(p.niCompilerName, batchSchnorrProtocol, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compile protocol to non interactive")
	}
	proverCtx := p.ctx.Clone()
	proverCtx.Transcript().AppendBytes(batchSchnorrProverIDLabel, binary.LittleEndian.AppendUint64(nil, uint64(p.ctx.HolderID())))
	prover, err := niBatchSchnorr.NewProver(proverCtx)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create batch schnorr prover")
	}

	witness := batch_schnorr.NewWitness(localSecretsPolynomial.Coefficients()...)
	statement := batch_schnorr.NewStatement(p.state.key.G(), p.state.localFeldmanVerificationVector.Coefficients()...)
	proof, err := prover.Prove(statement, witness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot prove batch schnorr statement")
	}

	p.round++
	return &Round2Broadcast[E, S]{
		FeldmanVerificationVector: p.state.localFeldmanVerificationVector,
		Proof:                     proof,
	}, nil
}

// Round3 verifies all incoming shares and proofs and outputs the joint key material.
func (p *Participant[E, S]) Round3(r3bi network.RoundMessages[*Round2Broadcast[E, S], *Participant[E, S]]) (*DKGOutput[E, S], error) {
	if p.round != 3 {
		return nil, ErrRound.WithMessage("expected round 3, got %d", p.round)
	}
	if errB := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), r3bi); errB != nil {
		return nil, errs.Wrap(errB)
	}

	batchSchnorrProtocol, err := batch_schnorr.NewProtocol(int(p.AccessStructure().Threshold()), p.state.key.Group(), p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create batch schnorr protocol")
	}
	niBatchSchnorr, err := compiler.Compile(p.niCompilerName, batchSchnorrProtocol, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compile protocol to non interactive")
	}

	summedFeldmanVerificationVector := p.state.localFeldmanVerificationVector
	for pid := range p.ctx.OtherPartiesOrdered() {
		inB, _ := r3bi.Get(pid)

		// Verify batch schnorr proof of knowledge of Feldman verification vector's coefficients' dlog.
		verifierCtx := p.ctx.Clone()
		verifierCtx.Transcript().AppendBytes(batchSchnorrProverIDLabel, binary.LittleEndian.AppendUint64(nil, uint64(pid)))
		verifier, err := niBatchSchnorr.NewVerifier(verifierCtx)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create batch schnorr verifier")
		}
		statement := batch_schnorr.NewStatement(p.state.key.G(), inB.FeldmanVerificationVector.Coefficients()...)
		err = verifier.Verify(statement, inB.Proof)
		if err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pid).WithMessage("failed to verify feldman verification vector")
		}

		// Verify Feldman Share
		feldmanShare, _ := feldman.NewShare(p.state.receivedShares[pid].ID(), p.state.receivedShares[pid].Value(), nil)
		if err := p.state.feldmanVSS.Verify(feldmanShare, inB.FeldmanVerificationVector); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pid).WithMessage("failed to verify feldman share from party %d", pid)
		}

		// Accumulate Feldman verification vectors for final output
		summedFeldmanVerificationVector = summedFeldmanVerificationVector.Op(inB.FeldmanVerificationVector)
	}
	outputShare, err := feldman.NewShare(p.ctx.HolderID(), p.state.summedShareValue, nil)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create output feldman share")
	}
	out, err := NewDKGOutput(outputShare, summedFeldmanVerificationVector, p.ac)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create DKG output")
	}
	p.round++
	return out, nil
}
