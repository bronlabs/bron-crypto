package gjkr07

import (
	"encoding/binary"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/batch_schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/errs-go/errs"
)

const proverIDLabel = "BRON_CRYPTO_DKG_GENNARO_PROVER_ID-"

func (p *Participant[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]) Round1() (*Round1Broadcast[LFTDF, LFTS, LFTSV, SV, AC], error) {
	if p.round != 1 {
		return nil, ErrRound.WithMessage("expected round 1, got round %d", p.round)
	}
	var err error
	p.state.localPedersenDealerOutput, p.state.localSecret, p.state.pedersenDealerFunc, err = p.state.pedersenVSS.DealRandomAndRevealDealerFunc(p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to deal random and reveal dealer function")
	}
	var ok bool
	p.state.localShare, ok = p.state.localPedersenDealerOutput.Shares().Get(p.SharingID())
	if !ok {
		return nil, ErrFailed.WithMessage("failed to get my pedersen share")
	}
	p.round++
	return &Round1Broadcast[LFTDF, LFTS, LFTSV, SV, AC]{
		PedersenVerificationVector: p.state.localPedersenDealerOutput.VerificationVector(),
	}, nil
}

func (p *Participant[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]) Round2(r2bin network.RoundMessages[*Round1Broadcast[LFTDF, LFTS, LFTSV, SV, AC]]) (*Round2Broadcast[LFTDF, LFTS, LFTSV, SV, AC], network.OutgoingUnicasts[*Round2Unicast[S, SV]], error) {
	if p.round != 2 {
		return nil, nil, ErrRound.WithMessage("expected round 2, got %d", p.round)
	}
	var err error
	r2uo := hashmap.NewComparable[sharing.ID, *Round2Unicast[S, SV]]()
	for pid := range p.ac.Shareholders().Iter() {
		if pid == p.SharingID() {
			continue // skip myself
		}
		inB, _ := r2bin.Get(pid)
		p.state.receivedPedersenVerificationVectors[pid] = inB.PedersenVerificationVector

		shareForThisParty, exists := p.state.localPedersenDealerOutput.Shares().Get(pid)
		if !exists {
			return nil, nil, ErrFailed.WithMessage("missing pedersen share for party %d", pid)
		}
		r2uo.Put(pid, &Round2Unicast[S, SV]{
			Share: shareForThisParty,
		})
	}

	secretsDealerFunc := p.state.pedersenDealerFunc.Shares()
	// In polynomial-based threshold access structures, linear representation of the dealer function is the coefficients of the underlying polynomial.
	secretsDealerFuncRepr := slices.Collect(secretsDealerFunc.Repr())

	p.state.localFeldmanVerificationVector, err = p.state.feldmanVSS.UnderlyingLSSS().LiftDealerFunc(secretsDealerFunc, p.state.key.G())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to lift pedersen dealer function to exponent")
	}

	// In polynomial-based threshold access structures, this would be coefficients of the underlying polynomial in the exponent.
	localFeldmanVerificationVectorRepr := slices.Collect(p.state.localFeldmanVerificationVector.Repr())

	batchSchnorrProtocol, err := batch_schnorr.NewProtocol(len(secretsDealerFuncRepr), p.state.key.Group(), p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create batch schnorr protocol")
	}
	niBatchSchnorr, err := compiler.Compile(p.niCompilerName, batchSchnorrProtocol, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot compile protocol to non interactive")
	}
	proverTape := p.ctx.Transcript().Clone()
	proverTape.AppendBytes(proverIDLabel, binary.LittleEndian.AppendUint64(nil, uint64(p.SharingID())))
	prover, err := niBatchSchnorr.NewProver(p.ctx.SessionID(), proverTape)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create batch schnorr prover")
	}

	witness := batch_schnorr.NewWitness(secretsDealerFuncRepr...)
	statement := batch_schnorr.NewStatement(p.state.key.G(), localFeldmanVerificationVectorRepr...)
	proof, err := prover.Prove(statement, witness)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot prove batch schnorr statement")
	}

	p.round++
	return &Round2Broadcast[LFTDF, LFTS, LFTSV, SV, AC]{
		FeldmanVerificationVector: p.state.localFeldmanVerificationVector,
		Proof:                     proof,
	}, r2uo.Freeze(), nil
}

func (p *Participant[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]) Round3(r3bi network.RoundMessages[*Round2Broadcast[LFTDF, LFTS, LFTSV, SV, AC]], r3ui network.RoundMessages[*Round2Unicast[S, SV]]) (*DKGOutput[LFTDF, LFTS, LFTSV, S, SV, AC], error) {
	if p.round != 3 {
		return nil, ErrRound.WithMessage("expected round 3, got %d", p.round)
	}

	localFeldmanVerificationVectorRepr := slices.Collect(p.state.localFeldmanVerificationVector.Repr())
	batchSchnorrProtocol, err := batch_schnorr.NewProtocol(len(localFeldmanVerificationVectorRepr), p.state.key.Group(), p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create batch schnorr protocol")
	}
	niBatchSchnorr, err := compiler.Compile(p.niCompilerName, batchSchnorrProtocol, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compile protocol to non interactive")
	}

	summedShareRepr := slices.Collect(p.state.localShare.Secret().Repr())
	summedFeldmanVerificationVector := p.state.localFeldmanVerificationVector
	for pid := range p.ac.Shareholders().Iter() {
		if pid == p.SharingID() {
			continue // skip myself
		}

		inB, _ := r3bi.Get(pid)
		inU, _ := r3ui.Get(pid)

		// Verify pedersen vss share
		referencePedersenVector := p.state.receivedPedersenVerificationVectors[pid]
		if err := p.state.pedersenVSS.Verify(inU.Share, referencePedersenVector); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pid).WithMessage("failed to verify pedersen share from party %d", pid)
		}

		// Verify feldman vss share
		if err := p.state.feldmanVSS.Verify(inU.Share.Secret(), inB.FeldmanVerificationVector); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pid).WithMessage("failed to verify feldman share from party %d", pid)
		}

		// Verify batch dlog proof
		verifierTape := p.ctx.Transcript().Clone()
		verifierTape.AppendBytes(proverIDLabel, binary.LittleEndian.AppendUint64(nil, uint64(pid)))
		verifier, err := niBatchSchnorr.NewVerifier(p.ctx.SessionID(), verifierTape)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create batch schnorr verifier")
		}
		receivedFeldmanVectorRepr := slices.Collect(inB.FeldmanVerificationVector.Repr())
		statement := batch_schnorr.NewStatement(p.state.key.G(), receivedFeldmanVectorRepr...)
		err = verifier.Verify(statement, inB.Proof)
		if err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pid).WithMessage("failed to verify feldman verification vector")
		}
		p.state.receivedFeldmanVerificationVectors[pid] = inB.FeldmanVerificationVector

		// Summing up
		receivedSecretShareRepr := slices.Collect(inU.Share.Secret().Repr())
		for i := range summedShareRepr {
			summedShareRepr[i] = summedShareRepr[i].Add(receivedSecretShareRepr[i])
		}
		summedFeldmanVerificationVector = summedFeldmanVerificationVector.Op(inB.FeldmanVerificationVector)
	}
	outputShare, err := p.state.feldmanVSS.UnderlyingLSSS().NewShareFromRepr(p.SharingID(), slices.Values(summedShareRepr))
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
