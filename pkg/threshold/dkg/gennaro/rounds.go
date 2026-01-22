package gennaro

import (
	"encoding/binary"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/batch_schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/errs-go/errs"
)

// Round1 runs the dealer step and broadcasts the Pedersen verification vector.
func (p *Participant[E, S]) Round1() (*Round1Broadcast[E, S], error) {
	if p.round != 1 {
		return nil, ErrRound.WithMessage("expected round 1, got %d", p.round)
	}
	var err error
	p.state.localPedersenDealerOutput, p.state.localSecret, p.state.pedersenDealerFunc, err = p.state.pedersenVSS.DealRandomAndRevealDealerFunc(p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to deal random and reveal dealer function")
	}
	var ok bool
	p.state.localShare, ok = p.state.localPedersenDealerOutput.Shares().Get(p.id)
	if !ok {
		return nil, ErrFailed.WithMessage("failed to get my pedersen share")
	}
	p.round++
	return &Round1Broadcast[E, S]{
		PedersenVerificationVector: p.state.localPedersenDealerOutput.VerificationVector(),
	}, nil
}

// Round2 shares Pedersen openings privately and proves correctness of Feldman vector.
func (p *Participant[E, S]) Round2(r2bin network.RoundMessages[*Round1Broadcast[E, S]]) (*Round2Broadcast[E, S], network.OutgoingUnicasts[*Round2Unicast[E, S]], error) {
	if p.round != 2 {
		return nil, nil, ErrRound.WithMessage("expected round 2, got %d", p.round)
	}
	var err error
	r2uo := hashmap.NewComparable[sharing.ID, *Round2Unicast[E, S]]()
	for pid := range p.ac.Shareholders().Iter() {
		if pid == p.id {
			continue // skip myself
		}
		inB, _ := r2bin.Get(pid)
		p.state.receivedPedersenVerificationVectors.Put(pid, inB.PedersenVerificationVector)

		shareForThisParty, exists := p.state.localPedersenDealerOutput.Shares().Get(pid)
		if !exists {
			return nil, nil, ErrFailed.WithMessage("missing pedersen share for party %d", pid)
		}
		r2uo.Put(pid, &Round2Unicast[E, S]{
			Share: shareForThisParty,
		})
	}
	p.state.localFeldmanVerificationVector, err = polynomials.LiftPolynomial(p.state.pedersenDealerFunc.G, p.state.key.G())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to lift pedersen dealer function to exponent")
	}

	batchSchnorrProtocol, err := batch_schnorr.NewProtocol(int(p.AccessStructure().Threshold()), p.state.key.Group(), p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create batch schnorr protocol")
	}
	niBatchSchnorr, err := compiler.Compile(p.niCompilerName, batchSchnorrProtocol, p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot compile protocol to non interactive")
	}
	proverTape := p.tape.Clone()
	proverTape.AppendBytes(proverIDLabel, binary.LittleEndian.AppendUint64(nil, uint64(p.id)))
	prover, err := niBatchSchnorr.NewProver(p.sid, proverTape)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create batch schnorr prover")
	}

	witness := batch_schnorr.NewWitness(p.state.pedersenDealerFunc.G.Coefficients()...)
	statement := batch_schnorr.NewStatement(p.state.key.G(), p.state.localFeldmanVerificationVector.Coefficients()...)
	proof, err := prover.Prove(statement, witness)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot prove batch schnorr statement")
	}

	p.round++
	return &Round2Broadcast[E, S]{
		FeldmanVerificationVector: p.state.localFeldmanVerificationVector,
		Proof:                     proof,
	}, r2uo.Freeze(), nil
}

// Round3 verifies all incoming shares and proofs and outputs the joint key material.
func (p *Participant[E, S]) Round3(r3bi network.RoundMessages[*Round2Broadcast[E, S]], r3ui network.RoundMessages[*Round2Unicast[E, S]]) (*DKGOutput[E, S], error) {
	if p.round != 3 {
		return nil, ErrRound.WithMessage("expected round 3, got %d", p.round)
	}

	batchSchnorrProtocol, err := batch_schnorr.NewProtocol(int(p.AccessStructure().Threshold()), p.state.key.Group(), p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create batch schnorr protocol")
	}
	niBatchSchnorr, err := compiler.Compile(p.niCompilerName, batchSchnorrProtocol, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compile protocol to non interactive")
	}

	summedShareValue := p.state.localShare.Value()
	summedFeldmanVerificationVector := p.state.localFeldmanVerificationVector
	for pid := range p.ac.Shareholders().Iter() {
		if pid == p.id {
			continue // skip myself
		}

		inB, _ := r3bi.Get(pid)
		verifierTape := p.tape.Clone()
		verifierTape.AppendBytes(proverIDLabel, binary.LittleEndian.AppendUint64(nil, uint64(pid)))
		verifier, err := niBatchSchnorr.NewVerifier(p.sid, verifierTape)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create batch schnorr prover")
		}
		statement := batch_schnorr.NewStatement(p.state.key.G(), inB.FeldmanVerificationVector.Coefficients()...)
		err = verifier.Verify(statement, inB.Proof)
		if err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pid).WithMessage("failed to verify feldman verification vector")
		}
		p.state.receivedFeldmanVerificationVectors.Put(pid, inB.FeldmanVerificationVector)

		inU, _ := r3ui.Get(pid)
		feldmanShare, _ := feldman.NewShare(inU.Share.ID(), inU.Share.Value(), nil)
		if err := p.state.feldmanVSS.Verify(feldmanShare, inB.FeldmanVerificationVector); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pid).WithMessage("failed to verify feldman share from party %d", pid)
		}
		referencePedersenVector, _ := p.state.receivedPedersenVerificationVectors.Get(pid)
		if err := p.state.pedersenVSS.Verify(inU.Share, referencePedersenVector); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, pid).WithMessage("failed to verify pedersen share from party %d", pid)
		}
		summedShareValue = summedShareValue.Add(inU.Share.Value())
		summedFeldmanVerificationVector = summedFeldmanVerificationVector.Op(inB.FeldmanVerificationVector)
	}
	outputShare, err := feldman.NewShare(p.id, summedShareValue, nil)
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
