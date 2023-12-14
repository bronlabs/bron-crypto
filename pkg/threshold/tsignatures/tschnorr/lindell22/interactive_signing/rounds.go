package interactive_signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	dlog "github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/fischlin"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

var fiatShamir = hashing.NewSchnorrCompatibleFiatShamir()

const (
	commitmentDomainRLabel = "Lindell2022InteractiveSignR"
	transcriptDLogSLabel   = "Lindell2022InteractiveSignDLogS"
)

type Round1Broadcast struct {
	BigRCommitment commitments.Commitment

	_ types.Incomparable
}

type Round2Broadcast struct {
	BigRProof   *dlog.Proof
	BigR        curves.Point
	BigRWitness commitments.Witness

	_ types.Incomparable
}

func (p *Cosigner) Round1() (output *Round1Broadcast, err error) {
	if p.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}

	// 1. choose a random k
	k, err := p.cohortConfig.CipherSuite.Curve.Scalar().Random(p.prng)
	if err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "cannot generate random k")
	}

	// 2. compute R = k * G
	bigR := p.cohortConfig.CipherSuite.Curve.ScalarBaseMult(k)

	// 3. compute Rcom = commit(R, pid, sid, S)
	bigRCommitment, bigRWitness, err := commit(bigR, p.state.pid, p.sid, p.state.bigS)
	if err != nil {
		return nil, errs.NewFailed("cannot commit to R")
	}

	p.state.k = k
	p.state.bigR = bigR
	p.state.bigRWitness = bigRWitness

	// 4. broadcast commitment
	p.round++
	return &Round1Broadcast{
		BigRCommitment: bigRCommitment,
	}, nil
}

func (p *Cosigner) Round2(input map[types.IdentityHash]*Round1Broadcast) (output *Round2Broadcast, err error) {
	if p.round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}

	p.state.theirBigRCommitment = make(map[types.IdentityHash]commitments.Commitment)
	for _, identity := range p.sessionParticipants.Iter() {
		if identity.Hash() == p.myAuthKey.Hash() {
			continue
		}

		in, ok := input[identity.Hash()]
		if !ok {
			return nil, errs.NewMissing("no input from participant")
		}
		p.state.theirBigRCommitment[identity.Hash()] = in.BigRCommitment
	}

	// 1. compute proof of dlog knowledge of R
	bigRProof, err := dlogProve(p.state.k, p.state.bigR, p.sid, p.state.bigS, p.transcript.Clone(), p.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot prove dlog")
	}

	// 2. broadcast proof and opening of R, revealing R
	p.round++
	return &Round2Broadcast{
		BigR:        p.state.bigR,
		BigRWitness: p.state.bigRWitness,
		BigRProof:   bigRProof,
	}, nil
}

func (p *Cosigner) Round3(input map[types.IdentityHash]*Round2Broadcast, message []byte) (partialSignature *lindell22.PartialSignature, err error) {
	if p.round != 3 {
		return nil, errs.NewInvalidRound("round mismatch %d != 3", p.round)
	}

	bigR := p.state.bigR
	for _, identity := range p.sessionParticipants.Iter() {
		if identity.Hash() == p.myAuthKey.Hash() {
			continue
		}

		in, ok := input[identity.Hash()]
		if !ok {
			return nil, errs.NewMissing("no input from participant")
		}

		theirBigR := in.BigR
		theirBigRWitness := in.BigRWitness
		theirPid := identity.PublicKey().ToAffineCompressed()

		// 1. verify commitment
		if err := openCommitment(theirBigR, theirPid, p.sid, p.state.bigS, p.state.theirBigRCommitment[identity.Hash()], theirBigRWitness); err != nil {
			return nil, errs.WrapFailed(err, "cannot open R commitment")
		}

		// 2. verify dlog
		if err := dlogVerifyProof(in.BigRProof, theirBigR, p.sid, p.state.bigS, p.transcript.Clone()); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, identity.Hash(), "cannot verify dlog proof")
		}

		// 3.i. compute sum of R
		bigR = bigR.Add(theirBigR)
	}

	if p.taproot {
		if bigR.Y().IsOdd() {
			p.state.k = p.state.k.Neg()
			bigR = bigR.Neg()
		}
	}

	// 3.ii. compute e
	var e curves.Scalar
	if p.taproot {
		e, err = fiatShamir.GenerateChallenge(p.cohortConfig.CipherSuite, bigR.ToAffineCompressed()[1:], p.mySigningKeyShare.PublicKey.ToAffineCompressed()[1:], message)
	} else {
		e, err = fiatShamir.GenerateChallenge(p.cohortConfig.CipherSuite, bigR.ToAffineCompressed(), p.mySigningKeyShare.PublicKey.ToAffineCompressed(), message)
	}
	if err != nil {
		return nil, errs.NewFailed("cannot create digest scalar")
	}

	// 3.iii. compute additive share d_i'
	dPrime, err := ToAdditiveShare(p.mySigningKeyShare.Share, p.mySharingId, p.sessionParticipants, p.identityKeyToSharingId)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot converts to additive share")
	}
	if p.taproot {
		if p.mySigningKeyShare.PublicKey.Y().IsOdd() {
			dPrime = dPrime.Neg()
		}
	}

	// 3.iv. compute s
	s := p.state.k.Add(e.Mul(dPrime))

	// 4. return (R, s) as partial signature
	p.round++
	return &lindell22.PartialSignature{
		R: p.cohortConfig.CipherSuite.Curve.ScalarBaseMult(p.state.k),
		S: s,
	}, nil
}

func commit(bigR curves.Point, pid, sid, bigS []byte) (commitment commitments.Commitment, witness commitments.Witness, err error) {
	commitment, witness, err = commitments.Commit(sid, []byte(commitmentDomainRLabel), bigR.ToAffineCompressed(), pid, bigS)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot commit to R")
	}

	return commitment, witness, nil
}

func openCommitment(bigR curves.Point, pid, sid, bigS []byte, commitment commitments.Commitment, witness commitments.Witness) (err error) {
	if err := commitments.Open(sid, commitment, witness, []byte(commitmentDomainRLabel), bigR.ToAffineCompressed(), pid, bigS); err != nil {
		return errs.WrapVerificationFailed(err, "couldn't open")
	}
	return nil
}

func dlogProve(x curves.Scalar, bigR curves.Point, sid, bigS []byte, transcript transcripts.Transcript, prng io.Reader) (proof *dlog.Proof, err error) {
	curve := x.Curve()

	transcript.AppendMessages(transcriptDLogSLabel, bigS)
	prover, err := dlog.NewProver(curve.Generator(), sid, transcript, prng)
	if err != nil {
		return nil, errs.NewFailed("cannot create dlog prover")
	}
	proof, statement, err := prover.Prove(x)
	if !bigR.Equal(statement) {
		return nil, errs.NewFailed("invalid statement")
	}
	if err != nil {
		return nil, errs.NewFailed("cannot create a proof")
	}

	return proof, nil
}

func dlogVerifyProof(proof *dlog.Proof, bigR curves.Point, sid, bigS []byte, transcript transcripts.Transcript) (err error) {
	curve := bigR.Curve()

	transcript.AppendMessages(transcriptDLogSLabel, bigS)
	if err := dlog.Verify(curve.Generator(), bigR, proof, sid); err != nil {
		return errs.WrapVerificationFailed(err, "dlog proof failed")
	}
	return nil
}
