package interactive_signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/chacha20"
	"github.com/copperexchange/krypton-primitives/pkg/hashing/fiatshamir"
	dlog "github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/fischlin"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/sample"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/setup"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

const (
	commitmentDomainRLabel = "Lindell2022InteractiveSignR"
	transcriptDLogSLabel   = "Lindell2022InteractiveSignDLogS"
)

type Round1Broadcast struct {
	BigRCommitment commitments.Commitment

	_ types.Incomparable
}

type Round1P2P struct {
	Przs *setup.Round1P2P

	_ types.Incomparable
}

type Round2Broadcast struct {
	BigRProof   *dlog.Proof
	BigR        curves.Point
	BigRWitness commitments.Witness

	_ types.Incomparable
}

type Round2P2P struct {
	Przs *setup.Round2P2P

	_ types.Incomparable
}

func (p *Cosigner) Round1() (broadcastOutput *Round1Broadcast, unicastOutput map[types.IdentityHash]*Round1P2P, err error) {
	if p.round != 1 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}

	// 1. choose a random k
	k, err := p.cohortConfig.CipherSuite.Curve.ScalarField().Random(p.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSampleFailed(err, "cannot generate random k")
	}

	// 2. compute R = k * G
	bigR := p.cohortConfig.CipherSuite.Curve.ScalarBaseMult(k)

	// 3. compute Rcom = commit(R, pid, sid, S)
	bigRCommitment, bigRWitness, err := commit(p.prng, bigR, p.state.pid, p.sid, p.state.bigS)
	if err != nil {
		return nil, nil, errs.NewFailed("cannot commit to R")
	}

	// 5. run PRZS round 1
	przsOutput, err := p.przsParticipant.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run PRZS setup")
	}

	broadcast := &Round1Broadcast{
		BigRCommitment: bigRCommitment,
	}
	unicast := make(map[types.IdentityHash]*Round1P2P)
	for id, r1 := range przsOutput {
		unicast[id] = &Round1P2P{
			Przs: r1,
		}
	}

	p.state.k = k
	p.state.bigR = bigR
	p.state.bigRWitness = bigRWitness
	p.round++

	// 4. broadcast commitment
	return broadcast, unicast, nil
}

func (p *Cosigner) Round2(broadcastInput map[types.IdentityHash]*Round1Broadcast, unicastInput map[types.IdentityHash]*Round1P2P) (broadcastOutput *Round2Broadcast, unicastOutput map[types.IdentityHash]*Round2P2P, err error) {
	if p.round != 2 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}

	p.state.theirBigRCommitment = make(map[types.IdentityHash]commitments.Commitment)
	for _, identity := range p.sessionParticipants.Iter() {
		if identity.Hash() == p.myAuthKey.Hash() {
			continue
		}

		in, ok := broadcastInput[identity.Hash()]
		if !ok {
			return nil, nil, errs.NewMissing("no input from participant")
		}
		p.state.theirBigRCommitment[identity.Hash()] = in.BigRCommitment
	}

	// 1. compute proof of dlog knowledge of R
	bigRProof, err := dlogProve(p.state.k, p.state.bigR, p.sid, p.state.bigS, p.transcript.Clone(), p.prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot prove dlog")
	}

	// 3. run PRZS round 2
	przsInput := make(map[types.IdentityHash]*setup.Round1P2P)
	for id, r2 := range unicastInput {
		przsInput[id] = r2.Przs
	}
	przsOutput, err := p.przsParticipant.Round2(przsInput)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run PRZS setup")
	}

	broadcast := &Round2Broadcast{
		BigR:        p.state.bigR,
		BigRWitness: p.state.bigRWitness,
		BigRProof:   bigRProof,
	}
	unicast := make(map[types.IdentityHash]*Round2P2P)
	for id, r2 := range przsOutput {
		unicast[id] = &Round2P2P{
			Przs: r2,
		}
	}

	// 2. broadcast proof and opening of R, revealing R
	p.round++
	return broadcast, unicast, nil
}

func (p *Cosigner) Round3(broadcastInput map[types.IdentityHash]*Round2Broadcast, unicastInput map[types.IdentityHash]*Round2P2P, message []byte) (partialSignature *lindell22.PartialSignature, err error) {
	if p.round != 3 {
		return nil, errs.NewInvalidRound("round mismatch %d != 3", p.round)
	}

	bigR := p.state.bigR
	for _, identity := range p.sessionParticipants.Iter() {
		if identity.Hash() == p.myAuthKey.Hash() {
			continue
		}

		in, ok := broadcastInput[identity.Hash()]
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

		// 4.i. compute sum of R
		bigR = bigR.Add(theirBigR)
	}

	if p.taproot {
		if bigR.AffineY().IsOdd() {
			p.state.k = p.state.k.Neg()
			bigR = bigR.Neg()
		}
	}

	// 3.ii. compute e
	fiatShamir := fiatshamir.NewSchnorrCompatibleFiatShamir(p.cohortConfig.CipherSuite.Curve)
	var e curves.Scalar
	if p.taproot {
		e, err = fiatShamir.GenerateChallenge(p.cohortConfig.CipherSuite, bigR.ToAffineCompressed()[1:], p.mySigningKeyShare.PublicKey.ToAffineCompressed()[1:], message)
	} else {
		e, err = fiatShamir.GenerateChallenge(p.cohortConfig.CipherSuite, bigR.ToAffineCompressed(), p.mySigningKeyShare.PublicKey.ToAffineCompressed(), message)
	}
	if err != nil {
		return nil, errs.NewFailed("cannot create digest scalar")
	}

	// 4.iii. compute additive share d_i'
	dPrime, err := ToAdditiveShare(p.mySigningKeyShare.Share, p.mySharingId, p.sessionParticipants, p.identityKeyToSharingId)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot converts to additive share")
	}
	if p.taproot {
		if p.mySigningKeyShare.PublicKey.AffineY().IsOdd() {
			dPrime = dPrime.Neg()
		}
	}

	// 3. run PRZS round 3 to get zero share
	przsInput := make(map[types.IdentityHash]*setup.Round2P2P)
	for id, r3 := range unicastInput {
		przsInput[id] = r3.Przs
	}
	przsSeeds, err := p.przsParticipant.Round3(przsInput)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run PRZS setup")
	}
	seededPrng, err := chacha20.NewChachaPRNG(nil, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create seeded CSPRNG")
	}
	przsSampleParticipant, err := sample.NewParticipant(p.cohortConfig.CipherSuite.Curve, p.sid, p.myAuthKey, przsSeeds, p.sessionParticipants, seededPrng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create seeded CSPRNG")
	}
	zeroS, err := przsSampleParticipant.Sample()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot sample zero share")
	}

	// 4.iv. compute s
	s := p.state.k.Add(e.Mul(dPrime)).Add(zeroS)

	// 4. return (R, s) as partial signature
	p.round++
	return &lindell22.PartialSignature{
		R: p.cohortConfig.CipherSuite.Curve.ScalarBaseMult(p.state.k),
		S: s,
	}, nil
}

func commit(prng io.Reader, bigR curves.Point, pid, sid, bigS []byte) (commitment commitments.Commitment, witness commitments.Witness, err error) {
	commitment, witness, err = commitments.Commit(sid, prng, []byte(commitmentDomainRLabel), bigR.ToAffineCompressed(), pid, bigS)
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
	curve := x.ScalarField().Curve()
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
