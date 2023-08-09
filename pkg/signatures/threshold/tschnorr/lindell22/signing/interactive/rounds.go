package interactive

import (
	"bytes"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/commitments"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/hashing"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	dlog "github.com/copperexchange/knox-primitives/pkg/proofs/schnorr"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/signing"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
)

const (
	commitmentDomainRLabel = "Lindell2022InteractiveSignR"
	transcriptDLogSLabel   = "Lindell2022InteractiveSignDLogS"
)

var commitmentHashFunc = sha3.New256

type Round1Broadcast struct {
	BigRCommitment commitments.Commitment
}

type Round2Broadcast struct {
	BigRProof   *dlog.Proof
	BigR        curves.Point
	BigRWitness commitments.Witness
}

func (p *Cosigner) Round1() (output *Round1Broadcast, err error) {
	if p.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}

	// 1. choose a random k
	k := p.cohortConfig.CipherSuite.Curve.NewScalar().Random(p.prng)

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

func (p *Cosigner) Round2(input map[integration.IdentityKey]*Round1Broadcast) (output *Round2Broadcast, err error) {
	if p.round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}

	p.state.theirBigRCommitment = make(map[integration.IdentityKey]commitments.Commitment)
	for _, identity := range p.sessionParticipants {
		in, ok := input[identity]
		if !ok {
			return nil, errs.NewIdentifiableAbort("no input from participant")
		}
		p.state.theirBigRCommitment[identity] = in.BigRCommitment
	}

	// 1. compute proof of dlog knowledge of R
	bigRProof, err := dlogProve(p.state.k, p.state.bigR, p.sid, p.state.bigS, p.transcript.Clone())
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

func (p *Cosigner) Round3(input map[integration.IdentityKey]*Round2Broadcast, message []byte) (partialSignature *lindell22.PartialSignature, err error) {
	if p.round != 3 {
		return nil, errs.NewInvalidRound("round mismatch %d != 3", p.round)
	}

	bigR := p.cohortConfig.CipherSuite.Curve.NewIdentityPoint()
	for _, identity := range p.sessionParticipants {
		in, ok := input[identity]
		if !ok {
			return nil, errs.NewIdentifiableAbort("no input from participant")
		}

		theirBigR := in.BigR
		theirBigRWitness := in.BigRWitness
		theirPid := identity.PublicKey().ToAffineCompressed()

		// 1. verify commitment
		if err := openCommitment(theirBigR, theirPid, p.sid, p.state.bigS, p.state.theirBigRCommitment[identity], theirBigRWitness); err != nil {
			return nil, errs.WrapFailed(err, "cannot open R commitment")
		}

		// 2. verify dlog
		if err := dlogVerifyProof(in.BigRProof, theirBigR, p.sid, p.state.bigS, p.transcript.Clone()); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, "cannot verify dlog proof")
		}

		// 3.i. compute sum of R
		bigR = bigR.Add(theirBigR)
	}

	// 3.ii. compute e
	eBytes, err := hashing.Hash(p.cohortConfig.CipherSuite.Hash, bigR.ToAffineCompressed(), p.mySigningKeyShare.PublicKey.ToAffineCompressed(), message)
	if err != nil {
		return nil, errs.NewFailed("cannot create message digest")
	}
	e, err := p.cohortConfig.CipherSuite.Curve.NewScalar().SetBytesWide(eBytes)
	if err != nil {
		return nil, errs.NewFailed("cannot set scalar")
	}

	// 3.iii. compute additive share d_i'
	dPrime, err := signing.ToAdditiveShare(p.mySigningKeyShare.Share, p.mySharingId, p.sessionParticipants, p.identityKeyToSharingId)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot converts to additive share")
	}
	// 3.iv. compute s
	s := p.state.k.Add(e.Mul(dPrime))

	// 4. return (R, s) as partial signature
	p.round++
	return &lindell22.PartialSignature{
		R: p.state.bigR,
		S: s,
	}, nil
}

func commit(bigR curves.Point, pid, sid, bigS []byte) (commitment commitments.Commitment, witness commitments.Witness, err error) {
	message := bytes.Join([][]byte{[]byte(commitmentDomainRLabel), bigR.ToAffineCompressed(), pid, sid, bigS}, nil)
	commitment, witness, err = commitments.Commit(commitmentHashFunc, message)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot commit to R")
	}

	return commitment, witness, nil
}

func openCommitment(bigR curves.Point, pid, sid, bigS []byte, commitment commitments.Commitment, witness commitments.Witness) (err error) {
	message := bytes.Join([][]byte{[]byte(commitmentDomainRLabel), bigR.ToAffineCompressed(), pid, sid, bigS}, nil)
	if err := commitments.Open(commitmentHashFunc, message, commitment, witness); err != nil {
		return errs.WrapVerificationFailed(err, "couldn't open")
	}
	return nil
}

func dlogProve(x curves.Scalar, bigR curves.Point, sid, bigS []byte, transcript transcripts.Transcript) (proof *dlog.Proof, err error) {
	curve, err := curves.GetCurveByName(x.CurveName())
	if err != nil {
		return nil, errs.NewInvalidCurve("invalid curve %s", curve.Name)
	}

	transcript.AppendMessages(transcriptDLogSLabel, bigS)
	prover, err := dlog.NewProver(curve.NewGeneratorPoint(), sid, transcript)
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
	curve, err := curves.GetCurveByName(bigR.CurveName())
	if err != nil {
		return errs.NewInvalidCurve("invalid curve %s", curve.Name)
	}

	transcript.AppendMessages(transcriptDLogSLabel, bigS)
	if err := dlog.Verify(curve.NewGeneratorPoint(), bigR, proof, sid, transcript); err != nil {
		return errs.WrapVerificationFailed(err, "dlog proof failed")
	}
	return nil
}
