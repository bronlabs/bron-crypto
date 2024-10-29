package noninteractive_signing

import (
	"io"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	hashcommitments "github.com/bronlabs/krypton-primitives/pkg/commitments/hash"
	"github.com/bronlabs/krypton-primitives/pkg/network"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/dlog"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts"
)

func (p *PreGenParticipant) Round1() (output *Round1Broadcast, err error) {
	// Validation
	if p.round != 1 {
		return nil, errs.NewRound("rounds mismatch %d != 1", p.round)
	}

	k, err := p.protocol.Curve().ScalarField().Random(p.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate random k")
	}
	bigR := p.protocol.Curve().ScalarBaseMult(k)

	committer, err := hashcommitments.NewCommittingKeyFromCrsBytes(p.sessionId, p.IdentityKey().PublicKey().ToAffineCompressed())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot instantiate committer")
	}
	bigRCommitment, bigROpening, err := committer.Commit(bigR.ToAffineCompressed(), p.prng)
	if err != nil {
		return nil, errs.NewFailed("cannot commit to R")
	}

	p.state.k = k
	p.state.bigR = bigR
	p.state.bigROpening = bigROpening

	p.round++
	return &Round1Broadcast{
		BigRCommitment: bigRCommitment,
	}, nil
}

func (p *PreGenParticipant) Round2(
	round1outputBroadcast network.RoundMessages[types.ThresholdProtocol, *Round1Broadcast],
) (output *Round2Broadcast, err error) {
	// Validation
	if p.round != 2 {
		return nil, errs.NewRound("rounds mismatch %d != 2", p.round)
	}
	if err := network.ValidateMessages(p.protocol, p.protocol.Participants(), p.IdentityKey(), round1outputBroadcast); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 2 input broadcast messages")
	}

	theirBigRCommitments := hashmap.NewHashableHashMap[types.IdentityKey, hashcommitments.Commitment]()
	for identity := range p.preSigners.Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		in, ok := round1outputBroadcast.Get(identity)
		if !ok {
			return nil, errs.NewMissing("no input from %s", identity.String())
		}
		theirBigRCommitments.Put(identity, in.BigRCommitment)
	}

	bigRProof, err := proveDlog(p.sessionId, p.transcript.Clone(), p.myAuthKey, p.state.k, p.state.bigR, p.nic, p.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot proof R dlog")
	}

	p.state.theirBigRCommitments = theirBigRCommitments

	p.round++
	return &Round2Broadcast{
		BigR:        p.state.bigR,
		BigRProof:   bigRProof,
		BigROpening: p.state.bigROpening,
	}, nil
}

func (p *PreGenParticipant) Round3(
	round2outputBroadcast network.RoundMessages[types.ThresholdProtocol, *Round2Broadcast],
) (*lindell17.PreProcessingMaterial, error) {
	// Validation
	if p.round != 3 {
		return nil, errs.NewRound("rounds mismatch %d != 3", p.round)
	}
	if err := network.ValidateMessages(p.protocol, p.protocol.Participants(), p.IdentityKey(), round2outputBroadcast); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 3 input broadcast messages")
	}

	bigRs := hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()
	bigRs.Put(p.IdentityKey(), p.state.bigR)

	for identity := range p.preSigners.Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		in, ok := round2outputBroadcast.Get(identity)
		if !ok {
			return nil, errs.NewMissing("no input from %x", identity.String())
		}
		theirBigRCommitment, ok := p.state.theirBigRCommitments.Get(identity)
		if !ok {
			return nil, errs.NewFailed("no commitment saved from %x", identity.String())
		}

		verifier, err := hashcommitments.NewCommittingKeyFromCrsBytes(p.sessionId, identity.PublicKey().ToAffineCompressed())
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot instantiate verifier")
		}
		// if !bytes.Equal(in.BigR.ToAffineCompressed(), in.BigROpening.GetMessage()) {
		//	return nil, errs.NewVerification("opening is not tied to the expected value")
		//}
		if err := verifier.Verify(theirBigRCommitment, in.BigR.ToAffineCompressed(), in.BigROpening); err != nil {
			return nil, errs.WrapFailed(err, "cannot open R commitment")
		}
		if err := verifyDlogProof(p.sessionId, p.transcript.Clone(), identity, in.BigR, in.BigRProof, p.nic); err != nil {
			return nil, errs.WrapFailed(err, "cannot verify dlog R proof")
		}

		bigRs.Put(identity, in.BigR.ScalarMul(p.state.k))
	}

	p.round++
	return &lindell17.PreProcessingMaterial{
		PrivateMaterial: &lindell17.PrivatePreProcessingMaterial{
			K: p.state.k,
		},
		PreSignature: &lindell17.PreSignature{
			BigR: bigRs,
		},
		PreSigners: p.preSigners,
	}, nil
}

func proveDlog(sessionId []byte, transcript transcripts.Transcript, party types.IdentityKey, k curves.Scalar, bigR curves.Point, nic compiler.Name, prng io.Reader) (proof compiler.NIZKPoKProof, err error) {
	curve := k.ScalarField().Curve()
	transcript.AppendPoints("bigR", bigR)
	transcript.AppendPoints("pid", party.PublicKey())
	proof, statement, err := dlog.Prove(sessionId, k, curve.Generator(), nic, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "prove operation failed")
	}
	if !bigR.Equal(statement) {
		return nil, errs.NewFailed("invalid proof statement")
	}

	return proof, nil
}

func verifyDlogProof(sessionId []byte, transcript transcripts.Transcript, party types.IdentityKey, bigR curves.Point, proof compiler.NIZKPoKProof, nic compiler.Name) (err error) {
	curve := bigR.Curve()
	transcript.AppendPoints("bigR", bigR)
	transcript.AppendPoints("pid", party.PublicKey())
	if err := dlog.Verify(sessionId, proof, bigR, curve.Generator(), nic, transcript); err != nil {
		return errs.WrapVerification(err, "dlog verify failed")
	}
	return nil
}
