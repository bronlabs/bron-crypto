package noninteractive_signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

type Round1Broadcast struct {
	BigRCommitment commitments.Commitment

	_ ds.Incomparable
}

type Round2Broadcast struct {
	BigR        curves.Point
	BigRProof   compiler.NIZKPoKProof
	BigRWitness commitments.Witness

	_ ds.Incomparable
}

func (p *PreGenParticipant) Round1() (output *Round1Broadcast, err error) {
	if p.round != 1 {
		return nil, errs.NewRound("rounds mismatch %d != 1", p.round)
	}

	k, err := p.protocol.Curve().ScalarField().Random(p.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate random k")
	}
	bigR := p.protocol.Curve().ScalarBaseMult(k)
	bigRCommitment, bigRWitness, err := commitments.Commit(p.sessionId, p.prng, p.IdentityKey().PublicKey().ToAffineCompressed(), bigR.ToAffineCompressed())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to R")
	}

	p.state.k = k
	p.state.bigR = bigR
	p.state.bigRWitness = bigRWitness

	p.round++
	return &Round1Broadcast{
		BigRCommitment: bigRCommitment,
	}, nil
}

func (p *PreGenParticipant) Round2(input types.RoundMessages[*Round1Broadcast]) (output *Round2Broadcast, err error) {
	if p.round != 2 {
		return nil, errs.NewRound("rounds mismatch %d != 2", p.round)
	}

	theirBigRCommitments := hashmap.NewHashableHashMap[types.IdentityKey, commitments.Commitment]()
	for identity := range p.preSigners.Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		in, ok := input.Get(identity)
		if !ok {
			return nil, errs.NewMissing("no input from %s", identity.String())
		}
		commitment := in.BigRCommitment
		if commitment == nil {
			return nil, errs.NewIsNil("commitment from %s", identity.String())
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
		BigRWitness: p.state.bigRWitness,
	}, nil
}

func (p *PreGenParticipant) Round3(input types.RoundMessages[*Round2Broadcast]) (*lindell17.PreProcessingMaterial, error) {
	if p.round != 3 {
		return nil, errs.NewRound("rounds mismatch %d != 3", p.round)
	}

	bigRs := hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()
	bigRs.Put(p.IdentityKey(), p.state.bigR)

	for identity := range p.preSigners.Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		in, ok := input.Get(identity)
		if !ok {
			return nil, errs.NewMissing("no input from %x", identity.String())
		}
		theirBigRCommitment, ok := p.state.theirBigRCommitments.Get(identity)
		if !ok {
			return nil, errs.NewFailed("no commitment saved from %x", identity.String())
		}

		if err := commitments.Open(p.sessionId, theirBigRCommitment, in.BigRWitness, identity.PublicKey().ToAffineCompressed(), in.BigR.ToAffineCompressed()); err != nil {
			return nil, errs.WrapFailed(err, "cannot open commitment to R")
		}
		if err := verifyDlogProof(p.sessionId, p.transcript.Clone(), identity, in.BigR, in.BigRProof, p.nic); err != nil {
			return nil, errs.WrapFailed(err, "cannot verify dlog R proof")
		}

		bigRs.Put(identity, in.BigR.Mul(p.state.k))
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
