package interactive_signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/comm/hashcomm"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/veccomm/hashveccomm"
)

const (
	commitmentDomainRLabel = "Lindell2022InteractiveSignR-"
	transcriptDLogSLabel   = "Lindell2022InteractiveSignDLogS-"
)

func (p *Cosigner[V]) Round1() (broadcastOutput *Round1Broadcast, err error) {
	// Validation
	if p.Round != 1 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 1, p.Round)
	}

	// step 1.1: Sample k_i <-$- ℤ_q  &  compute R_i = k_i * G
	k, err := p.Protocol.Curve().ScalarField().Random(p.Prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot generate random k")
	}
	bigR := p.Protocol.Curve().ScalarBaseMult(k)

	// step 1.2: Run c_i <= commit(sid || R_i || i || S)
	vector := make([]hashcomm.Message, 4)
	vector[0] = []byte(commitmentDomainRLabel)
	vector[1] = bigR.ToAffineCompressed()
	vector[2] = p.state.pid
	vector[3] = p.state.bigS
	vectorCommitter, err := hashveccomm.NewVectorCommitter(p.SessionId, p.Prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot instantiate vector committer")
	}
	commitment, opening, err := vectorCommitter.Commit(vector)
	if err != nil {
		return nil, errs.NewFailed("cannot commit to R")
	}

	// step 1.4: Broadcast(c_i)
	broadcast := &Round1Broadcast{
		BigRCommitment: commitment,
	}

	p.state.k = k
	p.state.bigR = bigR
	p.state.opening = opening
	p.Round++

	return broadcast, nil
}

func (p *Cosigner[V]) Round2(broadcastInput network.RoundMessages[types.ThresholdSignatureProtocol, *Round1Broadcast]) (broadcastOutput *Round2Broadcast, err error) {
	// Validation, unicastInput is delegated to Przs.Round2
	if p.Round != 2 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 2, p.Round)
	}
	if err := network.ValidateMessages(p.Protocol, p.quorum, p.IdentityKey(), broadcastInput); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 1 broadcast output")
	}

	p.state.theirBigRCommitment = hashmap.NewHashableHashMap[types.IdentityKey, *hashveccomm.VectorCommitment]()
	for iterator := p.quorum.Iterator(); iterator.HasNext(); {
		identity := iterator.Next()

		if identity.Equal(p.IdentityKey()) {
			continue
		}
		in, _ := broadcastInput.Get(identity)
		p.state.theirBigRCommitment.Put(identity, in.BigRCommitment)
	}

	// step 2.1: π^dl_i <- NIPoKDL.Prove(k_i, R_i, sessionId, S, nic)
	bigRProof, err := dlogProve(p.IdentityKey(), p.state.k, p.state.bigR, p.SessionId, p.state.bigS, p.nic, p.Transcript.Clone(), p.Prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot prove dlog")
	}

	// step 2.3: Broadcast(π^dl_i, R_i, c_i)
	broadcast := &Round2Broadcast{
		BigR:        p.state.bigR,
		BigROpening: p.state.opening,
		BigRProof:   bigRProof,
	}

	p.Round++
	return broadcast, nil
}

func (p *Cosigner[V]) Round3(broadcastInput network.RoundMessages[types.ThresholdSignatureProtocol, *Round2Broadcast], message []byte) (partialSignature *tschnorr.PartialSignature, err error) {
	// Validation, unicastInput is delegated to Przs.Round3
	if p.Round != 3 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 3, p.Round)
	}
	if err := network.ValidateMessages(p.Protocol, p.quorum, p.IdentityKey(), broadcastInput); err != nil {
		return nil, errs.WrapValidation(err, "invalid round %d input", p.Round)
	}

	bigR := p.state.bigR
	// step 3.1: For all other participants P_j in the quorum...
	for iterator := p.quorum.Iterator(); iterator.HasNext(); {
		identity := iterator.Next()
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		in, _ := broadcastInput.Get(identity)
		theirPid := identity.PublicKey().ToAffineCompressed()
		theirBigR := in.BigR
		theirBigROpening := in.BigROpening
		theirBigRCommitment, exists := p.state.theirBigRCommitment.Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find their bigR commitment (pid=%x)", theirPid)
		}

		// step 3.2: Open(sid || R_j || j || S)
		vectorVerifier := hashveccomm.NewVectorVerifier(p.SessionId)
		if err := vectorVerifier.Verify(theirBigRCommitment, theirBigROpening); err != nil {
			return nil, errs.WrapFailed(err, "cannot open R commitment")
		}

		// step 3.3: Run NIPoKDL.Verify(R_j, π^dl_j)
		if err := dlogVerifyProof(identity, in.BigRProof, theirBigR, p.SessionId, p.state.bigS, p.nic, p.Transcript.Clone()); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, identity.String(), "cannot verify dlog proof")
		}

		// step 3.4: R <- Σ R_j
		bigR = bigR.Add(theirBigR)
	}

	// step 3.7.1: compute additive share d_i'
	sk, err := p.mySigningKeyShare.ToAdditive(p.IdentityKey(), p.quorum, p.Protocol)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot converts to additive share")
	}

	// step 3.7.2: compute e
	eBytes := p.variant.ComputeChallengeBytes(bigR, p.mySigningKeyShare.PublicKey, message)
	e, err := schnorr.MakeGenericSchnorrChallenge(p.Protocol.SigningSuite(), eBytes)
	if err != nil {
		return nil, errs.NewFailed("cannot create digest scalar")
	}
	// step 3.7.3 & 3.8: compute s'_i and set s_i <- s'_i + ζ_i
	s := p.variant.ComputeResponse(bigR, p.mySigningKeyShare.PublicKey, p.state.k, sk, e)

	p.Round++
	return &tschnorr.PartialSignature{
		E: e,
		R: p.variant.ComputeNonceCommitment(bigR, p.state.bigR),
		S: s,
	}, nil
}

func dlogProve(prover types.IdentityKey, k curves.Scalar, bigR curves.Point, sessionId, bigS []byte, nic compiler.Name, transcript transcripts.Transcript, prng io.Reader) (proof compiler.NIZKPoKProof, err error) {
	curve := k.ScalarField().Curve()
	transcript.AppendMessages(transcriptDLogSLabel, bigS)
	transcript.AppendPoints("prover", prover.PublicKey())
	proof, statement, err := dlog.Prove(sessionId, k, curve.Generator(), nic, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create a proof")
	}
	if !bigR.Equal(statement) {
		return nil, errs.NewFailed("invalid statement")
	}
	return proof, nil
}

func dlogVerifyProof(prover types.IdentityKey, proof compiler.NIZKPoKProof, bigR curves.Point, sessionId, bigS []byte, nic compiler.Name, transcript transcripts.Transcript) (err error) {
	curve := bigR.Curve()
	transcript.AppendMessages(transcriptDLogSLabel, bigS)
	transcript.AppendPoints("prover", prover.PublicKey())
	if err := dlog.Verify(sessionId, proof, bigR, curve.Generator(), nic, transcript); err != nil {
		return errs.WrapVerification(err, "cannot verify proof")
	}
	return nil
}
