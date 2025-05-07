package interactive_signing

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	hashcommitments "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	commitmentDomainRLabel = "Lindell2022InteractiveSignR-"
	transcriptDLogSLabel   = "Lindell2022InteractiveSignDLogS-"
)

func (p *Cosigner[C, P, F, S, V, M]) Round1() (broadcastOutput *Round1Broadcast, err error) {
	// Validation
	if p.Round != 1 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 1, p.Round)
	}

	// step 1.1: Sample k_i <-$- ℤ_q  &  compute R_i = k_i * G
	k, err := p.Protocol.Curve().ScalarField().Random(p.Prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot generate random k")
	}
	bigR := p.Protocol.Curve().Generator().ScalarMul(k)

	// step 1.2: Run c_i <= commit(sid || R_i || i || S)
	committer, err := hashcommitments.NewCommittingKeyFromCrsBytes(p.SessionId, []byte(commitmentDomainRLabel), p.state.pid, p.state.bigS)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot instantiate vector committer")
	}
	commitment, opening, err := committer.Commit(bigR.ToAffineCompressed(), p.Prng)
	if err != nil {
		return nil, errs.NewFailed("cannot commit to R")
	}

	// step 1.4: Broadcast(c_i)
	broadcast := &Round1Broadcast{
		BigRCommitment: commitment,
	}

	p.state.k = k
	p.state.bigR = bigR
	p.state.bigRWitness = opening
	p.Round++

	return broadcast, nil
}

func (p *Cosigner[C, P, F, S, V, M]) Round2(broadcastInput network.RoundMessages[*Round1Broadcast]) (broadcastOutput *Round2Broadcast[P, F, S], err error) {
	// Validation, unicastInput is delegated to Przs.Round2
	if p.Round != 2 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 2, p.Round)
	}
	//if err := network.ValidateMessages(p.Protocol, p.quorum, p.IdentityKey(), broadcastInput); err != nil {
	//	return nil, errs.WrapValidation(err, "invalid round 2 input broadcast messages")
	//}

	p.state.theirBigRCommitment = hashmap.NewHashableHashMap[types.IdentityKey, hashcommitments.Commitment]()
	for identity := range p.quorum.Iter() {
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
	broadcast := &Round2Broadcast[P, F, S]{
		BigR:        p.state.bigR,
		BigRWitness: p.state.bigRWitness,
		BigRProof:   bigRProof,
	}

	p.Round++
	return broadcast, nil
}

func (p *Cosigner[C, P, F, S, V, M]) Round3(broadcastInput network.RoundMessages[*Round2Broadcast[P, F, S]], message M) (partialSignature *tschnorr.PartialSignature[P, F, S], err error) {
	// Validation, unicastInput is delegated to Przs.Round3
	if p.Round != 3 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 3, p.Round)
	}
	//if err := network.ValidateMessages(p.Protocol, p.quorum, p.IdentityKey(), broadcastInput); err != nil {
	//	return nil, errs.WrapValidation(err, "invalid round 3 input broadcast messages")
	//}

	bigR := p.state.bigR
	// step 3.1: For all other participants P_j in the quorum...
	for identity := range p.quorum.Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		in, _ := broadcastInput.Get(identity)
		theirPid := identity.PublicKeyBytes()
		theirBigR := in.BigR
		theirBigRWitness := in.BigRWitness
		theirBigRCommitment, exists := p.state.theirBigRCommitment.Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find their bigR commitment (pid=%x)", theirPid)
		}

		// step 3.2: Open(sid || R_j || j || S)
		verifier, err := hashcommitments.NewCommittingKeyFromCrsBytes(p.SessionId, []byte(commitmentDomainRLabel), theirPid, p.state.bigS)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot instantiate verifier")
		}
		if err := verifier.Verify(theirBigRCommitment, theirBigR.ToAffineCompressed(), theirBigRWitness); err != nil {
			return nil, errs.WrapFailed(err, "cannot open R commitment")
		}

		// step 3.3: Run NIPoKDL.Verify(R_j, π^dl_j)
		if err := dlogVerifyProof(identity, in.BigRProof, theirBigR, p.SessionId, p.state.bigS, p.nic, p.Transcript.Clone()); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, identity.String(), "cannot verify dlog proof")
		}

		// step 3.4: R <- Σ R_j
		bigR = bigR.Op(theirBigR)
	}

	// step 3.7.1: compute additive share d_i'
	sk, err := p.mySigningKeyShare.ToAdditive(p.IdentityKey(), p.quorum, p.Protocol)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot converts to additive share")
	}

	// step 3.7.2: compute e
	e, err := p.variant.ComputeChallenge(p.Protocol.SigningSuite().Hash(), bigR, p.mySigningKeyShare.PublicKey, message)
	if err != nil {
		return nil, errs.NewFailed("cannot create digest scalar")
	}
	// step 3.7.3 & 3.8: compute s'_i and set s_i <- s'_i + ζ_i
	s := p.variant.ComputeResponse(bigR, p.mySigningKeyShare.PublicKey, p.state.k, sk, e)

	p.Round++
	return &tschnorr.PartialSignature[P, F, S]{
		E: e,
		R: p.variant.ComputeNonceCommitment(bigR, p.state.bigR),
		S: s,
	}, nil
}

func dlogProve[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](prover types.IdentityKey, k S, bigR P, sessionId, bigS []byte, nic compiler.Name, transcript transcripts.Transcript, prng io.Reader) (proof compiler.NIZKPoKProof, err error) {
	curve, err := curves.GetCurve(bigR)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get curve")
	}

	transcript.AppendBytes(transcriptDLogSLabel, bigS)
	transcript.AppendBytes("prover", prover.PublicKeyBytes())
	proof, statement, err := dlog.Prove(sessionId, k, curve.Generator(), nic, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create a proof")
	}
	if !bigR.Equal(statement.X) {
		return nil, errs.NewFailed("invalid statement")
	}
	return proof, nil
}

func dlogVerifyProof[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](prover types.IdentityKey, proof compiler.NIZKPoKProof, bigR P, sessionId, bigS []byte, nic compiler.Name, transcript transcripts.Transcript) (err error) {
	curve, err := curves.GetCurve(bigR)
	if err != nil {
		return errs.WrapFailed(err, "cannot get curve")
	}

	transcript.AppendBytes(transcriptDLogSLabel, bigS)
	transcript.AppendBytes("prover", prover.PublicKeyBytes())
	if err := dlog.Verify(sessionId, proof, bigR, curve.Generator(), nic, transcript); err != nil {
		return errs.WrapVerification(err, "cannot verify proof")
	}
	return nil
}
