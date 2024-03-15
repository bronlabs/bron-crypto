package interactive_signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/chacha"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	schnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/sample"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/setup"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

const (
	commitmentDomainRLabel = "Lindell2022InteractiveSignR-"
	transcriptDLogSLabel   = "Lindell2022InteractiveSignDLogS-"
)

func (p *Cosigner[F]) Round1() (broadcastOutput *Round1Broadcast, unicastOutput network.RoundMessages[*Round1P2P], err error) {
	// Validation
	if err := p.InRound(1); err != nil {
		return nil, nil, errs.WrapValidation(err, "Participant in invalid round")
	}

	// step 1.1: Sample k_i <-$- ℤ_q  &  compute R_i = k_i * G
	k, err := p.Protocol().Curve().ScalarField().Random(p.Prng())
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot generate random k")
	}
	bigR := p.Protocol().Curve().ScalarBaseMult(k)

	// step 1.2: Run c_i <= commit(sid || R_i || i || S)
	bigRCommitment, bigRWitness, err := commitments.Commit(p.SessionId(), p.Prng(), []byte(commitmentDomainRLabel), bigR.ToAffineCompressed(), p.state.pid, p.state.bigS)
	if err != nil {
		return nil, nil, errs.NewFailed("cannot commit to R")
	}

	// step 1.3: Run z^{a}_i <- PRZS.Round1()
	przsOutput, err := p.przsParticipant.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run PRZS setup")
	}

	// step 1.4: Broadcast(c_i)
	broadcast := &Round1Broadcast{
		BigRCommitment: bigRCommitment,
	}
	// step 1.5: Send(z^{a}_ij) -> P_j   ∀j
	unicast := network.NewRoundMessages[*Round1P2P]()
	for pair := range przsOutput.Iter() {
		id := pair.Key
		r1 := pair.Value
		unicast.Put(id, r1)
	}

	p.state.k = k
	p.state.bigR = bigR
	p.state.bigRWitness = bigRWitness
	p.NextRound()

	return broadcast, unicast, nil
}

func (p *Cosigner[F]) Round2(broadcastInput network.RoundMessages[*Round1Broadcast], unicastInput network.RoundMessages[*Round1P2P]) (broadcastOutput *Round2Broadcast, unicastOutput network.RoundMessages[*Round2P2P], err error) {
	// Validation, unicastInput is delegated to Przs.Round2
	if err := p.InRound(2); err != nil {
		return nil, nil, errs.WrapValidation(err, "Participant in invalid round")
	}
	if err := network.ValidateMessages(p.quorum, p.IdentityKey(), broadcastInput); err != nil {
		return nil, nil, errs.WrapValidation(err, "invalid round 1 broadcast output")
	}

	p.state.theirBigRCommitment = hashmap.NewHashableHashMap[types.IdentityKey, commitments.Commitment]()
	for identity := range p.quorum.Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		in, _ := broadcastInput.Get(identity)
		p.state.theirBigRCommitment.Put(identity, in.BigRCommitment)
	}

	// step 2.1: π^dl_i <- NIPoKDL.Prove(k_i, R_i, sessionId, S, nic)
	bigRProof, err := dlogProve(p.state.k, p.state.bigR, p.SessionId(), p.state.bigS, p.nic, p.Transcript().Clone(), p.Prng())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot prove dlog")
	}

	// step 2.2: Run z^{b}_i <- PRZS.Round1({z^{a}_ji}_∀j)
	przsInput := network.NewRoundMessages[*setup.Round1P2P]()
	for pair := range unicastInput.Iter() {
		identity := pair.Key
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		r2 := pair.Value
		przsInput.Put(identity, r2)
	}
	przsOutput, err := p.przsParticipant.Round2(przsInput)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run PRZS setup")
	}

	// step 2.3: Broadcast(π^dl_i, R_i, c_i)
	broadcast := &Round2Broadcast{
		BigR:        p.state.bigR,
		BigRWitness: p.state.bigRWitness,
		BigRProof:   bigRProof,
	}
	// step 2.4: Send(z^{b}_ij) -> P_j   ∀j
	unicast := network.NewRoundMessages[*Round2P2P]()
	for pair := range przsOutput.Iter() {
		id := pair.Key
		r2 := pair.Value
		unicast.Put(id, r2)
	}

	p.NextRound()
	return broadcast, unicast, nil
}

func (p *Cosigner[F]) Round3(broadcastInput network.RoundMessages[*Round2Broadcast], unicastInput network.RoundMessages[*Round2P2P], message []byte) (partialSignature *lindell22.PartialSignature, err error) {
	// Validation, unicastInput is delegated to Przs.Round3
	if err := p.InRound(3); err != nil {
		return nil, errs.WrapValidation(err, "Participant in invalid round")
	}
	if err := network.ValidateMessages(p.quorum, p.IdentityKey(), broadcastInput); err != nil {
		return nil, errs.WrapValidation(err, "invalid round %d input", p.Round())
	}

	bigR := p.state.bigR
	// step 3.1: For all other participants P_j in the quorum...
	for identity := range p.quorum.Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		in, _ := broadcastInput.Get(identity)
		theirPid := identity.PublicKey().ToAffineCompressed()
		theirBigR := in.BigR
		theirBigRWitness := in.BigRWitness
		theirBigRCommitment, exists := p.state.theirBigRCommitment.Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find their bigR commitment (pid=%x)", theirPid)
		}

		// step 3.2: Open(sid || R_j || j || S)
		if err := commitments.Open(p.SessionId(), theirBigRCommitment, theirBigRWitness, []byte(commitmentDomainRLabel), theirBigR.ToAffineCompressed(), theirPid, p.state.bigS); err != nil {
			return nil, errs.WrapFailed(err, "cannot open R commitment")
		}

		// step 3.3: Run NIPoKDL.Verify(R_j, π^dl_j)
		if err := dlogVerifyProof(in.BigRProof, theirBigR, p.SessionId(), p.state.bigS, p.nic, p.Transcript().Clone()); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, identity.String(), "cannot verify dlog proof")
		}

		// step 3.4: R <- Σ R_j
		bigR = bigR.Add(theirBigR)
	}
	// step 3.5: Run PRZS.Round3({z^{b}_ji}_{∀j})
	przsInput := network.NewRoundMessages[*setup.Round2P2P]()
	for identity := range p.quorum.Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		r3, _ := unicastInput.Get(identity)
		przsInput.Put(identity, r3)
	}
	przsSeeds, err := p.przsParticipant.Round3(przsInput)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run PRZS setup")
	}
	// step 3.6: Run ζ_i <- PRZS.Sample()
	seededPrng, err := chacha.NewChachaPRNG(nil, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create seeded CSPRNG")
	}
	przsSampleParticipant, err := sample.NewParticipant(p.SessionId(), p.myAuthKey, przsSeeds, p.Protocol(), p.quorum, seededPrng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create seeded CSPRNG")
	}
	zeroS, err := przsSampleParticipant.Sample()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot sample zero share")
	}

	// step 3.7.1: compute additive share d_i'
	sk, err := p.mySigningKeyShare.ToAdditive(p.IdentityKey(), p.quorum, p.Protocol())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot converts to additive share")
	}

	// step 3.7.2: compute e
	eBytes := p.variant.ComputeChallengeBytes(bigR, p.mySigningKeyShare.PublicKey, message)
	e, err := schnorr.MakeSchnorrCompatibleChallenge(p.Protocol().CipherSuite(), eBytes)
	if err != nil {
		return nil, errs.NewFailed("cannot create digest scalar")
	}
	// step 3.7.3 & 3.8: compute s'_i and set s_i <- s'_i + ζ_i
	s := p.variant.ComputePartialResponse(bigR, p.mySigningKeyShare.PublicKey, p.state.k, sk, e).Add(zeroS)

	p.LastRound()
	return &lindell22.PartialSignature{
		E: e,
		R: p.variant.ComputePartialNonceCommitment(bigR, p.state.bigR),
		S: s,
	}, nil
}

func dlogProve(k curves.Scalar, bigR curves.Point, sessionId, bigS []byte, nic compiler.Name, transcript transcripts.Transcript, prng io.Reader) (proof compiler.NIZKPoKProof, err error) {
	curve := k.ScalarField().Curve()
	transcript.AppendMessages(transcriptDLogSLabel, bigS)
	proof, statement, err := dlog.Prove(sessionId, k, curve.Generator(), nic, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create a proof")
	}
	if !bigR.Equal(statement) {
		return nil, errs.NewFailed("invalid statement")
	}
	return proof, nil
}

func dlogVerifyProof(proof compiler.NIZKPoKProof, bigR curves.Point, sessionId, bigS []byte, nic compiler.Name, transcript transcripts.Transcript) (err error) {
	curve := bigR.Curve()
	transcript.AppendMessages(transcriptDLogSLabel, bigS)
	if err := dlog.Verify(sessionId, proof, bigR, curve.Generator(), nic, transcript); err != nil {
		return errs.WrapVerification(err, "cannot verify proof")
	}
	return nil
}
