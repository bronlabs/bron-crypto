package interactive_signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/chacha"
	schnorrSigma "github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	compilerUtils "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler_utils"
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

type Round1Broadcast struct {
	BigRCommitment commitments.Commitment

	_ ds.Incomparable
}

type Round1P2P struct {
	Przs *setup.Round1P2P

	_ ds.Incomparable
}

type Round2Broadcast struct {
	BigRProof   compiler.NIZKPoKProof
	BigR        curves.Point
	BigRWitness commitments.Witness

	_ ds.Incomparable
}

type Round2P2P struct {
	Przs *setup.Round2P2P

	_ ds.Incomparable
}

func (p *Cosigner[F]) Round1() (broadcastOutput *Round1Broadcast, unicastOutput types.RoundMessages[*Round1P2P], err error) {
	if p.round != 1 {
		return nil, nil, errs.NewRound("round mismatch %d != 1", p.round)
	}

	// step 1.1: Sample k_i <-$- ℤ_q  &  compute R_i = k_i * G
	k, err := p.protocol.Curve().ScalarField().Random(p.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot generate random k")
	}
	bigR := p.protocol.Curve().ScalarBaseMult(k)

	// step 1.2: Run c_i <= commit(R_i || i || sid || S)
	bigRCommitment, bigRWitness, err := commit(p.prng, bigR, p.state.pid, p.sessionId, p.state.bigS)
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
	unicast := types.NewRoundMessages[*Round1P2P]()
	for pair := range przsOutput.Iter() {
		id := pair.Key
		r1 := pair.Value
		unicast.Put(id, &Round1P2P{
			Przs: r1,
		})
	}

	p.state.k = k
	p.state.bigR = bigR
	p.state.bigRWitness = bigRWitness
	p.round++

	return broadcast, unicast, nil
}

func (p *Cosigner[F]) Round2(broadcastInput types.RoundMessages[*Round1Broadcast], unicastInput types.RoundMessages[*Round1P2P]) (broadcastOutput *Round2Broadcast, unicastOutput types.RoundMessages[*Round2P2P], err error) {
	if p.round != 2 {
		return nil, nil, errs.NewRound("round mismatch %d != 2", p.round)
	}

	p.state.theirBigRCommitment = hashmap.NewHashableHashMap[types.IdentityKey, commitments.Commitment]()
	for identity := range p.sessionParticipants.Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}

		in, ok := broadcastInput.Get(identity)
		if !ok {
			return nil, nil, errs.NewMissing("no input from participant")
		}
		p.state.theirBigRCommitment.Put(identity, in.BigRCommitment)
	}

	// step 2.1: π^dl_i <- NIPoKDL.Prove(k_i, R_i, sessionId, S, nic)
	bigRProof, err := dlogProve(p.state.k, p.state.bigR, p.sessionId, p.state.bigS, p.nic, p.transcript.Clone(), p.prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot prove dlog")
	}

	// step 2.2: Run z^{b}_i <- PRZS.Round1({z^{a}_ji}_∀j)
	przsInput := types.NewRoundMessages[*setup.Round1P2P]()
	for pair := range unicastInput.Iter() {
		identity := pair.Key
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		r2 := pair.Value
		if r2 == nil {
			return nil, nil, errs.NewIsNil("r2 for identity %x", identity.PublicKey())
		}
		przsInput.Put(identity, r2.Przs)
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
	unicast := types.NewRoundMessages[*Round2P2P]()
	for pair := range przsOutput.Iter() {
		id := pair.Key
		r2 := pair.Value
		unicast.Put(id, &Round2P2P{
			Przs: r2,
		})
	}

	p.round++
	return broadcast, unicast, nil
}

func (p *Cosigner[F]) Round3(broadcastInput types.RoundMessages[*Round2Broadcast], unicastInput types.RoundMessages[*Round2P2P], message []byte) (partialSignature *lindell22.PartialSignature, err error) {
	if p.round != 3 {
		return nil, errs.NewRound("round mismatch %d != 3", p.round)
	}

	bigR := p.state.bigR
	// step 3.1: For all other participants P_j in the quorum...
	for identity := range p.sessionParticipants.Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}

		in, ok := broadcastInput.Get(identity)
		if !ok {
			return nil, errs.NewMissing("no input from participant")
		}

		theirPid := identity.PublicKey().ToAffineCompressed()
		theirBigR := in.BigR
		theirBigRWitness := in.BigRWitness
		theirBigRCommitment, exists := p.state.theirBigRCommitment.Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find their bigR commitment (pid=%x)", theirPid)
		}

		// step 3.2: Open(R_j || j || sid || S)
		if err := openCommitment(theirBigR, theirPid, p.sessionId, p.state.bigS, theirBigRCommitment, theirBigRWitness); err != nil {
			return nil, errs.WrapFailed(err, "cannot open R commitment")
		}

		// step 3.3: Run NIPoKDL.Verify(R_j, π^dl_j)
		if err := dlogVerifyProof(in.BigRProof, theirBigR, p.sessionId, p.state.bigS, p.nic, p.transcript.Clone()); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, identity.PublicKey().ToAffineCompressed(), "cannot verify dlog proof")
		}

		// step 3.4: R <- Σ R_j
		bigR = bigR.Add(theirBigR)
	}
	// step 3.5: Run PRZS.Round3({z^{b}_ji}_{∀j})
	przsInput := types.NewRoundMessages[*setup.Round2P2P]()
	for pair := range unicastInput.Iter() {
		identity := pair.Key
		r3 := pair.Value
		przsInput.Put(identity, r3.Przs)
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
	przsSampleParticipant, err := sample.NewParticipant(p.sessionId, p.myAuthKey, przsSeeds, p.protocol, p.sessionParticipants, seededPrng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create seeded CSPRNG")
	}
	zeroS, err := przsSampleParticipant.Sample()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot sample zero share")
	}

	// step 3.7.1: compute additive share d_i'
	sk, err := p.mySigningKeyShare.ToAdditive(p.IdentityKey(), p.sessionParticipants, p.protocol)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot converts to additive share")
	}

	// step 3.7.2: compute e
	eBytes := p.variant.ComputeChallengeBytes(bigR, p.mySigningKeyShare.PublicKey, message)
	e, err := schnorr.MakeSchnorrCompatibleChallenge(p.protocol.CipherSuite(), eBytes)
	if err != nil {
		return nil, errs.NewFailed("cannot create digest scalar")
	}
	// step 3.7.3 & 3.8: compute s'_i and set s_i <- s'_i + ζ_i
	s := p.variant.ComputePartialResponse(bigR, p.mySigningKeyShare.PublicKey, p.state.k, sk, e).Add(zeroS)

	p.round++
	return &lindell22.PartialSignature{
		E: e,
		R: p.variant.ComputePartialNonceCommitment(bigR, p.state.bigR),
		S: s,
	}, nil
}

func commit(prng io.Reader, bigR curves.Point, pid, sessionId, bigS []byte) (commitment commitments.Commitment, witness commitments.Witness, err error) {
	commitment, witness, err = commitments.Commit(sessionId, prng, []byte(commitmentDomainRLabel), bigR.ToAffineCompressed(), pid, bigS)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot commit to R")
	}

	return commitment, witness, nil
}

func openCommitment(bigR curves.Point, pid, sessionId, bigS []byte, commitment commitments.Commitment, witness commitments.Witness) (err error) {
	if err := commitments.Open(sessionId, commitment, witness, []byte(commitmentDomainRLabel), bigR.ToAffineCompressed(), pid, bigS); err != nil {
		return errs.WrapVerification(err, "couldn't open")
	}
	return nil
}

func dlogProve(k curves.Scalar, bigR curves.Point, sessionId, bigS []byte, nic compiler.Name, transcript transcripts.Transcript, prng io.Reader) (proof compiler.NIZKPoKProof, err error) {
	transcript.AppendMessages(transcriptDLogSLabel, bigS)
	curve := k.ScalarField().Curve()
	sigmaProtocol, err := schnorrSigma.NewSigmaProtocol(curve.Generator(), prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct schnorr sigma protocol")
	}
	niSigma, err := compilerUtils.MakeNonInteractive(nic, sigmaProtocol, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert schnorr sigma protocol into non interactive")
	}
	prover, err := niSigma.NewProver(sessionId, transcript)
	if err != nil {
		return nil, errs.NewFailed("cannot create dlog prover")
	}
	proof, err = prover.Prove(bigR, k)
	if err != nil {
		return nil, errs.NewFailed("cannot create a proof")
	}
	return proof, nil
}

func dlogVerifyProof(proof compiler.NIZKPoKProof, bigR curves.Point, sessionId, bigS []byte, nic compiler.Name, transcript transcripts.Transcript) (err error) {
	transcript.AppendMessages(transcriptDLogSLabel, bigS)
	curve := bigR.Curve()
	sigmaProtocol, err := schnorrSigma.NewSigmaProtocol(curve.Generator(), nil)
	if err != nil {
		return errs.WrapFailed(err, "could not construct schnorr sigma protocol")
	}
	niSigma, err := compilerUtils.MakeNonInteractive(nic, sigmaProtocol, nil)
	if err != nil {
		return errs.WrapFailed(err, "could not convert schnorr sigma protocol into non interactive")
	}
	verifier, err := niSigma.NewVerifier(sessionId, transcript)
	if err != nil {
		return errs.WrapFailed(err, "could not construct verifier")
	}
	if err := verifier.Verify(bigR, proof); err != nil {
		return errs.WrapVerification(err, "dlog proof failed")
	}
	return nil
}
