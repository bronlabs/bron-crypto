package signing

import (
	"github.com/bronlabs/bron-crypto/pkg/base/bitstring"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	hashcommitments "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/bbot"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	mult "github.com/bronlabs/bron-crypto/pkg/threshold/mult/dkls23"
	zeroSetup "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/rprzs/setup"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23"
)

func DoRound1(p *Participant, protocol types.ThresholdSignatureProtocol) (network.RoundMessages[types.ThresholdSignatureProtocol, *Round1P2P], error) {
	zeroSamplingP2P, err := p.ZeroSamplingParty.Round1()
	if err != nil {
		return nil, errs.WrapFailed(err, "zero sampling round 1 failed")
	}
	baseOtP2P := hashmap.NewHashableHashMap[types.IdentityKey, *bbot.Round1P2P]()
	for identity, party := range p.BaseOTSenderParties.Iter() {
		r1out, err := party.Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "BaseOT as sender for identity %s", identity.String())
		}
		baseOtP2P.Put(identity, r1out)
	}

	p2pOutput := network.NewRoundMessages[types.ThresholdSignatureProtocol, *Round1P2P]()
	for identity := range p.Quorum().Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		zeroSamplingMessage, exists := zeroSamplingP2P.Get(identity)
		if !exists {
			return nil, errs.NewMissing("do not have a zero sampling message for %s", identity.String())
		}
		baseOtMessage, exists := baseOtP2P.Get(identity)
		if !exists {
			return nil, errs.NewMissing("do not have a baseot message for %s", identity.String())
		}
		p2pOutput.Put(identity, &Round1P2P{
			ZeroSampling: zeroSamplingMessage,
			BaseOTSender: baseOtMessage,
		})
	}
	return p2pOutput, nil
}

func DoRound2(p *Participant, protocol types.ThresholdSignatureProtocol,
	inputP2P network.RoundMessages[types.ThresholdSignatureProtocol, *Round1P2P],
) (network.RoundMessages[types.ThresholdSignatureProtocol, *Round2P2P], error) {
	// Validation
	if err := network.ValidateMessages(p.Protocol, p.Quorum(), p.IdentityKey(), inputP2P); err != nil {
		return nil, errs.WrapValidation(err, "round 1 output is invalid")
	}

	zeroSamplingRound1Output := network.NewRoundMessages[types.Protocol, *zeroSetup.Round1P2P]()
	baseOtRound1Output := network.NewRoundMessages[types.Protocol, *bbot.Round1P2P]()
	for sender, message := range inputP2P.Iter() {
		baseOtRound1Output.Put(sender, message.BaseOTSender)
		zeroSamplingRound1Output.Put(sender, message.ZeroSampling)
	}

	zeroSamplingP2P, err := p.ZeroSamplingParty.Round2(zeroSamplingRound1Output)
	if err != nil {
		return nil, errs.WrapFailed(err, "zero sampling round 2 failed")
	}

	baseOTP2P := network.NewRoundMessages[types.Protocol, *bbot.Round2P2P]()
	for identity, party := range p.BaseOTReceiverParties.Iter() {
		r2In, exists := baseOtRound1Output.Get(identity)
		if !exists {
			return nil, errs.NewMissing("did not have a message from %s", identity.String())
		}
		r2out, err := party.Round2(r2In)
		if err != nil {
			return nil, errs.WrapFailed(err, "base OT as receiver for identity %s", identity.String())
		}
		baseOTP2P.Put(identity, r2out)
	}
	p2pOutput := network.NewRoundMessages[types.ThresholdSignatureProtocol, *Round2P2P]()
	for identity := range p.Quorum().Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		zeroSamplingMessage, exists := zeroSamplingP2P.Get(identity)
		if !exists {
			return nil, errs.NewMissing("do not have a zero sampling message for %s", identity.String())
		}
		baseOtMessage, exists := baseOTP2P.Get(identity)
		if !exists {
			return nil, errs.NewMissing("do not have a baseot message for %s", identity.String())
		}
		p2pOutput.Put(identity, &Round2P2P{
			ZeroSampling:   zeroSamplingMessage,
			BaseOTReceiver: baseOtMessage,
		})
	}
	return p2pOutput, nil
}

func DoRound3Prologue(p *Participant, protocol types.ThresholdSignatureProtocol,
	round2outputP2P network.RoundMessages[types.ThresholdSignatureProtocol, *Round2P2P]) (dkls23.PairwiseSeeds, ds.Map[types.IdentityKey, *BaseOTConfig], error) {
	if err := network.ValidateMessages(p.Protocol, p.Quorum(), p.IdentityKey(), round2outputP2P); err != nil {
		return nil, nil, errs.WrapValidation(err, "round 2 output is invalid")
	}
	if err := p.shard.Validate(p.Protocol); err != nil {
		return nil, nil, errs.WrapValidation(err, "signing key share is invalid")
	}

	baseOtRound2Output := network.NewRoundMessages[types.Protocol, *bbot.Round2P2P]()
	zeroSamplingRound2Output := network.NewRoundMessages[types.Protocol, *zeroSetup.Round2P2P]()

	for party := range p.Quorum().Iter() {
		if party.Equal(p.myAuthKey) {
			continue
		}
		message, _ := round2outputP2P.Get(party)
		baseOtRound2Output.Put(party, message.BaseOTReceiver)
		zeroSamplingRound2Output.Put(party, message.ZeroSampling)
	}

	pairwiseSeeds, err := p.ZeroSamplingParty.Round3(zeroSamplingRound2Output)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "zero sampling round 3 failed")
	}

	for identity, party := range p.BaseOTSenderParties.Iter() {
		message, _ := baseOtRound2Output.Get(identity)
		if err := party.Round3(message); err != nil {
			return nil, nil, errs.WrapFailed(err, "base OT as sender for identity %s", identity.String())
		}
	}
	pairwiseBaseOTs := hashmap.NewHashableHashMap[types.IdentityKey, *BaseOTConfig]()
	for identity := range p.Quorum().Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		sender, exists := p.BaseOTSenderParties.Get(identity)
		if !exists {
			return nil, nil, errs.NewMissing("cannot get the sender party for %s", identity.String())
		}
		receiver, exists := p.BaseOTReceiverParties.Get(identity)
		if !exists {
			return nil, nil, errs.NewMissing("cannot get the receiver party for %s", identity.String())
		}
		pairwiseBaseOTs.Put(identity, &BaseOTConfig{
			AsSender:   sender.Output,
			AsReceiver: receiver.Output,
		})
	}

	return pairwiseSeeds, pairwiseBaseOTs, nil
}

func DoRound3(p *Participant, protocol types.ThresholdSignatureProtocol, state *SignerState,
) (r1b *Round3Broadcast, r1p2p network.RoundMessages[types.ThresholdSignatureProtocol, *Round3P2P], err error) {
	// step 1.1: Sample inversion mask Phi_i and instance key R_i
	state.Phi_i, err = protocol.Curve().ScalarField().Random(p.Prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "could not sample phi_i")
	}
	state.R_i, err = protocol.Curve().ScalarField().Random(p.Prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "could not sample r_i")
	}

	// step 1.2: public instance key BigR_i
	state.BigR_i = protocol.Curve().ScalarBaseMult(state.R_i)

	state.InstanceKeyOpening = make(map[types.SharingID]hashcommitments.Witness)
	state.Chi_i = make(map[types.SharingID]curves.Scalar)
	outputP2P := network.NewRoundMessages[types.ThresholdSignatureProtocol, *Round3P2P]()

	// step 1.3: For each other cosigner in the quorum...
	for participant := range p.Quorum().Iter() {
		if participant.Equal(p.IdentityKey()) {
			continue
		}
		sharingId, exists := p.SharingConfig().Reverse().Get(participant)
		if !exists {
			return nil, nil, errs.NewMissing("could not find sharing id of %s", participant.String())
		}

		// step 1.4: (c'_ij, w_ij) <- Commit(i || j || sid || R_i)
		committer, err := hashcommitments.NewCommittingKeyFromCrsBytes(p.SessionId, bitstring.ToBytes32LE(int32(p.SharingId())), bitstring.ToBytes32LE(int32(sharingId)))
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot instantiate committer")
		}
		commitmentToInstanceKey, opening, err := committer.Commit(state.BigR_i.ToAffineCompressed(), p.Prng)
		if err != nil {
			return nil, nil, errs.NewFailed("cannot commit to instance key")
		}
		state.InstanceKeyOpening[sharingId] = opening

		// step 1.5: Run γ_ij <- RVOLE.Round1() as Bob
		multInstance, exists := p.SubProtocols.Multiplication.Get(participant)
		if !exists {
			return nil, nil, errs.NewMissing("could not find multiplication instance for %s", participant.String())
		}
		b, multiplicationOutput, err := multInstance.Bob.Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "multiplication round 1")
		}
		state.Chi_i[sharingId] = b

		// step 1.6: Send(c'_ij, γ_ij) -> P_j
		outputP2P.Put(participant, &Round3P2P{
			InstanceKeyCommitment: commitmentToInstanceKey,
			MultiplicationOutput:  multiplicationOutput,
		})
	}

	// step 1.7: Broadcast(R_i)
	outputBroadcast := &Round3Broadcast{
		BigR_i: state.BigR_i,
	}

	return outputBroadcast, outputP2P, nil
}

func DoRound4(p *Participant, protocol types.ThresholdSignatureProtocol, state *SignerState,
	inputBroadcast network.RoundMessages[types.ThresholdSignatureProtocol, *Round3Broadcast],
	inputP2P network.RoundMessages[types.ThresholdSignatureProtocol, *Round3P2P],
) (*Round4Broadcast, network.RoundMessages[types.ThresholdSignatureProtocol, *Round4P2P], error) {
	// Validation
	if err := network.ValidateMessages(protocol, p.Quorum(), p.IdentityKey(), inputBroadcast); err != nil {
		return nil, nil, errs.WrapValidation(err, "invalid round 2 input broadcast messages")
	}
	if err := network.ValidateMessages(protocol, p.Quorum(), p.IdentityKey(), inputP2P); err != nil {
		return nil, nil, errs.WrapValidation(err, "invalid round 2 input P2P messages")
	}

	// step 2.1: ζ_i <- Zero.Sample()
	zeta_i, err := p.SubProtocols.ZeroShareSampling.Sample()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "mask F_Zero (sample)")
	}
	state.Zeta_i = zeta_i

	// step 2.2: a_i <- Shamir.AdditiveShare(i, S, x_i)
	myAdditiveShare, err := p.Shard().SigningKeyShare.ToAdditive(p.IdentityKey(), p.Quorum(), protocol)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not convert my shamir share to additive share")
	}

	// step 2.3: sk_i <- a_i + ζ_i    &    Pk_i <- sk_i · G
	state.Sk_i = myAdditiveShare.Add(zeta_i)
	state.Pk_i = protocol.Curve().ScalarBaseMult(state.Sk_i)

	a := [mult.L]curves.Scalar{state.R_i, state.Sk_i}

	state.ReceivedBigR_i = hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()
	state.ReceivedInstanceKeyCommitments = make(map[types.SharingID]hashcommitments.Commitment)
	state.Cu_i = make(map[types.SharingID]curves.Scalar)
	state.Cv_i = make(map[types.SharingID]curves.Scalar)
	outputP2P := network.NewRoundMessages[types.ThresholdSignatureProtocol, *Round4P2P]()
	// step 2.4: For each other cosigner in the quorum...
	for participant := range p.Quorum().Iter() {
		if participant.Equal(p.IdentityKey()) {
			continue
		}
		sharingId, exists := p.SharingConfig().Reverse().Get(participant)
		if !exists {
			return nil, nil, errs.NewMissing("could not find sharing id of %s", participant.String())
		}

		receivedBroadcastMessage, exists := inputBroadcast.Get(participant)
		if !exists {
			return nil, nil, errs.NewMissing("did not get a broadcasted message from id %d", sharingId)
		}
		state.ReceivedBigR_i.Put(participant, receivedBroadcastMessage.BigR_i)

		receivedP2PMessage, exists := inputP2P.Get(participant)
		if !exists {
			return nil, nil, errs.NewMissing("did not get a p2p message from id %d", sharingId)
		}
		state.ReceivedInstanceKeyCommitments[sharingId] = receivedP2PMessage.InstanceKeyCommitment

		// step 2.5: Run (μ_ij, c={c^u_ij, c^v_ij}) <- RVOLE.Round2(γ_ij, a={r_i, sk_i}) as Alice
		multInstance, exists := p.SubProtocols.Multiplication.Get(participant)
		if !exists {
			return nil, nil, errs.NewMissing("could not find multiplication instance for %s", participant.String())
		}
		c_ij, multiplicationOutput, err := multInstance.Alice.Round2(receivedP2PMessage.MultiplicationOutput, a)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "F_RVOLE round 2 sample")
		}
		state.Cu_i[sharingId] = c_ij[0]
		state.Cv_i[sharingId] = c_ij[1]

		// step 2.6: Γ^u_ij <- c^u_ij · G    &    Γ^v_ij <- c^v_ij · G
		gammaU_ij := protocol.Curve().ScalarBaseMult(state.Cu_i[sharingId])
		gammaV_ij := protocol.Curve().ScalarBaseMult(state.Cv_i[sharingId])

		// step 2.7: ψ_ij <- Φ_i - b_ij
		psi_ij := state.Phi_i.Sub(state.Chi_i[sharingId])

		// step 2.8: Send(μ_ij, Γ^u_ij, Γ^v_ij, ψ_ij, w_ij, R_i) -> P_j
		outputP2P.Put(participant, &Round4P2P{
			Multiplication:     multiplicationOutput,
			GammaU_ij:          gammaU_ij,
			GammaV_ij:          gammaV_ij,
			Psi_ij:             psi_ij,
			InstanceKeyOpening: state.InstanceKeyOpening[sharingId],
		})
	}

	// step 2.9: Broadcast(Pk_i)
	outputBroadcast := &Round4Broadcast{
		Pk_i: state.Pk_i,
	}

	return outputBroadcast, outputP2P, nil
}

func DoRound5Prologue(p *Participant, protocol types.ThresholdSignatureProtocol, state *SignerState,
	inputBroadcast network.RoundMessages[types.ThresholdSignatureProtocol, *Round4Broadcast],
	inputP2P network.RoundMessages[types.ThresholdSignatureProtocol, *Round4P2P],
) (err error) {
	// Validation
	if err := network.ValidateMessages(protocol, p.Quorum(), p.IdentityKey(), inputBroadcast); err != nil {
		return errs.WrapValidation(err, "invalid round 3 input broadcast messages")
	}
	if err := network.ValidateMessages(protocol, p.Quorum(), p.IdentityKey(), inputP2P); err != nil {
		return errs.WrapValidation(err, "invalid round 3 input P2P messages")
	}

	state.Du_i = make(map[types.SharingID]curves.Scalar)
	state.Dv_i = make(map[types.SharingID]curves.Scalar)
	state.Psi_i = make(map[types.SharingID]curves.Scalar)
	refreshedPublicKey := state.Pk_i // this has zeta_i added so different from the one from public key share map
	// step 3.1: For each other cosigner in the quorum...
	for participant := range p.Quorum().Iter() {
		if participant.Equal(p.IdentityKey()) {
			continue
		}
		sharingId, exists := p.SharingConfig().Reverse().Get(participant)
		if !exists {
			return errs.NewMissing("could not find sharing id of %s", participant.String())
		}

		receivedBroadcastMessage, exists := inputBroadcast.Get(participant)
		if !exists {
			return errs.NewMissing("did not get a broadcasted message from id %d", sharingId)
		}
		pk_j := receivedBroadcastMessage.Pk_i

		receivedP2PMessage, exists := inputP2P.Get(participant)
		if !exists {
			return errs.NewMissing("did not get a p2p message from id %d", sharingId)
		}
		GammaU_ji := receivedP2PMessage.GammaU_ij
		GammaV_ji := receivedP2PMessage.GammaV_ij

		receivedBigR_i, exists := state.ReceivedBigR_i.Get(participant)
		if !exists {
			return errs.NewMissing("do not have BigRI in memory for %s", participant.String())
		}
		// step 3.2: Open(j || i || sid || R_i, c'_ij, w_ij)
		verifier, err := hashcommitments.NewCommittingKeyFromCrsBytes(p.SessionId, bitstring.ToBytes32LE(int32(sharingId)), bitstring.ToBytes32LE(int32(p.SharingId())))
		if err != nil {
			return errs.WrapFailed(err, "cannot create verifier")
		}
		// if !bytes.Equal(receivedBigR_i.ToAffineCompressed(), receivedP2PMessage.InstanceKeyOpening.GetMessage()) {
		//	return errs.NewVerification("opening is not tied to the expected value")
		//}
		if err := verifier.Verify(state.ReceivedInstanceKeyCommitments[sharingId], receivedBigR_i.ToAffineCompressed(), receivedP2PMessage.InstanceKeyOpening); err != nil {
			return errs.WrapIdentifiableAbort(err, participant.String(), "message could not be opened")
		}

		// step 3.3: Run ({d^u_ij, d^v_ij}) <- RVOLE.Round3(μ_ij) as Bob
		multInstance, exists := p.SubProtocols.Multiplication.Get(participant)
		if !exists {
			return errs.NewMissing("could not find multiplication instance for %s", participant.String())
		}
		d_ij, err := multInstance.Bob.Round3(receivedP2PMessage.Multiplication)
		if err != nil {
			return errs.WrapIdentifiableAbort(err, participant.String(), "bob round 3")
		}
		du_ij := d_ij[0]
		dv_ij := d_ij[1]

		// step 3.4: Check   b_ij · R_j - Γ^u_ij = d^u_ij · G
		Chi_ij := state.Chi_i[sharingId]
		R_j, exists := state.ReceivedBigR_i.Get(participant)
		if !exists {
			return errs.NewMissing("do not have Rj in memory for j=%d", sharingId)
		}
		lhs1 := R_j.ScalarMul(Chi_ij).Sub(GammaU_ji)
		rhs1 := protocol.Curve().ScalarBaseMult(du_ij)
		if !lhs1.Equal(rhs1) {
			return errs.NewIdentifiableAbort(participant.String(), "failed first check")
		}

		// step 3.5: Check   b_ij · Pk_j - Γ^v_ij = d^v_ij · G
		lhs2 := pk_j.ScalarMul(Chi_ij).Sub(GammaV_ji)
		rhs2 := protocol.Curve().ScalarBaseMult(dv_ij)
		if !lhs2.Equal(rhs2) {
			return errs.NewIdentifiableAbort(participant.String(), "failed second check")
		}

		refreshedPublicKey = refreshedPublicKey.Add(pk_j)

		// We're partially evaluating what we need for future steps inside of this loop
		state.Du_i[sharingId] = du_ij
		state.Dv_i[sharingId] = dv_ij
		state.Psi_i[sharingId] = receivedP2PMessage.Psi_ij
	}

	// step 3.6: Check Σ Pk_j = Pk
	if !refreshedPublicKey.Equal(p.Shard().SigningKeyShare.PublicKey) {
		return errs.NewTotalAbort(nil, "recomputed public key is wrong")
	}

	return nil
}

func DoRound5Epilogue(p *Participant, protocol types.ThresholdSignatureProtocol,
	message []byte, r, sk, phi curves.Scalar, cu, cv, du, dv, psi map[types.SharingID]curves.Scalar, bigRs ds.Map[types.IdentityKey, curves.Point],
) (*dkls23.PartialSignature, error) {
	R := r.ScalarField().Curve().ScalarBaseMult(r)
	phiPsi := phi
	cUdU := phi.ScalarField().Zero()
	cVdV := phi.ScalarField().Zero()
	for participant := range p.Quorum().Iter() {
		if participant.Equal(p.IdentityKey()) {
			continue
		}
		sharingId, exists := p.SharingConfig().Reverse().Get(participant)
		if !exists {
			return nil, errs.NewMissing("could not find sharing id of %s", participant.String())
		}
		cu_ij := cu[sharingId]
		cv_ij := cv[sharingId]
		du_ij := du[sharingId]
		dv_ij := dv[sharingId]
		phiPsi = phiPsi.Add(psi[sharingId])
		cUdU = cUdU.Add(cu_ij).Add(du_ij)
		cVdV = cVdV.Add(cv_ij).Add(dv_ij)
		Rj, exists := bigRs.Get(participant)
		if !exists {
			return nil, errs.NewMissing("no Rj for j=%d", sharingId)
		}
		// step 3.7: R <- Σ R_j
		R = R.Add(Rj)
	}

	// step 3.8: u_i <- r · (Φ_i + Σ ψ_ij) + Σ (c^u_ij + d^u_ij)
	u_i := r.Mul(phiPsi).Add(cUdU)

	// step 3.9: w_i <- sk_i · (Φ_i + Σ ψ_ij) + Σ (c^v_ij + d^v_ij)
	v_i := sk.Mul(phiPsi).Add(cVdV)

	// step 3.10: w_i <- H(m) · Φ_i + R_x · v_i
	rx := protocol.SigningSuite().Curve().ScalarField().Element().SetNat(R.AffineX().Nat())
	digest, err := hashing.Hash(protocol.SigningSuite().Hash(), message)
	if err != nil {
		return nil, errs.WrapHashing(err, "digest")
	}
	digestScalar, err := protocol.SigningSuite().Curve().ScalarField().Element().SetBytesWide(digest)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "digestScalar")
	}
	w_i := digestScalar.Mul(phi).Add(rx.Mul(v_i))

	// step 3.11: σ_i={u_i, w_i}
	return &dkls23.PartialSignature{
		Ui: u_i,
		Wi: w_i,
		Ri: r.ScalarField().Curve().ScalarBaseMult(r),
	}, nil
}

// Aggregate computes the sum of partial signatures to get a valid signature. It also normalises the signature to the low-s form as well as attaches the recovery id to the final signature.
func Aggregate(cipherSuite types.SigningSuite, publicKey curves.Point,
	partialSignatures network.RoundMessages[types.ThresholdSignatureProtocol, *dkls23.PartialSignature], message []byte) (*ecdsa.Signature, error) {
	curve := cipherSuite.Curve()
	w := curve.ScalarField().Zero()
	u := curve.ScalarField().Zero()
	R := curve.AdditiveIdentity()
	// step 4.1: R <- Σ R_i   &    rx <- R_x
	for _, partialSignature := range partialSignatures.Iter() {
		w = w.Add(partialSignature.Wi)
		u = u.Add(partialSignature.Ui)
		R = R.Add(partialSignature.Ri)
	}
	rx := curve.ScalarField().Element().SetNat(R.AffineX().Nat())
	// step 4.2: s <- (Σ w_i) / (Σ u_i)
	s, err := w.Div(u)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute w/u")
	}

	// step 4.3: v <- (R_y mod 2) + 2(R_x > q)
	v, err := ecdsa.CalculateRecoveryId(R)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute recovery id")
	}
	// steps 4.4-4.6: s = min(s, -s mod q);    v = v + 2 · (s > -s mod q)
	sigma := &ecdsa.Signature{V: &v, R: rx, S: s}
	sigma.Normalise()
	// step 4.7
	if err := ecdsa.Verify(sigma, cipherSuite.Hash(), publicKey, message); err != nil {
		return nil, errs.WrapVerification(err, "sigma is invalid")
	}
	return sigma, nil
}
