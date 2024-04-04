package signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/ecdsa"
	mult "github.com/copperexchange/krypton-primitives/pkg/threshold/mult/dkls23"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23"
)

func DoRound1(p *Participant, protocol types.ThresholdProtocol, quorum ds.Set[types.IdentityKey], state *SignerState) (r1b *Round1Broadcast, r1p2p network.RoundMessages[types.ThresholdSignatureProtocol, *Round1P2P], err error) {
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

	state.InstanceKeyWitness = make(map[types.SharingID]commitments.Witness)
	state.Chi_i = make(map[types.SharingID]curves.Scalar)
	outputP2P := network.NewRoundMessages[types.ThresholdSignatureProtocol, *Round1P2P]()

	// step 1.3: For each other cosigner in the quorum...
	for participant := range quorum.Iter() {
		if participant.Equal(p.IdentityKey()) {
			continue
		}
		sharingId, exists := p.SharingConfig().Reverse().Get(participant)
		if !exists {
			return nil, nil, errs.NewMissing("could not find sharing id of %s", participant.String())
		}

		// step 1.4: (c'_ij, w_ij) <- Commit(i || j || sid || R_i)
		commitmentToInstanceKey, witness, err := commitments.Commit(
			p.SessionId,
			p.Prng,
			bitstring.ToBytesLE(int(p.SharingId())),
			bitstring.ToBytesLE(int(sharingId)),
			state.BigR_i.ToAffineCompressed(),
		)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not commit to instance key")
		}
		state.InstanceKeyWitness[sharingId] = witness

		// step 1.5: Run γ_ij <- RVOLE.Round1() as Bob
		multInstance, exists := state.Protocols.Multiplication.Get(participant)
		if !exists {
			return nil, nil, errs.NewMissing("could not find multiplication instance for %s", participant.String())
		}
		b, multiplicationOutput, err := multInstance.Bob.Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "multiplication round 1")
		}
		state.Chi_i[sharingId] = b

		// step 1.6: Send(c'_ij, γ_ij) -> P_j
		outputP2P.Put(participant, &Round1P2P{
			InstanceKeyCommitment: commitmentToInstanceKey,
			MultiplicationOutput:  multiplicationOutput,
		})
	}

	// step 1.7: Broadcast(R_i)
	outputBroadcast := &Round1Broadcast{
		BigR_i: state.BigR_i,
	}

	return outputBroadcast, outputP2P, nil
}

func DoRound2(p *Participant, protocol types.ThresholdProtocol, quorum ds.Set[types.IdentityKey], state *SignerState, inputBroadcast network.RoundMessages[types.ThresholdSignatureProtocol, *Round1Broadcast], inputP2P network.RoundMessages[types.ThresholdSignatureProtocol, *Round1P2P]) (*Round2Broadcast, network.RoundMessages[types.ThresholdSignatureProtocol, *Round2P2P], error) {
	// step 2.1: ζ_i <- Zero.Sample()
	zeta_i, err := state.Protocols.ZeroShareSampling.Sample()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "mask F_Zero (sample)")
	}
	state.Zeta_i = zeta_i

	// step 2.2: a_i <- Shamir.AdditiveShare(i, S, x_i)
	myAdditiveShare, err := p.Shard().SigningKeyShare.ToAdditive(p.IdentityKey(), quorum, protocol)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not convert my shamir share to additive share")
	}

	// step 2.3: sk_i <- a_i + ζ_i    &    Pk_i <- sk_i · G
	state.Sk_i = myAdditiveShare.Add(zeta_i)
	state.Pk_i = protocol.Curve().ScalarBaseMult(state.Sk_i)

	a := [mult.L]curves.Scalar{state.R_i, state.Sk_i}

	state.ReceivedBigR_i = hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()
	state.ReceivedInstanceKeyCommitments = make(map[types.SharingID]commitments.Commitment)
	state.Cu_i = make(map[types.SharingID]curves.Scalar)
	state.Cv_i = make(map[types.SharingID]curves.Scalar)
	outputP2P := network.NewRoundMessages[types.ThresholdSignatureProtocol, *Round2P2P]()
	// step 2.4: For each other cosigner in the quorum...
	for participant := range quorum.Iter() {
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
		multInstance, exists := state.Protocols.Multiplication.Get(participant)
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
		outputP2P.Put(participant, &Round2P2P{
			Multiplication:     multiplicationOutput,
			GammaU_ij:          gammaU_ij,
			GammaV_ij:          gammaV_ij,
			Psi_ij:             psi_ij,
			InstanceKeyWitness: state.InstanceKeyWitness[sharingId],
		})
	}

	// step 2.9: Broadcast(Pk_i)
	outputBroadcast := &Round2Broadcast{
		Pk_i: state.Pk_i,
	}

	return outputBroadcast, outputP2P, nil
}

func DoRound3Prologue(p *Participant, protocol types.ThresholdProtocol, quorum ds.Set[types.IdentityKey], state *SignerState, inputBroadcast network.RoundMessages[types.ThresholdSignatureProtocol, *Round2Broadcast], inputP2P network.RoundMessages[types.ThresholdSignatureProtocol, *Round2P2P]) (err error) {
	state.Du_i = make(map[types.SharingID]curves.Scalar)
	state.Dv_i = make(map[types.SharingID]curves.Scalar)
	state.Psi_i = make(map[types.SharingID]curves.Scalar)
	refreshedPublicKey := state.Pk_i // this has zeta_i added so different from the one from public key share map
	// step 3.1: For each other cosigner in the quorum...
	for participant := range quorum.Iter() {
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
		if err := commitments.Open(
			p.SessionId,
			state.ReceivedInstanceKeyCommitments[sharingId],
			receivedP2PMessage.InstanceKeyWitness,
			bitstring.ToBytesLE(int(sharingId)),
			bitstring.ToBytesLE(int(p.SharingId())),
			receivedBigR_i.ToAffineCompressed(),
		); err != nil {
			return errs.WrapIdentifiableAbort(err, participant.String(), "message could not be opened")
		}

		// step 3.3: Run ({d^u_ij, d^v_ij}) <- RVOLE.Round3(μ_ij) as Bob
		multInstance, exists := state.Protocols.Multiplication.Get(participant)
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
		lhs1 := R_j.Mul(Chi_ij).Sub(GammaU_ji)
		rhs1 := protocol.Curve().ScalarBaseMult(du_ij)
		if !lhs1.Equal(rhs1) {
			return errs.NewIdentifiableAbort(participant.String(), "failed first check")
		}

		// step 3.5: Check   b_ij · Pk_j - Γ^v_ij = d^v_ij · G
		lhs2 := pk_j.Mul(Chi_ij).Sub(GammaV_ji)
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

func DoRound3Epilogue(p *Participant, protocol types.ThresholdSignatureProtocol, quorum ds.Set[types.IdentityKey], message []byte, r, sk, phi curves.Scalar, cu, cv, du, dv, psi map[types.SharingID]curves.Scalar, bigRs ds.Map[types.IdentityKey, curves.Point]) (*dkls23.PartialSignature, error) {
	R := r.ScalarField().Curve().ScalarBaseMult(r)
	phiPsi := phi
	cUdU := phi.ScalarField().Zero()
	cVdV := phi.ScalarField().Zero()
	for participant := range quorum.Iter() {
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
	rx := protocol.SigningSuite().Curve().Scalar().SetNat(R.AffineX().Nat())
	digest, err := hashing.Hash(protocol.SigningSuite().Hash(), message)
	if err != nil {
		return nil, errs.WrapHashing(err, "digest")
	}
	digestScalar, err := protocol.SigningSuite().Curve().Scalar().SetBytesWide(digest)
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
func Aggregate(cipherSuite types.SigningSuite, publicKey curves.Point, partialSignatures network.RoundMessages[types.ThresholdSignatureProtocol, *dkls23.PartialSignature], message []byte) (*ecdsa.Signature, error) {
	curve := cipherSuite.Curve()
	w := curve.ScalarField().Zero()
	u := curve.ScalarField().Zero()
	R := curve.Identity()
	// step 4.1: R <- Σ R_i   &    rx <- R_x
	for pair := range partialSignatures.Iter() {
		partialSignature := pair.Value
		w = w.Add(partialSignature.Wi)
		u = u.Add(partialSignature.Ui)
		R = R.Add(partialSignature.Ri)
	}
	rx := curve.Scalar().SetNat(R.AffineX().Nat())
	// step 4.2: s <- (Σ w_i) / (Σ u_i)
	s := w.Div(u)
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
