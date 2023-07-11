package gennaro

import (
	"fmt"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	pedersenDkg "github.com/copperexchange/crypto-primitives-go/pkg/dkg/pedersen"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/pedersen"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold"
	dlog "github.com/copperexchange/crypto-primitives-go/pkg/zkp/schnorr"
	"github.com/gtank/merlin"
)

const DlogProofLabel = "COPPER_KNOX_GENNARO_DKG_DLOG_PROOF-"

type Round1Broadcast struct {
	BlindedCommitments []curves.Point
}

type Round1P2P struct {
	X_ij      curves.Scalar
	XPrime_ij curves.Scalar
}

type Round2Broadcast struct {
	Commitments    []curves.Point
	A_i0Proof      *dlog.Proof
	APrime_i0Proof *dlog.Proof
}

func (p *Participant) Round1() (*Round1Broadcast, map[integration.IdentityKey]*Round1P2P, error) {
	if p.round != 1 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}
	a_i0 := p.CohortConfig.CipherSuite.Curve.Scalar.Random(p.prng)

	dealer, err := pedersen.NewDealer(p.CohortConfig.Threshold, p.CohortConfig.TotalParties, p.H)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't construct pedersen dealer")
	}
	dealt := dealer.Split(a_i0, p.prng)

	proverTranscript := merlin.NewTranscript(DlogProofLabel)
	proverTranscript.AppendMessage([]byte("shamir id"), []byte(fmt.Sprintf("%d", p.MyShamirId)))
	prover, err := dlog.NewProver(p.CohortConfig.CipherSuite.Curve.Point.Generator(), p.UniqueSessionId, proverTranscript)

	a_i0Proof, err := prover.Prove(a_i0)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not prove dlog proof of a_i0")
	}
	prover.BasePoint = p.H
	// note that prover transcript will contain a_i0 transcript
	aPrime_i0Proof, err := prover.Prove(dealt.Blinding)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not prove dlog proof of aPrime_i0")
	}

	outboundP2PMessages := map[integration.IdentityKey]*Round1P2P{}
	for shamirId, identityKey := range p.shamirIdToIdentityKey {
		if shamirId != p.MyShamirId {
			shamirIndex := shamirId - 1
			xij := dealt.SecretShares[shamirIndex].Value
			xPrimeIJ := dealt.BlindingShares[shamirIndex].Value
			outboundP2PMessages[identityKey] = &Round1P2P{
				X_ij:      xij,
				XPrime_ij: xPrimeIJ,
			}
			dealt.SecretShares[shamirIndex] = nil
			dealt.BlindingShares[shamirIndex] = nil
		}
	}
	a_i0 = nil
	dealt.Blinding = nil

	p.state.myPartialSecretShare = dealt.SecretShares[p.MyShamirId-1]
	p.state.commitments = dealt.Commitments
	p.state.blindedCommitments = dealt.BlindedCommitments
	p.state.a_i0Proof = a_i0Proof
	p.state.aPrime_i0Proof = aPrime_i0Proof

	p.round++
	return &Round1Broadcast{
		BlindedCommitments: dealt.BlindedCommitments,
	}, outboundP2PMessages, nil
}

func (p *Participant) Round2(round1outputBroadcast map[integration.IdentityKey]*Round1Broadcast, round1outputP2P map[integration.IdentityKey]*Round1P2P) (*Round2Broadcast, error) {
	if p.round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}
	secretKeyShare := p.state.myPartialSecretShare.Value

	receivedBlindedCommitmentVectors := map[int][]curves.Point{
		p.MyShamirId: p.state.commitments,
	}
	partialPublicKeyShares := map[int]curves.Point{}

	for senderShamirId := 1; senderShamirId <= p.CohortConfig.TotalParties; senderShamirId++ {
		if senderShamirId == p.MyShamirId {
			continue
		}
		senderIdentityKey, exists := p.shamirIdToIdentityKey[senderShamirId]
		if !exists {
			return nil, errs.NewMissing("can't find identity key of shamir id %d", senderShamirId)
		}
		broadcastedMessageFromSender, exists := round1outputBroadcast[senderIdentityKey]
		if !exists {
			return nil, errs.NewMissing("do not have broadcasted message of the sender with shamir id %d", senderShamirId)
		}
		senderBlindedCommitmentVector := broadcastedMessageFromSender.BlindedCommitments

		p2pMessageFromSender, exists := round1outputP2P[senderIdentityKey]
		if !exists {
			return nil, errs.NewMissing("did not get a p2p message from sender with shamir id %d", senderShamirId)
		}
		receivedShare := &pedersen.Share{
			Id:    p.MyShamirId,
			Value: p2pMessageFromSender.X_ij,
		}
		receivedBlindingShare := &pedersen.Share{
			Id:    p.MyShamirId,
			Value: p2pMessageFromSender.XPrime_ij,
		}
		if err := pedersen.Verify(receivedShare, receivedBlindingShare, senderBlindedCommitmentVector, p.H); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, "abort from pedersen (shamir id: %d)", senderShamirId)
		}

		secretKeyShare = secretKeyShare.Add(p2pMessageFromSender.X_ij)
		round1outputP2P[senderIdentityKey] = nil
		receivedBlindedCommitmentVectors[senderShamirId] = senderBlindedCommitmentVector
		partialPublicKeyShares[senderShamirId] = p.CohortConfig.CipherSuite.Curve.ScalarBaseMult(p2pMessageFromSender.X_ij)
	}

	p.state.secretKeyShare = secretKeyShare
	p.state.receivedBlindedCommitmentVectors = receivedBlindedCommitmentVectors
	p.state.partialPublicKeyShares = partialPublicKeyShares
	p.round++
	return &Round2Broadcast{
		Commitments:    p.state.commitments,
		A_i0Proof:      p.state.a_i0Proof,
		APrime_i0Proof: p.state.aPrime_i0Proof,
	}, nil
}

func (p *Participant) Round3(round2output map[integration.IdentityKey]*Round2Broadcast) (*threshold.SigningKeyShare, *threshold.PublicKeyShares, error) {
	if p.round != 3 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 3", p.round)
	}
	publicKey := p.state.commitments[0]
	receivedCommitmentVectors := map[int][]curves.Point{
		p.MyShamirId: p.state.commitments,
	}

	for senderShamirId := 1; senderShamirId <= p.CohortConfig.TotalParties; senderShamirId++ {
		if senderShamirId == p.MyShamirId {
			continue
		}
		senderIdentityKey, exists := p.shamirIdToIdentityKey[senderShamirId]
		if !exists {
			return nil, nil, errs.NewMissing("can't find identity key of shamir id %d", senderShamirId)
		}
		broadcastedMessageFromSender, exists := round2output[senderIdentityKey]
		if !exists {
			return nil, nil, errs.NewMissing("do not have broadcasted message of the sender with shamir id %d", senderShamirId)
		}
		if broadcastedMessageFromSender.A_i0Proof == nil {
			return nil, nil, errs.NewMissing("do not have the dlog proof of a_i0 for shamir id %d", senderShamirId)
		}
		if broadcastedMessageFromSender.A_i0Proof.Statement == nil {
			return nil, nil, errs.NewMissing("do not have the statement of the dlog proof of a_i0 for shamir id %d", senderShamirId)
		}
		if broadcastedMessageFromSender.APrime_i0Proof == nil {
			return nil, nil, errs.NewMissing("do not have the the dlog proof of aPrime_i0 for shamir id %d", senderShamirId)
		}
		if broadcastedMessageFromSender.APrime_i0Proof.Statement == nil {
			return nil, nil, errs.NewMissing("do not have the statement of the dlog proof of aPrime_i0 for shamir id %d", senderShamirId)
		}
		senderCommitmentVector := broadcastedMessageFromSender.Commitments
		senderCommitmentToTheirLocalSecret := senderCommitmentVector[0]
		senderBlindedCommitmentVector := p.state.receivedBlindedCommitmentVectors[senderShamirId]
		senderCommitmentToTheirBlindedSecret := senderBlindedCommitmentVector[0]
		jointStatements := broadcastedMessageFromSender.A_i0Proof.Statement.Add(broadcastedMessageFromSender.APrime_i0Proof.Statement)

		if !senderCommitmentToTheirBlindedSecret.Equal(jointStatements) {
			return nil, nil, errs.NewIdentifiableAbort("aG + a'H != (a+a')(G+H) for shamir id %d", senderShamirId)
		}

		if p.CohortConfig.CipherSuite.Curve.Name == curves.ED25519Name {
			edwardsPoint, ok := senderCommitmentToTheirLocalSecret.(*curves.PointEd25519)
			if !ok {
				return nil, nil, errs.NewIdentifiableAbort("curve is ed25519 but the sender with shamirId %d did not have a valid commitment to her local secret.", senderShamirId)
			}
			// Since the honest behavior is to create a scalar out of the ristretto group, it is guaranteed to be in the prime subgroup.
			// A malicious party - or a party engaging in DKG with another client software - may send this element such that it needs cofactor clearing.
			// Such an element has a 1/8 chance of bypassing the dlog proof therefore successfully injecting a small group element into
			// the resulting public key. More info: https://medium.com/zengo/baby-sharks-a3b9ceb4efe0
			if edwardsPoint.Double().Double().Double().Sub(edwardsPoint).IsIdentity() {
				return nil, nil, errs.NewIdentifiableAbort("shamir id %d tries to contribute a small group element to the public key", senderShamirId)
			}
		}

		transcript := merlin.NewTranscript(DlogProofLabel)
		transcript.AppendMessage([]byte("shamir id"), []byte(fmt.Sprintf("%d", senderShamirId)))
		if err := dlog.Verify(p.CohortConfig.CipherSuite.Curve.Point.Generator(), broadcastedMessageFromSender.A_i0Proof, p.UniqueSessionId, transcript); err != nil {
			return nil, nil, errs.WrapIdentifiableAbort(err, "abort from schnorr dlog proof of a_i0 (shamir id: %d)", senderShamirId)
		}
		if err := dlog.Verify(p.H, broadcastedMessageFromSender.APrime_i0Proof, p.UniqueSessionId, transcript); err != nil {
			return nil, nil, errs.WrapIdentifiableAbort(err, "abort from schnorr dlog proof of aPrime_i0 (shamir id: %d)", senderShamirId)
		}

		partialPublicKeyShare := p.state.partialPublicKeyShares[senderShamirId]
		derivedPartialPublicKeyShare := p.CohortConfig.CipherSuite.Curve.Point.Identity()
		for k := 0; k < p.CohortConfig.Threshold; k++ {
			exp := p.CohortConfig.CipherSuite.Curve.Scalar.New(k)
			iToK := p.CohortConfig.CipherSuite.Curve.Scalar.New(p.MyShamirId).Exp(exp)
			C_lk := senderCommitmentVector[k]
			ikC_lk := C_lk.Mul(iToK)
			derivedPartialPublicKeyShare = derivedPartialPublicKeyShare.Add(ikC_lk)
		}
		if !partialPublicKeyShare.Equal(derivedPartialPublicKeyShare) {
			return nil, nil, errs.NewIdentifiableAbort("shares received from shamir id %d is inconsistent", senderShamirId)
		}

		publicKey = publicKey.Add(senderCommitmentToTheirLocalSecret)
		receivedCommitmentVectors[senderShamirId] = senderCommitmentVector
	}

	publicKeySharesMap, err := pedersenDkg.ConstructPublicKeySharesMap(p.CohortConfig, receivedCommitmentVectors, p.shamirIdToIdentityKey)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't derive public key shares")
	}
	myPresumedPublicKeyShare := publicKeySharesMap[p.MyIdentityKey]
	myPublicKeyShare := p.CohortConfig.CipherSuite.Curve.ScalarBaseMult(p.state.secretKeyShare)
	if !myPublicKeyShare.Equal(myPresumedPublicKeyShare) {
		return nil, nil, errs.NewFailed("did not calculate my public key share correctly")
	}

	publicKeyShares := &threshold.PublicKeyShares{
		Curve:     p.CohortConfig.CipherSuite.Curve,
		PublicKey: publicKey,
		SharesMap: publicKeySharesMap,
	}

	p.round++
	return &threshold.SigningKeyShare{
		Share:     p.state.secretKeyShare,
		PublicKey: publicKey,
	}, publicKeyShares, nil
}
