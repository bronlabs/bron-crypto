package gennaro

import (
	"fmt"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashmap"
	pedersenDkg "github.com/copperexchange/knox-primitives/pkg/dkg/pedersen"
	dlog "github.com/copperexchange/knox-primitives/pkg/proofs/schnorr"
	"github.com/copperexchange/knox-primitives/pkg/sharing/pedersen"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/merlin"
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
	Commitments []curves.Point
	A_i0Proof   *dlog.Proof
}

func (p *Participant) Round1() (*Round1Broadcast, *hashmap.HashMap[integration.IdentityKey, *Round1P2P], error) {
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
	proverTranscript.AppendMessages("sharing id", []byte(fmt.Sprintf("%d", p.MySharingId)))
	prover, err := dlog.NewProver(p.CohortConfig.CipherSuite.Curve.Point.Generator(), p.UniqueSessionId, proverTranscript)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not construct dlog prover")
	}

	a_i0Proof, _, err := prover.Prove(a_i0)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not prove dlog proof of a_i0")
	}
	prover.BasePoint = p.H

	outboundP2PMessages := hashmap.NewHashMap[integration.IdentityKey, *Round1P2P]()
	for sharingId, identityKey := range p.sharingIdToIdentityKey {
		if sharingId == p.MySharingId {
			continue
		}
		sharingIndex := sharingId - 1
		xij := dealt.SecretShares[sharingIndex].Value
		xPrimeIJ := dealt.BlindingShares[sharingIndex].Value
		outboundP2PMessages.Put(identityKey, &Round1P2P{
			X_ij:      xij,
			XPrime_ij: xPrimeIJ,
		})
		dealt.SecretShares[sharingIndex] = nil
		dealt.BlindingShares[sharingIndex] = nil
	}
	dealt.Blinding = nil

	p.state.myPartialSecretShare = dealt.SecretShares[p.MySharingId-1]
	p.state.commitments = dealt.Commitments
	p.state.blindedCommitments = dealt.BlindedCommitments
	p.state.a_i0Proof = a_i0Proof

	p.round++
	return &Round1Broadcast{
		BlindedCommitments: dealt.BlindedCommitments,
	}, outboundP2PMessages, nil
}

func (p *Participant) Round2(round1outputBroadcast *hashmap.HashMap[integration.IdentityKey, *Round1Broadcast], round1outputP2P *hashmap.HashMap[integration.IdentityKey, *Round1P2P]) (*Round2Broadcast, error) {
	if p.round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}
	secretKeyShare := p.state.myPartialSecretShare.Value

	receivedBlindedCommitmentVectors := map[int][]curves.Point{
		p.MySharingId: p.state.commitments,
	}
	partialPublicKeyShares := map[int]curves.Point{}

	for senderSharingId := 1; senderSharingId <= p.CohortConfig.TotalParties; senderSharingId++ {
		if senderSharingId == p.MySharingId {
			continue
		}
		senderIdentityKey, exists := p.sharingIdToIdentityKey[senderSharingId]
		if !exists {
			return nil, errs.NewMissing("can't find identity key of sharing id %d", senderSharingId)
		}
		broadcastedMessageFromSender, exists := round1outputBroadcast.Get(senderIdentityKey)
		if !exists {
			return nil, errs.NewMissing("do not have broadcasted message of the sender with sharing id %d", senderSharingId)
		}
		senderBlindedCommitmentVector := broadcastedMessageFromSender.BlindedCommitments

		p2pMessageFromSender, exists := round1outputP2P.Get(senderIdentityKey)
		if !exists {
			return nil, errs.NewMissing("did not get a p2p message from sender with sharing id %d", senderSharingId)
		}
		receivedShare := &pedersen.Share{
			Id:    p.MySharingId,
			Value: p2pMessageFromSender.X_ij,
		}
		receivedBlindingShare := &pedersen.Share{
			Id:    p.MySharingId,
			Value: p2pMessageFromSender.XPrime_ij,
		}
		if err := pedersen.Verify(receivedShare, receivedBlindingShare, senderBlindedCommitmentVector, p.H); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, "abort from pedersen (sharing id: %d)", senderSharingId)
		}

		secretKeyShare = secretKeyShare.Add(p2pMessageFromSender.X_ij)
		round1outputP2P.Remove(senderIdentityKey)
		receivedBlindedCommitmentVectors[senderSharingId] = senderBlindedCommitmentVector
		partialPublicKeyShares[senderSharingId] = p.CohortConfig.CipherSuite.Curve.ScalarBaseMult(p2pMessageFromSender.X_ij)
	}

	p.state.secretKeyShare = secretKeyShare
	p.state.receivedBlindedCommitmentVectors = receivedBlindedCommitmentVectors
	p.state.partialPublicKeyShares = partialPublicKeyShares
	p.round++
	return &Round2Broadcast{
		Commitments: p.state.commitments,
		A_i0Proof:   p.state.a_i0Proof,
	}, nil
}

func (p *Participant) Round3(round2output *hashmap.HashMap[integration.IdentityKey, *Round2Broadcast]) (*threshold.SigningKeyShare, *threshold.PublicKeyShares, error) {
	if p.round != 3 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 3", p.round)
	}
	publicKey := p.state.commitments[0]
	receivedCommitmentVectors := map[int][]curves.Point{
		p.MySharingId: p.state.commitments,
	}

	for senderSharingId := 1; senderSharingId <= p.CohortConfig.TotalParties; senderSharingId++ {
		if senderSharingId == p.MySharingId {
			continue
		}
		senderIdentityKey, exists := p.sharingIdToIdentityKey[senderSharingId]
		if !exists {
			return nil, nil, errs.NewMissing("can't find identity key of sharing id %d", senderSharingId)
		}
		broadcastedMessageFromSender, exists := round2output.Get(senderIdentityKey)
		if !exists {
			return nil, nil, errs.NewMissing("do not have broadcasted message of the sender with sharing id %d", senderSharingId)
		}
		if broadcastedMessageFromSender.A_i0Proof == nil {
			return nil, nil, errs.NewMissing("do not have the dlog proof of a_i0 for sharing id %d", senderSharingId)
		}
		senderCommitmentVector := broadcastedMessageFromSender.Commitments
		senderCommitmentToTheirLocalSecret := senderCommitmentVector[0]

		if p.CohortConfig.CipherSuite.Curve.Name == curves.ED25519Name {
			edwardsPoint, ok := senderCommitmentToTheirLocalSecret.(*curves.PointEd25519)
			if !ok {
				return nil, nil, errs.NewIdentifiableAbort("curve is ed25519 but the sender with sharingId %d did not have a valid commitment to her local secret.", senderSharingId)
			}
			// Since the honest behaviour is to create a scalar out of the ristretto group, it is guaranteed to be in the prime subgroup.
			// A malicious party - or a party engaging in DKG with another client software - may send this element such that it needs cofactor clearing.
			// Such an element has a 1/8 chance of bypassing the dlog proof therefore successfully injecting a small group element into
			// the resulting public key. More info: https://medium.com/zengo/baby-sharks-a3b9ceb4efe0
			if edwardsPoint.Double().Double().Double().Sub(edwardsPoint).IsIdentity() {
				return nil, nil, errs.NewIdentifiableAbort("sharing id %d tries to contribute a small group element to the public key", senderSharingId)
			}
		}

		transcript := merlin.NewTranscript(DlogProofLabel)
		transcript.AppendMessages("sharing id", []byte(fmt.Sprintf("%d", senderSharingId)))
		if err := dlog.Verify(p.CohortConfig.CipherSuite.Curve.Point.Generator(), senderCommitmentToTheirLocalSecret, broadcastedMessageFromSender.A_i0Proof, p.UniqueSessionId, transcript); err != nil {
			return nil, nil, errs.WrapIdentifiableAbort(err, "abort from schnorr dlog proof of a_i0 (sharing id: %d)", senderSharingId)
		}

		partialPublicKeyShare := p.state.partialPublicKeyShares[senderSharingId]
		iToKs := make([]curves.Scalar, p.CohortConfig.Threshold)
		C_lks := make([]curves.Point, p.CohortConfig.Threshold)
		for k := 0; k < p.CohortConfig.Threshold; k++ {
			exp := p.CohortConfig.CipherSuite.Curve.Scalar.New(k)
			iToK := p.CohortConfig.CipherSuite.Curve.Scalar.New(p.MySharingId).Exp(exp)
			C_lk := senderCommitmentVector[k]
			iToKs[k] = iToK
			C_lks[k] = C_lk
		}
		derivedPartialPublicKeyShare, err := p.CohortConfig.CipherSuite.Curve.MultiScalarMult(iToKs, C_lks)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "couldn't derive partial public key share")
		}
		if !partialPublicKeyShare.Equal(derivedPartialPublicKeyShare) {
			return nil, nil, errs.NewIdentifiableAbort("shares received from sharing id %d is inconsistent", senderSharingId)
		}

		publicKey = publicKey.Add(senderCommitmentToTheirLocalSecret)
		receivedCommitmentVectors[senderSharingId] = senderCommitmentVector
	}

	publicKeySharesMap, err := pedersenDkg.ConstructPublicKeySharesMap(p.CohortConfig, receivedCommitmentVectors, p.sharingIdToIdentityKey)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't derive public key shares")
	}
	myPresumedPublicKeyShare, exists := publicKeySharesMap.Get(p.MyIdentityKey)
	if !exists {
		return nil, nil, errs.NewMissing("couldn't find my public key share")
	}
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
