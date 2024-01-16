package pedersen

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	dlog "github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/fischlin"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/feldman"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

type Round1Broadcast struct {
	Ci        []curves.Point
	DlogProof *dlog.Proof

	_ types.Incomparable
}

type Round1P2P struct {
	Xij curves.Scalar

	_ types.Incomparable
}

const (
	DkgLabel       = "COPPER-PEDERSEN-DKG-V1-"
	SharingIdLabel = "Pedersen DKG sharing id parameter"
)

func (p *Participant) Round1(a_i0 curves.Scalar) (r1b *Round1Broadcast, r1u map[types.IdentityHash]*Round1P2P, err error) {
	if p.round != 1 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}

	if a_i0 == nil {
		a_i0, err = p.CohortConfig.CipherSuite.Curve.ScalarField().Random(p.prng)
		if err != nil {
			return nil, nil, errs.WrapRandomSampleFailed(err, "could not generate random scalar")
		}
	}

	dealer, err := feldman.NewDealer(p.CohortConfig.Protocol.Threshold, p.CohortConfig.Protocol.TotalParties, p.CohortConfig.CipherSuite.Curve)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't construct feldman dealer")
	}
	commitments, shares, err := dealer.Split(a_i0, p.prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't split the secret via feldman dealer")
	}
	p.State.ShareVector = shares
	p.State.Commitments = commitments

	transcript := hagrid.NewTranscript(DkgLabel, nil)
	transcript.AppendMessages(SharingIdLabel, bitstring.ToBytesLE(p.MySharingId))
	prover, err := dlog.NewProver(p.CohortConfig.CipherSuite.Curve.Generator(), p.UniqueSessionId, transcript.Clone(), p.prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't create DLOG prover")
	}
	var proof *dlog.Proof
	if !a_i0.IsZero() {
		proof, _, err = prover.Prove(a_i0)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "couldn't sign")
		}
	}

	outboundP2PMessages := map[types.IdentityHash]*Round1P2P{}

	for sharingId, identityKey := range p.SharingIdToIdentityKey {
		if sharingId != p.MySharingId {
			sharingIndex := sharingId - 1
			xij := shares[sharingIndex].Value
			outboundP2PMessages[identityKey.Hash()] = &Round1P2P{
				Xij: xij,
			}
		}
	}
	p.State.A_i0 = a_i0

	p.round++
	return &Round1Broadcast{
		Ci:        commitments,
		DlogProof: proof,
	}, outboundP2PMessages, nil
}

func (p *Participant) Round2(round1outputBroadcast map[types.IdentityHash]*Round1Broadcast, round1outputP2P map[types.IdentityHash]*Round1P2P) (*tsignatures.SigningKeyShare, *tsignatures.PublicKeyShares, error) {
	if p.round != 2 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}
	myShamirShare := p.State.ShareVector[p.MySharingId-1]
	if myShamirShare == nil {
		return nil, nil, errs.NewMissing("could not find my shamir share from the state")
	}
	secretKeyShare := myShamirShare.Value

	publicKey := p.State.Commitments[0]
	commitmentVectors := map[int][]curves.Point{
		p.MySharingId: p.State.Commitments,
	}

	for senderSharingId := 1; senderSharingId <= p.CohortConfig.Protocol.TotalParties; senderSharingId++ {
		if senderSharingId == p.MySharingId {
			continue
		}
		senderIdentityKey, exists := p.SharingIdToIdentityKey[senderSharingId]
		if !exists {
			return nil, nil, errs.NewMissing("can't find identity key of sharing id %d", senderSharingId)
		}
		broadcastedMessageFromSender, exists := round1outputBroadcast[senderIdentityKey.Hash()]
		if !exists {
			return nil, nil, errs.NewMissing("do not have broadcasted message of the sender with sharing id %d", senderSharingId)
		}

		senderCommitmentVector := broadcastedMessageFromSender.Ci
		senderCommitmentToTheirLocalSecret := senderCommitmentVector[0]

		if !p.State.A_i0.IsZero() {
			if broadcastedMessageFromSender.DlogProof == nil {
				return nil, nil, errs.NewMissing("have the dlog proof for sharing id %d", senderSharingId)
			}

			transcript := hagrid.NewTranscript(DkgLabel, nil)
			transcript.AppendMessages(SharingIdLabel, bitstring.ToBytesLE(senderSharingId))
			if err := dlog.Verify(p.CohortConfig.CipherSuite.Curve.Generator(), senderCommitmentToTheirLocalSecret, broadcastedMessageFromSender.DlogProof, p.UniqueSessionId); err != nil {
				return nil, nil, errs.NewIdentifiableAbort(senderSharingId, "abort from dlog proof given sharing id ")
			}
		} else if broadcastedMessageFromSender.DlogProof != nil {
			return nil, nil, errs.NewMissing("have the dlog proof for sharing id %d when a_i0 is zero", senderSharingId)
		}

		p2pMessageFromSender, exists := round1outputP2P[senderIdentityKey.Hash()]
		if !exists {
			return nil, nil, errs.NewMissing("did not get a p2p message from sender with sharing id %d", senderSharingId)
		}
		receivedSecretKeyShare := p2pMessageFromSender.Xij
		receivedShare := &feldman.Share{
			Id:    p.MySharingId,
			Value: receivedSecretKeyShare,
		}
		if err := feldman.Verify(receivedShare, broadcastedMessageFromSender.Ci); err != nil {
			return nil, nil, errs.WrapIdentifiableAbort(err, senderSharingId, "abort from feldman given sharing id")
		}

		partialPublicKeyShare := p.CohortConfig.CipherSuite.Curve.ScalarBaseMult(receivedSecretKeyShare)
		iToKs := make([]curves.Scalar, p.CohortConfig.Protocol.Threshold)
		C_lks := make([]curves.Point, p.CohortConfig.Protocol.Threshold)
		for k := 0; k < p.CohortConfig.Protocol.Threshold; k++ {
			exp := p.CohortConfig.CipherSuite.Curve.ScalarField().New(uint64(k))
			iToK := p.CohortConfig.CipherSuite.Curve.ScalarField().New(uint64(p.MySharingId)).Exp(exp)
			C_lk := senderCommitmentVector[k]
			iToKs[k] = iToK
			C_lks[k] = C_lk
		}
		derivedPartialPublicKeyShare, err := p.CohortConfig.CipherSuite.Curve.MultiScalarMult(iToKs, C_lks)
		if err != nil {
			return nil, nil, errs.NewFailed("couldn't derive partial public key share")
		}
		if !partialPublicKeyShare.Equal(derivedPartialPublicKeyShare) {
			return nil, nil, errs.NewFailed("shares received from sharing id %d is inconsistent", senderSharingId)
		}

		secretKeyShare = secretKeyShare.Add(p2pMessageFromSender.Xij)
		publicKey = publicKey.Add(senderCommitmentToTheirLocalSecret)
		commitmentVectors[senderSharingId] = senderCommitmentVector
	}

	publicKeySharesMap, err := dkg.ConstructPublicKeySharesMap(p.CohortConfig, commitmentVectors, p.SharingIdToIdentityKey)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't derive public key shares")
	}
	myPresumedPublicKeyShare := publicKeySharesMap[p.MyAuthKey.Hash()]
	myPublicKeyShare := p.CohortConfig.CipherSuite.Curve.ScalarBaseMult(secretKeyShare)
	if !myPublicKeyShare.Equal(myPresumedPublicKeyShare) {
		return nil, nil, errs.NewFailed("did not calculate my public key share correctly")
	}

	publicKeyShares := &tsignatures.PublicKeyShares{
		PublicKey:               publicKey,
		SharesMap:               publicKeySharesMap,
		FeldmanCommitmentVector: p.State.Commitments,
	}
	if err := publicKeyShares.Validate(p.CohortConfig); err != nil {
		return nil, nil, errs.WrapVerificationFailed(err, "couldn't verify public key shares")
	}

	p.round++
	return &tsignatures.SigningKeyShare{
		Share:     secretKeyShare,
		PublicKey: publicKey,
	}, publicKeyShares, nil
}
