package dkg

import (
	"fmt"
	"sort"

	"github.com/copperexchange/crypto-primitives-go/internal"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/schnorr"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"

	"github.com/pkg/errors"
)

type Round1Broadcast struct {
	Ri curves.Scalar
}

type Round2Broadcast struct {
	Ci     []curves.Point
	SigmaI *schnorr.Signature
}

type Round2P2P struct {
	Xij curves.Scalar
}

func (p *DKGParticipant) Round1() (*Round1Broadcast, error) {
	if p.round != 1 {
		return nil, errors.New("round mismatch")
	}
	r_i := p.CohortConfig.Curve.Scalar.Random(p.reader)
	p.state.r_i = r_i
	p.round++
	return &Round1Broadcast{
		Ri: r_i,
	}, nil
}

func (p *DKGParticipant) Round2(round1output map[integration.IdentityKey]*Round1Broadcast) (*Round2Broadcast, map[integration.IdentityKey]*Round2P2P, error) {
	if p.round != 2 {
		return nil, nil, errors.New("round mismatch")
	}
	round1output[p.MyIdentityKey] = &Round1Broadcast{
		Ri: p.state.r_i,
	}

	rVector, err := deriveSortedRVector(round1output)
	if err != nil {
		return nil, nil, errors.Wrap(err, "couldn't derive r vector")
	}
	rVectorBytes := make([][]byte, len(rVector))
	for i, r_i := range rVector {
		rVectorBytes[i] = r_i.Bytes()
	}
	phi, err := internal.Hash([]byte("FROST DKG phi parameter"), rVectorBytes...)
	if err != nil {
		return nil, nil, errors.Wrap(err, "couldn't compute phi paramter")
	}
	p.state.phi = phi

	a_i0 := p.CohortConfig.Curve.Scalar.Random(p.reader)
	dealer, err := sharing.NewFeldman(uint32(p.CohortConfig.Threshold), uint32(p.CohortConfig.TotalParties), p.CohortConfig.Curve)
	if err != nil {
		return nil, nil, errors.Wrap(err, "couldn't construct feldman dealer")
	}
	commitmentVector, shares, err := dealer.Split(a_i0, p.reader)
	if err != nil {
		return nil, nil, errors.Wrap(err, "couldn't split the secret via feldman dealer")
	}
	p.state.shareVector = shares
	p.state.commitmentVector = commitmentVector

	ai0AsSchnorrPrivateKey := schnorr.Keygen(p.CohortConfig.Curve, a_i0, p.reader)
	sigma_i, err := ai0AsSchnorrPrivateKey.Sign(p.reader, []byte(fmt.Sprintf("%d", p.MyShamirId)), [][]byte{phi})
	if err != nil {
		return nil, nil, errors.Wrap(err, "couldn't sign")
	}

	outboundP2PMessages := map[integration.IdentityKey]*Round2P2P{}

	for shamirId, identityKey := range p.shamirIdToIdentityKey {
		if shamirId != p.MyShamirId {
			shamirIndex := shamirId - 1
			xij, err := p.CohortConfig.Curve.Scalar.SetBytes(shares[shamirIndex].Value)
			if err != nil {
				return nil, nil, errors.Wrap(err, "couldn't convert shamir share to scalar")
			}
			outboundP2PMessages[identityKey] = &Round2P2P{
				Xij: xij,
			}
			shares[shamirIndex] = nil
		}
	}
	a_i0 = nil

	p.round++

	return &Round2Broadcast{
		Ci:     commitmentVector.Commitments,
		SigmaI: sigma_i,
	}, outboundP2PMessages, nil
}

func (p *DKGParticipant) Round3(round2outputBroadcast map[integration.IdentityKey]*Round2Broadcast, round2outputP2P map[integration.IdentityKey]*Round2P2P) (*frost.SigningKeyShare, *frost.PublicKeyShares, error) {
	if p.round != 3 {
		return nil, nil, errors.New("round mismatch")
	}
	myShamirShare := p.state.shareVector[p.MyShamirId-1]
	if myShamirShare == nil {
		return nil, nil, errors.New("could not find my shamir share from the state")
	}
	secretKeyShare, err := p.CohortConfig.Curve.Scalar.SetBytes(myShamirShare.Value)
	if err != nil {
		return nil, nil, errors.New("could not convert my shamir share to scalar")
	}

	publicKey := p.state.commitmentVector.Commitments[0]
	commitmentVectors := map[int][]curves.Point{
		p.MyShamirId: p.state.commitmentVector.Commitments,
	}

	for senderShamirId := 1; senderShamirId <= p.CohortConfig.TotalParties; senderShamirId++ {
		if senderShamirId != p.MyShamirId {
			senderIdentityKey, exists := p.shamirIdToIdentityKey[senderShamirId]
			if !exists {
				return nil, nil, errors.Errorf("can't find identity key of shamir id %d", senderShamirId)
			}
			broadcastedMessageFromSender, exists := round2outputBroadcast[senderIdentityKey]
			if !exists {
				return nil, nil, errors.Errorf("do not have broadcasted message of the sender with shamir id %d", senderShamirId)
			}
			senderCommitmentVector := broadcastedMessageFromSender.Ci
			senderCommitmentToTheirLocalSecret := senderCommitmentVector[0]
			senderCommitmentToTheirLocalSecretAsSchnorrPublicKey := &schnorr.PublicKey{
				Curve: p.CohortConfig.Curve,
				Y:     senderCommitmentToTheirLocalSecret,
			}
			if err := schnorr.Verify(senderCommitmentToTheirLocalSecretAsSchnorrPublicKey, []byte(fmt.Sprintf("%d", senderShamirId)), broadcastedMessageFromSender.SigmaI, [][]byte{p.state.phi}); err != nil {
				return nil, nil, errors.New("Abort from schnorr")
			}
			feldmanVerifier := &sharing.FeldmanVerifier{
				Commitments: broadcastedMessageFromSender.Ci,
			}
			p2pMessageFromSender, exists := round2outputP2P[senderIdentityKey]
			if !exists {
				return nil, nil, errors.Errorf("did not get a p2p message from sender with shamir id %d", senderShamirId)
			}
			receivedSecretKeyShare := p2pMessageFromSender.Xij
			receivedShare := &sharing.ShamirShare{
				Id:    uint32(p.MyShamirId),
				Value: receivedSecretKeyShare.Bytes(),
			}
			if err := feldmanVerifier.Verify(receivedShare); err != nil {
				return nil, nil, errors.New("Abort from feldman")
			}

			partialPublicKeyShare := p.CohortConfig.Curve.ScalarBaseMult(receivedSecretKeyShare)
			derivedPartialPublicKeyShare := p.CohortConfig.Curve.Point.Identity()
			for k := 0; k < p.CohortConfig.Threshold; k++ {
				iToK := p.CohortConfig.Curve.Scalar.One()
				// perform exponentiation
				for iteration := 0; iteration < k; iteration++ {
					iToK = iToK.Mul(p.CohortConfig.Curve.Scalar.New(p.MyShamirId))
				}
				C_lk := senderCommitmentVector[k]
				ikC_lk := C_lk.Mul(iToK)
				derivedPartialPublicKeyShare = derivedPartialPublicKeyShare.Add(ikC_lk)
			}
			if !partialPublicKeyShare.Equal(derivedPartialPublicKeyShare) {
				return nil, nil, errors.Errorf("shares received from shamir id %d is inconsistent", senderShamirId)
			}

			secretKeyShare = secretKeyShare.Add(p2pMessageFromSender.Xij)
			publicKey = publicKey.Add(senderCommitmentToTheirLocalSecret)
			commitmentVectors[senderShamirId] = senderCommitmentVector

			round2outputP2P[senderIdentityKey] = nil
		}
	}

	publicKeySharesMap, err := constructPublicKeySharesMap(p.CohortConfig, commitmentVectors, p.shamirIdToIdentityKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "couldn't derive public key shares")
	}
	myPresumedPublicKeyShare := publicKeySharesMap[p.MyIdentityKey]
	myPublicKeyShare := p.CohortConfig.Curve.ScalarBaseMult(secretKeyShare)
	if !myPublicKeyShare.Equal(myPresumedPublicKeyShare) {
		return nil, nil, errors.New("did not calculate my public key share correctly")
	}

	publicKeyShares := &frost.PublicKeyShares{
		Curve:     p.CohortConfig.Curve,
		PublicKey: publicKey,
		SharesMap: publicKeySharesMap,
	}
	// if err := publicKeyShares.Validate(); err != nil {
	// 	return nil, nil, errors.Wrap(err, "couldn't verify public key shares")
	// }

	p.round++
	return &frost.SigningKeyShare{
		Share:     secretKeyShare,
		PublicKey: publicKey,
	}, publicKeyShares, nil
}

func constructPublicKeySharesMap(cohort *integration.CohortConfig, commitmentVectors map[int][]curves.Point, shamirIdToIdentityKey map[int]integration.IdentityKey) (map[integration.IdentityKey]curves.Point, error) {
	shares := map[integration.IdentityKey]curves.Point{}
	for j, identityKey := range shamirIdToIdentityKey {
		Y_j := cohort.Curve.Point.Identity()
		for _, C_l := range commitmentVectors {
			for k := 0; k < cohort.Threshold; k++ {

				jToK := cohort.Curve.Scalar.One()
				// perform exponentiation
				for iteration := 0; iteration < k; iteration++ {
					jToK = jToK.Mul(cohort.Curve.Scalar.New(j))
				}

				jkC_lk := C_l[k].Mul(jToK)
				Y_j = Y_j.Add(jkC_lk)
			}
		}
		if Y_j.IsIdentity() {
			return nil, errors.Errorf("public key share of shamir id %d is at infinity", j)
		}
		shares[identityKey] = Y_j
	}
	return shares, nil
}

func deriveSortedRVector(allIdentityKeysToRi map[integration.IdentityKey]*Round1Broadcast) ([]curves.Scalar, error) {
	serializedIdentityKeys := make([]string, len(allIdentityKeysToRi))
	serializedIdentityKeyToIdentityKey := map[string]integration.IdentityKey{}
	i := 0
	for identityKey := range allIdentityKeysToRi {
		serializedIdentityKey, err := integration.SerializePublicKey(identityKey.PublicKey())
		if err != nil {
			return nil, errors.Wrap(err, "could not serialize identity key of sender")
		}
		serializedIdentityKeys[i] = serializedIdentityKey
		serializedIdentityKeyToIdentityKey[serializedIdentityKey] = identityKey
		i++
	}
	sort.Strings(serializedIdentityKeys)

	sortedRVector := make([]curves.Scalar, len(allIdentityKeysToRi))
	for i, serializedIdentityKey := range serializedIdentityKeys {
		identityKey, exists := serializedIdentityKeyToIdentityKey[serializedIdentityKey]
		if !exists {
			return nil, errors.New("identity key can't be found")
		}
		message, exists := allIdentityKeysToRi[identityKey]
		if !exists {
			return nil, errors.New("message coun't be found")
		}
		sortedRVector[i] = message.Ri
	}

	return sortedRVector, nil

}
