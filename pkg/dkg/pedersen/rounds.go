package pedersen

import (
	"fmt"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/feldman"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold"
	dlog "github.com/copperexchange/crypto-primitives-go/pkg/zkp/schnorr"
	"github.com/gtank/merlin"
)

type Round1Broadcast struct {
	Ci        []curves.Point
	DlogProof *dlog.Proof
}

type Round1P2P struct {
	Xij curves.Scalar
}

const DkgLabel = "COPPER-PEDERSEN-DKG-V1-"
const ShamirIdLabel = "Pedersen DKG shamir id parameter"

func (p *Participant) Round1() (*Round1Broadcast, map[integration.IdentityKey]*Round1P2P, error) {
	if p.round != 1 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}

	a_i0 := p.CohortConfig.CipherSuite.Curve.Scalar.Random(p.prng)

	dealer, err := feldman.NewDealer(p.CohortConfig.Threshold, p.CohortConfig.TotalParties, p.CohortConfig.CipherSuite.Curve)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't construct feldman dealer")
	}
	commitments, shares, err := dealer.Split(a_i0, p.prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't split the secret via feldman dealer")
	}
	p.state.shareVector = shares
	p.state.commitments = commitments

	transcript := merlin.NewTranscript(DkgLabel)
	transcript.AppendMessage([]byte(ShamirIdLabel), []byte(fmt.Sprintf("%d", p.MyShamirId)))
	prover, err := dlog.NewProver(p.CohortConfig.CipherSuite.Curve.Point.Generator(), p.UniqueSessionId, transcript)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't create DLOG prover")
	}
	proof, err := prover.Prove(a_i0)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't sign")
	}

	outboundP2PMessages := map[integration.IdentityKey]*Round1P2P{}

	for shamirId, identityKey := range p.shamirIdToIdentityKey {
		if shamirId != p.MyShamirId {
			shamirIndex := shamirId - 1
			xij := shares[shamirIndex].Value
			outboundP2PMessages[identityKey] = &Round1P2P{
				Xij: xij,
			}
			shares[shamirIndex] = nil
		}
	}
	a_i0 = nil

	p.round++

	return &Round1Broadcast{
		Ci:        commitments,
		DlogProof: proof,
	}, outboundP2PMessages, nil
}

func (p *Participant) Round2(round1outputBroadcast map[integration.IdentityKey]*Round1Broadcast, round1outputP2P map[integration.IdentityKey]*Round1P2P) (*threshold.SigningKeyShare, *threshold.PublicKeyShares, error) {
	if p.round != 2 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}
	myShamirShare := p.state.shareVector[p.MyShamirId-1]
	if myShamirShare == nil {
		return nil, nil, errs.NewMissing("could not find my shamir share from the state")
	}
	secretKeyShare := myShamirShare.Value

	publicKey := p.state.commitments[0]
	commitmentVectors := map[int][]curves.Point{
		p.MyShamirId: p.state.commitments,
	}

	for senderShamirId := 1; senderShamirId <= p.CohortConfig.TotalParties; senderShamirId++ {
		if senderShamirId != p.MyShamirId {
			senderIdentityKey, exists := p.shamirIdToIdentityKey[senderShamirId]
			if !exists {
				return nil, nil, errs.NewMissing("can't find identity key of shamir id %d", senderShamirId)
			}
			broadcastedMessageFromSender, exists := round1outputBroadcast[senderIdentityKey]
			if !exists {
				return nil, nil, errs.NewMissing("do not have broadcasted message of the sender with shamir id %d", senderShamirId)
			}
			senderCommitmentVector := broadcastedMessageFromSender.Ci
			senderCommitmentToTheirLocalSecret := senderCommitmentVector[0]

			if p.CohortConfig.CipherSuite.Curve.Name == curves.ED25519Name {
				edwardsPoint, ok := publicKey.(*curves.PointEd25519)
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

			transcript := merlin.NewTranscript(DkgLabel)
			transcript.AppendMessage([]byte(ShamirIdLabel), []byte(fmt.Sprintf("%d", senderShamirId)))
			if err := dlog.Verify(p.CohortConfig.CipherSuite.Curve.Point.Generator(), broadcastedMessageFromSender.DlogProof, p.UniqueSessionId, transcript); err != nil {
				return nil, nil, errs.NewIdentifiableAbort("abort from schnorr (shamir id: %d)", senderShamirId)
			}

			p2pMessageFromSender, exists := round1outputP2P[senderIdentityKey]
			if !exists {
				return nil, nil, errs.NewMissing("did not get a p2p message from sender with shamir id %d", senderShamirId)
			}
			receivedSecretKeyShare := p2pMessageFromSender.Xij
			receivedShare := &feldman.Share{
				Id:    p.MyShamirId,
				Value: receivedSecretKeyShare,
			}
			if err := feldman.Verify(receivedShare, broadcastedMessageFromSender.Ci); err != nil {
				return nil, nil, errs.NewIdentifiableAbort("abort from feldman (shamir id: %d)", senderShamirId)
			}

			partialPublicKeyShare := p.CohortConfig.CipherSuite.Curve.ScalarBaseMult(receivedSecretKeyShare)
			derivedPartialPublicKeyShare := p.CohortConfig.CipherSuite.Curve.Point.Identity()
			for k := 0; k < p.CohortConfig.Threshold; k++ {
				exp := p.CohortConfig.CipherSuite.Curve.Scalar.New(k)
				iToK := p.CohortConfig.CipherSuite.Curve.Scalar.New(p.MyShamirId).Exp(exp)
				C_lk := senderCommitmentVector[k]
				ikC_lk := C_lk.Mul(iToK)
				derivedPartialPublicKeyShare = derivedPartialPublicKeyShare.Add(ikC_lk)
			}
			if !partialPublicKeyShare.Equal(derivedPartialPublicKeyShare) {
				return nil, nil, errs.NewFailed("shares received from shamir id %d is inconsistent", senderShamirId)
			}

			secretKeyShare = secretKeyShare.Add(p2pMessageFromSender.Xij)
			publicKey = publicKey.Add(senderCommitmentToTheirLocalSecret)
			commitmentVectors[senderShamirId] = senderCommitmentVector

			round1outputP2P[senderIdentityKey] = nil
		}
	}

	publicKeySharesMap, err := ConstructPublicKeySharesMap(p.CohortConfig, commitmentVectors, p.shamirIdToIdentityKey)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't derive public key shares")
	}
	myPresumedPublicKeyShare := publicKeySharesMap[p.MyIdentityKey]
	myPublicKeyShare := p.CohortConfig.CipherSuite.Curve.ScalarBaseMult(secretKeyShare)
	if !myPublicKeyShare.Equal(myPresumedPublicKeyShare) {
		return nil, nil, errs.NewFailed("did not calculate my public key share correctly")
	}

	publicKeyShares := &threshold.PublicKeyShares{
		Curve:     p.CohortConfig.CipherSuite.Curve,
		PublicKey: publicKey,
		SharesMap: publicKeySharesMap,
	}
	// TODO: Fix this.
	// if err := publicKeyShares.Validate(); err != nil {
	// 	return nil, nil, errors.Wrap(err, "couldn't verify public key shares")
	// }

	p.round++
	return &threshold.SigningKeyShare{
		Share:     secretKeyShare,
		PublicKey: publicKey,
	}, publicKeyShares, nil
}

func ConstructPublicKeySharesMap(cohort *integration.CohortConfig, commitmentVectors map[int][]curves.Point, shamirIdToIdentityKey map[int]integration.IdentityKey) (map[integration.IdentityKey]curves.Point, error) {
	shares := map[integration.IdentityKey]curves.Point{}
	for j, identityKey := range shamirIdToIdentityKey {
		Y_j := cohort.CipherSuite.Curve.Point.Identity()
		for _, C_l := range commitmentVectors {
			for k := 0; k < cohort.Threshold; k++ {
				exp := cohort.CipherSuite.Curve.Scalar.New(k)
				jToK := cohort.CipherSuite.Curve.Scalar.New(j).Exp(exp)
				jkC_lk := C_l[k].Mul(jToK)
				Y_j = Y_j.Add(jkC_lk)
			}
		}
		if Y_j.IsIdentity() {
			return nil, errs.NewIsIdentity("public key share of shamir id %d is at infinity", j)
		}
		shares[identityKey] = Y_j
	}
	return shares, nil
}
