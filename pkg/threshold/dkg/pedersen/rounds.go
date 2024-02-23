package pedersen

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/feldman"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

type Round1Broadcast struct {
	Ci        []curves.Point
	DlogProof compiler.NIZKPoKProof

	_ ds.Incomparable
}

type Round1P2P struct {
	Xij curves.Scalar

	_ ds.Incomparable
}

const (
	DkgLabel       = "COPPER_KRYPTON_PEDERSEN_DKG-"
	SharingIdLabel = "Pedersen_DKG_sharing_label-"
)

func (p *Participant) Round1(a_i0 curves.Scalar) (r1b *Round1Broadcast, r1u types.RoundMessages[*Round1P2P], err error) {
	if p.round != 1 {
		return nil, nil, errs.NewRound("round mismatch %d != 1", p.round)
	}
	// step 1.1: a_i0 <-$- Z_q
	if a_i0 == nil {
		a_i0, err = p.Protocol.Curve().ScalarField().Random(p.prng)
		if err != nil {
			return nil, nil, errs.WrapRandomSample(err, "could not generate random scalar")
		}
	}

	dealer, err := feldman.NewDealer(p.Protocol.Threshold(), p.Protocol.TotalParties(), p.Protocol.Curve())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't construct feldman dealer")
	}
	transcript := hagrid.NewTranscript(DkgLabel, nil)
	transcript.AppendMessages(SharingIdLabel, bitstring.ToBytesLE(int(p.SharingId())))
	prover, err := p.State.NiCompiler.NewProver(p.SessionId, p.Transcript.Clone())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create commitment prover")
	}

	// step 1.2: (x_i, Ci) <- Feldman.Split(a_i0)
	// step 1.3: π_i <- NIZKPoK.Prove(s)  ∀s∈{a_i0, x_i1, x_i2, ..., x_in}
	commitments, shares, proof, err := dealer.Split(a_i0, prover, p.prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't split the secret via feldman dealer")
	}
	p.State.ShareVector = shares
	p.State.Commitments = commitments

	outboundP2PMessages := types.NewRoundMessages[*Round1P2P]()

	// step 1.4: send (x_ij) to P_j
	for pair := range p.SharingConfig.Iter() {
		sharingId := pair.Left
		identityKey := pair.Right
		if sharingId != p.SharingId() {
			shamirPolynomialIndex := sharingId - 1
			xij := shares[shamirPolynomialIndex].Value
			outboundP2PMessages.Put(identityKey, &Round1P2P{
				Xij: xij,
			})
		}
	}
	p.State.A_i0 = a_i0

	p.round++
	// step 1.5: Broadcast(Ci)
	return &Round1Broadcast{
		Ci:        commitments,
		DlogProof: proof,
	}, outboundP2PMessages, nil
}

func (p *Participant) Round2(round1outputBroadcast types.RoundMessages[*Round1Broadcast], round1outputP2P types.RoundMessages[*Round1P2P]) (*tsignatures.SigningKeyShare, *tsignatures.PartialPublicKeys, error) {
	if p.round != 2 {
		return nil, nil, errs.NewRound("round mismatch %d != 2", p.round)
	}
	myShamirShare := p.State.ShareVector[p.SharingId()-1]
	if myShamirShare == nil {
		return nil, nil, errs.NewMissing("could not find my shamir share from the state")
	}
	secretKeyShare := myShamirShare.Value

	publicKey := p.State.Commitments[0]
	commitmentVectors := map[types.SharingID][]curves.Point{
		p.SharingId(): p.State.Commitments,
	}

	for senderSharingIdUint := uint(1); senderSharingIdUint <= p.Protocol.TotalParties(); senderSharingIdUint++ {
		senderSharingId := types.SharingID(senderSharingIdUint)
		if senderSharingId == p.SharingId() {
			continue
		}
		senderIdentityKey, exists := p.SharingConfig.LookUpLeft(senderSharingId)
		if !exists {
			return nil, nil, errs.NewMissing("can't find identity key of sharing id %d", senderSharingId)
		}
		broadcastedMessageFromSender, exists := round1outputBroadcast.Get(senderIdentityKey)
		if !exists {
			return nil, nil, errs.NewMissing("do not have broadcasted message of the sender with sharing id %d", senderSharingId)
		}

		senderCommitmentVector := broadcastedMessageFromSender.Ci
		senderCommitmentToTheirLocalSecret := senderCommitmentVector[0]

		p2pMessageFromSender, exists := round1outputP2P.Get(senderIdentityKey)
		if !exists {
			return nil, nil, errs.NewMissing("did not get a p2p message from sender with sharing id %d", senderSharingId)
		}
		receivedSecretKeyShare := p2pMessageFromSender.Xij
		receivedShare := &feldman.Share{
			Id:    uint(p.SharingId()),
			Value: receivedSecretKeyShare,
		}
		// step 2.1: Feldman.Verify(Ci)
		// step 2.2: π_i <- NIZKPoK.Prove(s)  ∀s∈{Ci, x_ji}
		transcript := hagrid.NewTranscript(DkgLabel, nil)
		transcript.AppendMessages(SharingIdLabel, bitstring.ToBytesLE(int(senderSharingId)))
		verifier, err := p.State.NiCompiler.NewVerifier(p.SessionId, p.Transcript.Clone())
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot create commitment verifier")
		}
		if err := feldman.Verify(receivedShare, broadcastedMessageFromSender.Ci, verifier, broadcastedMessageFromSender.DlogProof); err != nil {
			return nil, nil, errs.WrapIdentifiableAbort(err, senderSharingId, "abort from feldman given sharing id")
		}

		partialPublicKeyShare := p.Protocol.Curve().ScalarBaseMult(receivedSecretKeyShare)
		iToKs := make([]curves.Scalar, p.Protocol.Threshold())
		C_lks := make([]curves.Point, p.Protocol.Threshold())
		for k := 0; k < int(p.Protocol.Threshold()); k++ {
			exp := p.Protocol.Curve().ScalarField().New(uint64(k))
			iToK := p.Protocol.Curve().ScalarField().New(uint64(p.SharingId())).Exp(exp)
			C_lk := senderCommitmentVector[k]
			iToKs[k] = iToK
			C_lks[k] = C_lk
		}
		derivedPartialPublicKeyShare, err := p.Protocol.Curve().MultiScalarMult(iToKs, C_lks)
		if err != nil {
			return nil, nil, errs.NewFailed("couldn't derive partial public key share")
		}
		if !partialPublicKeyShare.Equal(derivedPartialPublicKeyShare) {
			return nil, nil, errs.NewFailed("shares received from sharing id %d is inconsistent", senderSharingId)
		}
		// step 2.3: x_i <- Σ x_ij
		secretKeyShare = secretKeyShare.Add(p2pMessageFromSender.Xij)
		// step 2.4: Y <- Sum C_{j,0}
		publicKey = publicKey.Add(senderCommitmentToTheirLocalSecret)
		commitmentVectors[senderSharingId] = senderCommitmentVector
	}

	publicKeySharesMap, err := dkg.ConstructPublicKeySharesMap(p.Protocol, commitmentVectors, p.SharingConfig)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't derive public key shares")
	}
	myPresumedPublicKeyShare, exists := publicKeySharesMap.Get(p.IdentityKey())
	if !exists {
		return nil, nil, errs.NewMissing("couldn't find my own computed partial public key")
	}
	myPublicKeyShare := p.Protocol.Curve().ScalarBaseMult(secretKeyShare)
	if !myPublicKeyShare.Equal(myPresumedPublicKeyShare) {
		return nil, nil, errs.NewFailed("did not calculate my public key share correctly")
	}

	publicKeyShares := &tsignatures.PartialPublicKeys{
		PublicKey:               publicKey,
		Shares:                  publicKeySharesMap,
		FeldmanCommitmentVector: p.State.Commitments,
	}
	if err := publicKeyShares.Validate(p.Protocol); err != nil {
		return nil, nil, errs.WrapValidation(err, "couldn't verify public key shares")
	}

	p.round++
	return &tsignatures.SigningKeyShare{
		Share:     secretKeyShare,
		PublicKey: publicKey,
	}, publicKeyShares, nil
}
