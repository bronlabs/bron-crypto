package gennaro

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/pedersen"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

const (
	sharingIdLabel = "sharing_id-"
)

type Round1Broadcast struct {
	BlindedCommitments []curves.Point

	_ ds.Incomparable
}

type Round1P2P struct {
	X_ij      curves.Scalar
	XPrime_ij curves.Scalar

	_ ds.Incomparable
}

type Round2Broadcast struct {
	Commitments      []curves.Point
	CommitmentsProof compiler.NIZKPoKProof

	_ ds.Incomparable
}

func (p *Participant) Round1() (*Round1Broadcast, types.RoundMessages[*Round1P2P], error) {
	if p.round != 1 {
		return nil, nil, errs.NewRound("round mismatch %d != 1", p.round)
	}
	// step 1.1: a_i0 <-$- Z_q
	a_i0, err := p.Protocol.Curve().ScalarField().Random(p.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "could not generate random scalar")
	}
	// step 1.2: (x_i, x-i, Ci, Bi) <- Pedersen.Split(a_i0)
	dealer, err := pedersen.NewDealer(p.Protocol.Threshold(), p.Protocol.TotalParties(), p.H)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't construct pedersen dealer")
	}
	dealt, err := dealer.Split(a_i0, p.prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't split")
	}
	// step 1.3: π_i <- NIZKPoK.Prove(s)  ∀s∈{a_i0, x_i1, x_i2, ..., x_in}
	proverTranscript := p.state.transcript.Clone()
	proverTranscript.AppendMessages(sharingIdLabel, bitstring.ToBytesLE(int(p.SharingId())))
	prover, err := p.state.niCompiler.NewProver(p.SessionId, proverTranscript)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not construct dlog prover")
	}
	commitmentsProof, err := prover.Prove(dealt.Commitments, dealt.PolynomialCoefficients)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not generate dlog proof")
	}

	// step 1.4: Send (x_ij, x'_ij) -> P_j
	outboundP2PMessages := types.NewRoundMessages[*Round1P2P]()
	for pair := range p.SharingConfig.Iter() {
		identityKey := pair.Value
		sharingId := pair.Key
		if sharingId == p.SharingId() {
			continue
		}
		shamirPolynomialIndex := sharingId - 1
		xij := dealt.SecretShares[shamirPolynomialIndex].Value
		xPrimeIJ := dealt.BlindingShares[shamirPolynomialIndex].Value
		outboundP2PMessages.Put(identityKey, &Round1P2P{
			X_ij:      xij,
			XPrime_ij: xPrimeIJ,
		})
		dealt.SecretShares[shamirPolynomialIndex] = nil
		dealt.BlindingShares[shamirPolynomialIndex] = nil
	}
	dealt.Blinding = nil

	p.state.myPartialSecretShare = dealt.SecretShares[p.SharingId()-1]
	p.state.commitments = dealt.Commitments
	p.state.commitmentsProof = commitmentsProof

	p.round++
	// step 1.5: Broadcast(Bi)
	return &Round1Broadcast{
		BlindedCommitments: dealt.BlindedCommitments,
	}, outboundP2PMessages, nil
}

func (p *Participant) Round2(round1outputBroadcast types.RoundMessages[*Round1Broadcast], round1outputP2P types.RoundMessages[*Round1P2P]) (*Round2Broadcast, error) {
	if p.round != 2 {
		return nil, errs.NewRound("round mismatch %d != 2", p.round)
	}
	secretKeyShare := p.state.myPartialSecretShare.Value

	receivedBlindedCommitmentVectors := map[types.SharingID][]curves.Point{
		p.SharingId(): p.state.commitments,
	}
	partialPublicKeyShares := map[types.SharingID]curves.Point{}

	for senderSharingIdUint := uint(1); senderSharingIdUint <= p.Protocol.TotalParties(); senderSharingIdUint++ {
		senderSharingId := types.SharingID(senderSharingIdUint)
		if senderSharingId == p.SharingId() {
			continue
		}
		senderIdentityKey, exists := p.SharingConfig.Get(senderSharingId)
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
			Id:    uint(p.SharingId()),
			Value: p2pMessageFromSender.X_ij,
		}
		receivedBlindingShare := &pedersen.Share{
			Id:    uint(p.SharingId()),
			Value: p2pMessageFromSender.XPrime_ij,
		}
		// step 2.1: Pedersen.Verify(x_j, x'_j, B_i)
		if err := pedersen.Verify(receivedShare, receivedBlindingShare, senderBlindedCommitmentVector, p.H); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, senderIdentityKey.String(), "abort from pedersen")
		}
		// step 2.2: x_i <- Σ x_ij
		secretKeyShare = secretKeyShare.Add(p2pMessageFromSender.X_ij)
		receivedBlindedCommitmentVectors[senderSharingId] = senderBlindedCommitmentVector
		partialPublicKeyShares[senderSharingId] = p.Protocol.Curve().ScalarBaseMult(p2pMessageFromSender.X_ij)
	}

	p.state.secretKeyShare = secretKeyShare
	p.state.partialPublicKeyShares = partialPublicKeyShares
	p.round++
	// step 2.3: Broadcast(C_i, π_i)
	return &Round2Broadcast{
		Commitments:      p.state.commitments,
		CommitmentsProof: p.state.commitmentsProof,
	}, nil
}

func (p *Participant) Round3(round2output types.RoundMessages[*Round2Broadcast]) (*tsignatures.SigningKeyShare, *tsignatures.PartialPublicKeys, error) {
	if p.round != 3 {
		return nil, nil, errs.NewRound("round mismatch %d != 3", p.round)
	}
	publicKey := p.state.commitments[0]
	receivedCommitmentVectors := map[types.SharingID][]curves.Point{
		p.SharingId(): p.state.commitments,
	}

	for senderSharingIdUint := uint(1); senderSharingIdUint <= p.Protocol.TotalParties(); senderSharingIdUint++ {
		senderSharingId := types.SharingID(senderSharingIdUint)
		if senderSharingId == p.SharingId() {
			continue
		}
		senderIdentityKey, exists := p.SharingConfig.Get(senderSharingId)
		if !exists {
			return nil, nil, errs.NewMissing("can't find identity key of sharing id %d", senderSharingId)
		}
		broadcastedMessageFromSender, exists := round2output.Get(senderIdentityKey)
		if !exists {
			return nil, nil, errs.NewMissing("do not have broadcasted message of the sender with sharing id %d", senderSharingId)
		}
		if broadcastedMessageFromSender.CommitmentsProof == nil {
			return nil, nil, errs.NewMissing("do not have the dlog proof of a_i0 for sharing id %d", senderSharingId)
		}
		senderCommitmentVector := broadcastedMessageFromSender.Commitments
		if senderCommitmentVector == nil {
			return nil, nil, errs.NewIsNil("sender commitment vector")
		}
		if len(senderCommitmentVector) != int(p.Protocol.Threshold()) {
			return nil, nil, errs.NewLength("len(senderCommitmentVector) == %d != t == %d", len(senderCommitmentVector), p.Protocol.Threshold())
		}
		senderCommitmentToTheirLocalSecret := senderCommitmentVector[0]
		// step 3.1: NIZKPoK.Verify(π_i)
		verifierTranscript := p.state.transcript.Clone()
		verifierTranscript.AppendMessages(sharingIdLabel, bitstring.ToBytesLE(int(senderSharingId)))
		verifier, err := p.state.niCompiler.NewVerifier(p.SessionId, verifierTranscript)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot create commitments verifier")
		}
		if err := verifier.Verify(senderCommitmentVector, broadcastedMessageFromSender.CommitmentsProof); err != nil {
			return nil, nil, errs.WrapIdentifiableAbort(err, senderIdentityKey.String(), "abort from dlog proof of a_i0")
		}
		// step 3.2: Feldman.Verify(C_i, B_i)
		partialPublicKeyShare := p.state.partialPublicKeyShares[senderSharingId]
		iToKs := make([]curves.Scalar, p.Protocol.Threshold())
		C_lks := make([]curves.Point, p.Protocol.Threshold())
		for k := uint(0); k < p.Protocol.Threshold(); k++ {
			exp := p.Protocol.Curve().ScalarField().New(uint64(k))
			iToK := p.Protocol.Curve().ScalarField().New(uint64(p.SharingId())).Exp(exp)
			C_lk := senderCommitmentVector[k]
			iToKs[k] = iToK
			C_lks[k] = C_lk
		}
		derivedPartialPublicKeyShare, err := p.Protocol.Curve().MultiScalarMult(iToKs, C_lks)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "couldn't derive partial public key share")
		}
		if !partialPublicKeyShare.Equal(derivedPartialPublicKeyShare) {
			return nil, nil, errs.NewIdentifiableAbort(senderIdentityKey.String(), "shares received from sharing id is inconsistent")
		}
		// step 3.3: Y <- Sum C_{j,0}
		publicKey = publicKey.Add(senderCommitmentToTheirLocalSecret)
		receivedCommitmentVectors[senderSharingId] = senderCommitmentVector
	}

	publicKeySharesMap, err := dkg.ConstructPublicKeySharesMap(p.Protocol, receivedCommitmentVectors, p.SharingConfig)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't derive public key shares")
	}
	myPresumedPublicKeyShare, exists := publicKeySharesMap.Get(p.IdentityKey())
	if !exists {
		return nil, nil, errs.NewMissing("couldn't find my own computed partial public key")
	}
	myPublicKeyShare := p.Protocol.Curve().ScalarBaseMult(p.state.secretKeyShare)
	if !myPublicKeyShare.Equal(myPresumedPublicKeyShare) {
		return nil, nil, errs.NewFailed("did not calculate my public key share correctly")
	}

	signingKeyShare := &tsignatures.SigningKeyShare{
		Share:     p.state.secretKeyShare,
		PublicKey: publicKey,
	}

	publicKeyShares := &tsignatures.PartialPublicKeys{
		PublicKey:               publicKey,
		Shares:                  publicKeySharesMap,
		FeldmanCommitmentVector: p.state.commitments,
	}

	p.round++
	return signingKeyShare, publicKeyShares, nil
}
