package dkg

import (
	"io"
	"slices"

	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	hashcommitments "github.com/bronlabs/krypton-primitives/pkg/commitments/hash"
	"github.com/bronlabs/krypton-primitives/pkg/indcpa/paillier"
	"github.com/bronlabs/krypton-primitives/pkg/network"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/dlog"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/paillier/lp"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/paillier/lpdl"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts"
)

func (p *Participant) Round1() (output *Round1Broadcast, err error) {
	// Validation
	if p.Round != 1 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 1, p.Round)
	}

	// 1.i. choose randomly x' and x'' such that x = 3x' + x'' and both x' and x'' are in (q/3, 2q/3) range
	xPrime, xDoublePrime, err := lindell17.DecomposeInQThirdsDeterministically(p.mySigningKeyShare.Share, p.Prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot split share")
	}

	// 1.ii. calculate Q' and Q''
	bigQPrime := p.Protocol.Curve().ScalarBaseMult(xPrime)
	bigQDoublePrime := p.Protocol.Curve().ScalarBaseMult(xDoublePrime)

	// 1.iii. calculates commitments Qcom to Q' and Q''
	bigQCommitment, bigQOpening, err := commit(p.SessionId, p.Prng, bigQPrime, bigQDoublePrime, p.myAuthKey.PublicKey())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to (Q', Q'')")
	}

	p.state.myXPrime = xPrime
	p.state.myXDoublePrime = xDoublePrime
	p.state.myBigQPrime = bigQPrime
	p.state.myBigQDoublePrime = bigQDoublePrime
	p.state.myBigQOpening = bigQOpening

	// some paranoid checks
	myPartialPublicKey, exists := p.publicKeyShares.IdentityBasedMapping(p.Protocol.Participants()).Get(p.IdentityKey())
	if !exists {
		return nil, errs.NewMissing("could not find my partial public key")
	}
	if !bigQPrime.Add(bigQPrime).Add(bigQPrime).Add(bigQDoublePrime).Equal(myPartialPublicKey) {
		return nil, errs.NewFailed("something went really wrong")
	}

	// 1.iv. broadcast commitments
	p.Round++
	return &Round1Broadcast{
		BigQCommitment: bigQCommitment,
	}, nil
}

func (p *Participant) Round2(input network.RoundMessages[types.ThresholdProtocol, *Round1Broadcast]) (output *Round2Broadcast, err error) {
	// Validation
	if p.Round != 2 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 2, p.Round)
	}
	if err := network.ValidateMessages(p.Protocol, p.Protocol.Participants(), p.IdentityKey(), input); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 2 input broadcast messages")
	}

	// 2. store commitments
	p.state.theirBigQCommitment = make(map[types.SharingID]hashcommitments.Commitment)
	for identity := range p.Protocol.Participants().Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		sharingId, exists := p.sharingConfig.Reverse().Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find sender sharing id %s", identity.String())
		}
		message, exists := input.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no input from participant with sharing id %d", sharingId)
		}
		p.state.theirBigQCommitment[sharingId] = message.BigQCommitment
	}

	// 2.i. calculate proofs of dlog knowledge of Q' and Q'' (Qdl' and Qdl'' respectively)
	dlogTranscript := p.Transcript.Clone()
	bigQPrimeProof, err := dlogProve(p.state.myXPrime, p.state.myBigQPrime, p.state.myBigQDoublePrime, p.SessionId, p.nic, dlogTranscript, p.Prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog proof of Q'")
	}
	bigQDoublePrimeProof, err := dlogProve(p.state.myXDoublePrime, p.state.myBigQDoublePrime, p.state.myBigQPrime, p.SessionId, p.nic, dlogTranscript, p.Prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog proof of Q''")
	}

	// 2.ii. send opening of Qcom revealing Q', Q'' and broadcast proofs of dlog knowledge of these (Qdl', Qdl'' respectively)
	p.Round++
	return &Round2Broadcast{
		BigQOpening:          p.state.myBigQOpening,
		BigQPrime:            p.state.myBigQPrime,
		BigQPrimeProof:       bigQPrimeProof,
		BigQDoublePrime:      p.state.myBigQDoublePrime,
		BigQDoublePrimeProof: bigQDoublePrimeProof,
	}, nil
}

func (p *Participant) Round3(input network.RoundMessages[types.ThresholdProtocol, *Round2Broadcast]) (output *Round3Broadcast, err error) {
	// Validation
	if p.Round != 3 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 3, p.Round)
	}
	if err := network.ValidateMessages(p.Protocol, p.Protocol.Participants(), p.IdentityKey(), input); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 3 input broadcast messages")
	}

	p.state.theirBigQPrime = make(map[types.SharingID]curves.Point)
	p.state.theirBigQDoublePrime = make(map[types.SharingID]curves.Point)

	// 3.i. verify proofs of dlog knowledge of Qdl'_j Qdl''_j
	for identity := range p.Protocol.Participants().Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		sharingId, exists := p.sharingConfig.Reverse().Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find sender sharing id %s", identity.String())
		}
		message, exists := input.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no input from participant with sharing id %d", sharingId)
		}

		// 3.i. open commitments
		if err := openCommitment(p.SessionId, p.state.theirBigQCommitment[sharingId], message.BigQOpening, message.BigQPrime, message.BigQDoublePrime, identity.PublicKey()); err != nil {
			return nil, errs.WrapFailed(err, "cannot open (Q', Q'') commitment")
		}

		dlogTranscript := p.Transcript.Clone()
		if err := dlogVerify(message.BigQPrimeProof, message.BigQPrime, message.BigQDoublePrime, p.SessionId, p.nic, dlogTranscript); err != nil {
			return nil, errs.WrapFailed(err, "cannot verify dlog proof of Q'")
		}
		if err := dlogVerify(message.BigQDoublePrimeProof, message.BigQDoublePrime, message.BigQPrime, p.SessionId, p.nic, dlogTranscript); err != nil {
			return nil, errs.WrapFailed(err, "cannot verify dlog proof of Q''")
		}
		p.state.theirBigQPrime[sharingId] = message.BigQPrime
		p.state.theirBigQDoublePrime[sharingId] = message.BigQDoublePrime

		// 3.ii. verify that y_j == 3Q'_j + Q''_j and abort if not
		theirBigQ := p.state.theirBigQPrime[sharingId].ScalarMul(p.Protocol.Curve().ScalarField().New(3)).Add(message.BigQDoublePrime)
		partialPublicKey, exists := p.publicKeyShares.IdentityBasedMapping(p.Protocol.Participants()).Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find participant partial publickey (sharing id=%d)", sharingId)
		}
		if !theirBigQ.Equal(partialPublicKey) {
			return nil, errs.NewIdentifiableAbort(identity.String(), "invalid Q' or Q''")
		}
	}

	// 3.iii. generate a Paillier key pair
	p.state.myPaillierPk, p.state.myPaillierSk, err = paillier.KeyGen(lp.PaillierBitSize, p.Prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate Paillier keys")
	}
	cKeyPrime, rPrime, err := p.state.myPaillierPk.Encrypt(p.state.myXPrime.Nat(), p.Prng)

	// 3.iv. calculate ckey' = Enc(x'; r') and ckey'' = Enc(x''; r'')
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt x'")
	}
	cKeyDoublePrime, rDoublePrime, err := p.state.myPaillierPk.Encrypt(p.state.myXDoublePrime.Nat(), p.Prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt x''")
	}
	p.state.myRPrime = rPrime
	p.state.myRDoublePrime = rDoublePrime

	// 3.vi. prove pairwise iz ZK that pk was generated correctly (LP)
	//       and that (ckey', ckey'') encrypt dlogs of (Q', Q'') (LPDL)
	p.state.lpProvers = make(map[types.SharingID]*lp.Prover)
	p.state.lpdlPrimeProvers = make(map[types.SharingID]*lpdl.Prover)
	p.state.lpdlDoublePrimeProvers = make(map[types.SharingID]*lpdl.Prover)
	for identity := range p.Protocol.Participants().Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		paillierProofsTranscript := p.Transcript.Clone()
		sharingId, exists := p.sharingConfig.Reverse().Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find sharing id for participant %x", identity)
		}
		p.state.lpProvers[sharingId], err = lp.NewProver(base.ComputationalSecurity, p.state.myPaillierSk, p.SessionId, paillierProofsTranscript, p.Prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create LP prover")
		}
		p.state.lpdlPrimeProvers[sharingId], err = lpdl.NewProver(p.state.myPaillierSk, p.state.myXPrime, p.state.myRPrime, p.SessionId, paillierProofsTranscript, p.Prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL prover")
		}
		p.state.lpdlDoublePrimeProvers[sharingId], err = lpdl.NewProver(p.state.myPaillierSk, p.state.myXDoublePrime, p.state.myRDoublePrime, p.SessionId, paillierProofsTranscript, p.Prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL prover")
		}
	}

	// 3.v. broadcast (pk, ckey', ckey'')
	p.Round++
	return &Round3Broadcast{
		CKeyPrime:         cKeyPrime,
		CKeyDoublePrime:   cKeyDoublePrime,
		PaillierPublicKey: p.state.myPaillierPk,
	}, nil
}

func (p *Participant) Round4(input network.RoundMessages[types.ThresholdProtocol, *Round3Broadcast]) (output network.RoundMessages[types.ThresholdProtocol, *Round4P2P], err error) {
	// Validation
	if p.Round != 4 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 4, p.Round)
	}
	if err := network.ValidateMessages(p.Protocol, p.Protocol.Participants(), p.IdentityKey(), input); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 4 input broadcast messages")
	}

	p.state.theirPaillierPublicKeys = hashmap.NewHashableHashMap[types.IdentityKey, *paillier.PublicKey]()
	p.state.theirPaillierEncryptedShares = hashmap.NewHashableHashMap[types.IdentityKey, *paillier.CipherText]()
	p.state.lpVerifiers = make(map[types.SharingID]*lp.Verifier)
	p.state.lpdlPrimeVerifiers = make(map[types.SharingID]*lpdl.Verifier)
	p.state.lpdlDoublePrimeVerifiers = make(map[types.SharingID]*lpdl.Verifier)

	round4Outputs := network.NewRoundMessages[types.ThresholdProtocol, *Round4P2P]()
	for identity := range p.Protocol.Participants().Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		sharingId, exists := p.sharingConfig.Reverse().Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find sender sharing id %s", identity.String())
		}
		message, exists := input.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no input from participant with sharing id %d", sharingId)
		}
		theirPaillierPublicKey := message.PaillierPublicKey
		p.state.theirPaillierPublicKeys.Put(identity, theirPaillierPublicKey)
		theirCKeyPrime := message.CKeyPrime
		theirCKeyDoublePrime := message.CKeyDoublePrime

		// 4.i. calculate and store ckey_j = 3 (*) ckey'_j (+) ckey''_j
		cKey1, err := theirPaillierPublicKey.CipherTextAdd(theirCKeyPrime, theirCKeyPrime)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}
		cKey2, err := theirPaillierPublicKey.CipherTextAdd(cKey1, theirCKeyPrime)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}
		theirEncryptedShare, err := theirPaillierPublicKey.CipherTextAdd(cKey2, theirCKeyDoublePrime)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}
		p.state.theirPaillierEncryptedShares.Put(identity, theirEncryptedShare)

		// 4.ii. LP and LPDL continue
		paillierProofsTranscript := p.Transcript.Clone()
		p.state.lpVerifiers[sharingId], err = lp.NewVerifier(base.ComputationalSecurity, theirPaillierPublicKey, p.SessionId, paillierProofsTranscript, p.Prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create P verifier")
		}
		p.state.lpdlPrimeVerifiers[sharingId], err = lpdl.NewVerifier(theirPaillierPublicKey, p.state.theirBigQPrime[sharingId], theirCKeyPrime, p.SessionId, paillierProofsTranscript, p.Prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL verifier")
		}
		p.state.lpdlDoublePrimeVerifiers[sharingId], err = lpdl.NewVerifier(theirPaillierPublicKey, p.state.theirBigQDoublePrime[sharingId], theirCKeyDoublePrime, p.SessionId, paillierProofsTranscript, p.Prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL verifier")
		}

		outgoingMessage := new(Round4P2P)
		outgoingMessage.LpRound1Output, err = p.state.lpVerifiers[sharingId].Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 1 of LP verifier")
		}
		outgoingMessage.LpdlPrimeRound1Output, err = p.state.lpdlPrimeVerifiers[sharingId].Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 1 of LPDL verifier")
		}
		outgoingMessage.LpdlDoublePrimeRound1Output, err = p.state.lpdlDoublePrimeVerifiers[sharingId].Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 1 of LPDLP verifier")
		}
		round4Outputs.Put(identity, outgoingMessage)
	}

	p.Round++
	return round4Outputs, nil
}

func (p *Participant) Round5(input network.RoundMessages[types.ThresholdProtocol, *Round4P2P]) (output network.RoundMessages[types.ThresholdProtocol, *Round5P2P], err error) {
	// Validation
	if p.Round != 5 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 5, p.Round)
	}
	if err := network.ValidateMessages(p.Protocol, p.Protocol.Participants(), p.IdentityKey(), input); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 5 input P2P messages")
	}

	// 5. LP and LPDL continue
	round5Outputs := network.NewRoundMessages[types.ThresholdProtocol, *Round5P2P]()
	for identity := range p.Protocol.Participants().Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		sharingId, exists := p.sharingConfig.Reverse().Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find sender sharing id %s", identity.String())
		}
		message, exists := input.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no input from participant with sharing id %d", sharingId)
		}

		outgoingMessage := new(Round5P2P)
		outgoingMessage.LpRound2Output, err = p.state.lpProvers[sharingId].Round2(message.LpRound1Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
		outgoingMessage.LpdlPrimeRound2Output, err = p.state.lpdlPrimeProvers[sharingId].Round2(message.LpdlPrimeRound1Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LPDL prover")
		}
		outgoingMessage.LpdlDoublePrimeRound2Output, err = p.state.lpdlDoublePrimeProvers[sharingId].Round2(message.LpdlDoublePrimeRound1Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LPDL prover")
		}
		round5Outputs.Put(identity, outgoingMessage)
	}

	p.Round++
	return round5Outputs, nil
}

func (p *Participant) Round6(input network.RoundMessages[types.ThresholdProtocol, *Round5P2P]) (output network.RoundMessages[types.ThresholdProtocol, *Round6P2P], err error) {
	// Validation
	if p.Round != 6 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 6, p.Round)
	}
	if err := network.ValidateMessages(p.Protocol, p.Protocol.Participants(), p.IdentityKey(), input); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 6 input P2P messages")
	}

	// 6. LP and LPDL continue
	round6Outputs := network.NewRoundMessages[types.ThresholdProtocol, *Round6P2P]()
	for identity := range p.Protocol.Participants().Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		sharingId, exists := p.sharingConfig.Reverse().Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find sender sharing id %s", identity.String())
		}
		message, exists := input.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no input from participant with sharing id %d", sharingId)
		}

		outgoingMessage := new(Round6P2P)
		outgoingMessage.LpRound3Output, err = p.state.lpVerifiers[sharingId].Round3(message.LpRound2Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 3 of LP verifier")
		}
		outgoingMessage.LpdlPrimeRound3Output, err = p.state.lpdlPrimeVerifiers[sharingId].Round3(message.LpdlPrimeRound2Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 3 of LP verifier")
		}
		outgoingMessage.LpdlDoublePrimeRound3Output, err = p.state.lpdlDoublePrimeVerifiers[sharingId].Round3(message.LpdlDoublePrimeRound2Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 3 of LP verifier")
		}
		round6Outputs.Put(identity, outgoingMessage)
	}

	p.Round++
	return round6Outputs, nil
}

func (p *Participant) Round7(
	inputP2P network.RoundMessages[types.ThresholdProtocol, *Round6P2P],
) (output network.RoundMessages[types.ThresholdProtocol, *Round7P2P], err error) {
	// Validation
	if p.Round != 7 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 7, p.Round)
	}
	if err := network.ValidateMessages(p.Protocol, p.Protocol.Participants(), p.IdentityKey(), inputP2P); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 7 input P2P messages")
	}

	// 7. LP and LPDL continue
	round7Outputs := network.NewRoundMessages[types.ThresholdProtocol, *Round7P2P]()
	for identity := range p.Protocol.Participants().Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		sharingId, exists := p.sharingConfig.Reverse().Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find sender sharing id %s", identity.String())
		}
		message, exists := inputP2P.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no input from participant with sharing id %d", sharingId)
		}

		outgoingMessage := new(Round7P2P)
		outgoingMessage.LpRound4Output, err = p.state.lpProvers[sharingId].Round4(message.LpRound3Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
		outgoingMessage.LpdlPrimeRound4Output, err = p.state.lpdlPrimeProvers[sharingId].Round4(message.LpdlPrimeRound3Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
		outgoingMessage.LpdlDoublePrimeRound4Output, err = p.state.lpdlDoublePrimeProvers[sharingId].Round4(message.LpdlDoublePrimeRound3Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
		round7Outputs.Put(identity, outgoingMessage)
	}

	p.Round++
	return round7Outputs, nil
}

func (p *Participant) Round8(input network.RoundMessages[types.ThresholdProtocol, *Round7P2P]) (shard *lindell17.Shard, err error) {
	// Validation
	if p.Round != 8 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 8, p.Round)
	}
	if err := network.ValidateMessages(p.Protocol, p.Protocol.Participants(), p.IdentityKey(), input); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 6 input P2P messages")
	}

	for identity := range p.Protocol.Participants().Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		sharingId, exists := p.sharingConfig.Reverse().Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find sender sharing id %s", identity.String())
		}
		message, exists := input.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no input from participant with sharing id %d", sharingId)
		}

		if err := p.state.lpVerifiers[sharingId].Round5(message.LpRound4Output); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, identity.String(), "failed to verify valid Paillier public-key")
		}
		if err := p.state.lpdlPrimeVerifiers[sharingId].Round5(message.LpdlPrimeRound4Output); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, identity.String(), "failed to verify encrypted dlog")
		}
		if err := p.state.lpdlDoublePrimeVerifiers[sharingId].Round5(message.LpdlDoublePrimeRound4Output); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, identity.String(), "failed to verify encrypted dlog")
		}
	}

	p.Round++
	// 8. store encrypted x_j aka ckey_j (ckey_j = Enc(x_j) = Enc(3x'_j + x''_j)) and pk_j alongside share
	return &lindell17.Shard{
		SigningKeyShare:         p.mySigningKeyShare,
		PublicKeyShares:         p.publicKeyShares,
		PaillierSecretKey:       p.state.myPaillierSk,
		PaillierPublicKeys:      lindell17.PaillierPublicKeysAsSharingIDMappedToPublicKeys(p.Protocol, p.state.theirPaillierPublicKeys),
		PaillierEncryptedShares: lindell17.PaillierEncryptedSharesAsSharingIDMappedToCiphertexts(p.Protocol, p.state.theirPaillierEncryptedShares),
	}, nil
}

func commit(sessionId []byte, prng io.Reader, bigQPrime, bigQDoublePrime curves.Point, pid curves.Point) (vectorCommitment hashcommitments.Commitment, witness hashcommitments.Witness, err error) {
	committer, err := hashcommitments.NewCommittingKeyFromCrsBytes(sessionId, pid.ToAffineCompressed())
	if err != nil {
		return *new(hashcommitments.Commitment), *new(hashcommitments.Witness), errs.WrapFailed(err, "cannot instantiate committer")
	}
	return committer.Commit(slices.Concat(bigQPrime.ToAffineCompressed(), bigQDoublePrime.ToAffineCompressed()), prng)
}

func openCommitment(sessionId []byte, commitment hashcommitments.Commitment, witness hashcommitments.Witness, bigQPrime, bigQDoublePrime curves.Point, pid curves.Point) (err error) {
	verifier, err := hashcommitments.NewCommittingKeyFromCrsBytes(sessionId, pid.ToAffineCompressed())
	if err != nil {
		return errs.WrapFailed(err, "cannot instantiate committer")
	}

	return verifier.Verify(commitment, slices.Concat(bigQPrime.ToAffineCompressed(), bigQDoublePrime.ToAffineCompressed()), witness)
}

func dlogProve(x curves.Scalar, bigQ, bigQTwin curves.Point, sessionId []byte, nic compiler.Name, transcript transcripts.Transcript, prng io.Reader) (proof compiler.NIZKPoKProof, err error) {
	// TODO: check this.
	transcript.AppendPoints("bigQTwin", bigQTwin)

	basePoint := bigQ.Curve().Generator()
	proof, statement, err := dlog.Prove(sessionId, x, basePoint, nic, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot prove dlog")
	}
	if !statement.Equal(bigQ) {
		return nil, errs.NewValue("invalid statement")
	}
	return proof, nil
}

func dlogVerify(proof compiler.NIZKPoKProof, bigQ, bigQTwin curves.Point, sessionId []byte, nic compiler.Name, transcript transcripts.Transcript) (err error) {
	transcript.AppendPoints("bigQTwin", bigQTwin)
	basePoint := bigQ.Curve().Generator()
	if err := dlog.Verify(sessionId, proof, bigQ, basePoint, nic, transcript); err != nil {
		return errs.WrapVerification(err, "dlog proof can't be verified")
	}
	return nil
}
