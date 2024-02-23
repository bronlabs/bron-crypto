package dkg

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/lp"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/lpdl"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

type Round1Broadcast struct {
	BigQCommitment commitments.Commitment

	_ ds.Incomparable
}

type Round2Broadcast struct {
	BigQWitness          commitments.Witness
	BigQPrime            curves.Point
	BigQPrimeProof       compiler.NIZKPoKProof
	BigQDoublePrime      curves.Point
	BigQDoublePrimeProof compiler.NIZKPoKProof

	_ ds.Incomparable
}

type Round3Broadcast struct {
	CKeyPrime         *paillier.CipherText
	CKeyDoublePrime   *paillier.CipherText
	PaillierPublicKey *paillier.PublicKey

	_ ds.Incomparable
}

type Round4P2P struct {
	LpRound1Output              *lp.Round1Output
	LpdlPrimeRound1Output       *lpdl.Round1Output
	LpdlDoublePrimeRound1Output *lpdl.Round1Output

	_ ds.Incomparable
}

type Round5P2P struct {
	LpRound2Output              *lp.Round2Output
	LpdlPrimeRound2Output       *lpdl.Round2Output
	LpdlDoublePrimeRound2Output *lpdl.Round2Output

	_ ds.Incomparable
}

type Round6P2P struct {
	LpRound3Output              *lp.Round3Output
	LpdlPrimeRound3Output       *lpdl.Round3Output
	LpdlDoublePrimeRound3Output *lpdl.Round3Output

	_ ds.Incomparable
}

type Round7P2P struct {
	LpRound4Output              *lp.Round4Output
	LpdlPrimeRound4Output       *lpdl.Round4Output
	LpdlDoublePrimeRound4Output *lpdl.Round4Output

	_ ds.Incomparable
}

func (p *Participant) Round1() (output *Round1Broadcast, err error) {
	if p.round != 1 {
		return nil, errs.NewRound("%d != 1", p.round)
	}

	// 1.i. choose randomly x' and x'' such that x = 3x' + x'' and both x' and x'' are in (q/3, 2q/3) range
	xPrime, xDoublePrime, err := lindell17.DecomposeInQThirdsDeterministically(p.mySigningKeyShare.Share, p.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot split share")
	}

	// 1.ii. calculate Q' and Q''
	bigQPrime := p.protocol.Curve().ScalarBaseMult(xPrime)
	bigQDoublePrime := p.protocol.Curve().ScalarBaseMult(xDoublePrime)

	// 1.iii. calculates commitments Qcom to Q' and Q''
	bigQCommitment, bigQWitness, err := commit(p.prng, bigQPrime, bigQDoublePrime, p.sessionId, p.myAuthKey.PublicKey())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to (Q', Q'')")
	}

	p.state.myXPrime = xPrime
	p.state.myXDoublePrime = xDoublePrime
	p.state.myBigQPrime = bigQPrime
	p.state.myBigQDoublePrime = bigQDoublePrime
	p.state.myBigQWitness = bigQWitness

	// some paranoid checks
	myPartialPublicKey, exists := p.publicKeyShares.Shares.Get(p.IdentityKey())
	if !exists {
		return nil, errs.NewMissing("could not find my partial public key")
	}
	if !bigQPrime.Add(bigQPrime).Add(bigQPrime).Add(bigQDoublePrime).Equal(myPartialPublicKey) {
		return nil, errs.NewFailed("something went really wrong")
	}

	// 1.iv. broadcast commitments
	p.round++
	return &Round1Broadcast{
		BigQCommitment: bigQCommitment,
	}, nil
}

func (p *Participant) Round2(input types.RoundMessages[*Round1Broadcast]) (output *Round2Broadcast, err error) {
	if p.round != 2 {
		return nil, errs.NewRound("%d != 2", p.round)
	}

	// 2. store commitments
	p.state.theirBigQCommitment = make(map[types.SharingID]commitments.Commitment)
	for identity := range p.protocol.Participants().Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		sharingId, exists := p.sharingConfig.Reverse().Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find sender sharing id %x", identity.PublicKey())
		}
		message, exists := input.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no input from participant with sharing id %d", sharingId)
		}
		p.state.theirBigQCommitment[sharingId] = message.BigQCommitment
	}

	// 2.i. calculate proofs of dlog knowledge of Q' and Q'' (Qdl' and Qdl'' respectively)
	dlogTranscript := p.transcript.Clone()
	bigQPrimeProof, err := dlogProve(p.state.myXPrime, p.state.myBigQPrime, p.state.myBigQDoublePrime, p.sessionId, p.nic, dlogTranscript, p.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog proof of Q'")
	}
	bigQDoublePrimeProof, err := dlogProve(p.state.myXDoublePrime, p.state.myBigQDoublePrime, p.state.myBigQPrime, p.sessionId, p.nic, dlogTranscript, p.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog proof of Q''")
	}

	// 2.ii. send opening of Qcom revealing Q', Q'' and broadcast proofs of dlog knowledge of these (Qdl', Qdl'' respectively)
	p.round++
	return &Round2Broadcast{
		BigQWitness:          p.state.myBigQWitness,
		BigQPrime:            p.state.myBigQPrime,
		BigQPrimeProof:       bigQPrimeProof,
		BigQDoublePrime:      p.state.myBigQDoublePrime,
		BigQDoublePrimeProof: bigQDoublePrimeProof,
	}, nil
}

func (p *Participant) Round3(input types.RoundMessages[*Round2Broadcast]) (output *Round3Broadcast, err error) {
	if p.round != 3 {
		return nil, errs.NewRound("%d != 3", p.round)
	}

	p.state.theirBigQPrime = make(map[types.SharingID]curves.Point)
	p.state.theirBigQDoublePrime = make(map[types.SharingID]curves.Point)

	// 3.i. verify proofs of dlog knowledge of Qdl'_j Qdl''_j
	for identity := range p.protocol.Participants().Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		sharingId, exists := p.sharingConfig.Reverse().Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find sender sharing id %x", identity.PublicKey())
		}
		message, exists := input.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no input from participant with sharing id %d", sharingId)
		}

		// 3.i. open commitments
		if err := openCommitment(p.state.theirBigQCommitment[sharingId], message.BigQWitness, message.BigQPrime, message.BigQDoublePrime, p.sessionId, identity.PublicKey()); err != nil {
			return nil, errs.WrapFailed(err, "cannot open (Q', Q'') commitment")
		}

		dlogTranscript := p.transcript.Clone()
		if err := dlogVerify(message.BigQPrimeProof, message.BigQPrime, message.BigQDoublePrime, p.sessionId, p.nic, dlogTranscript); err != nil {
			return nil, errs.WrapFailed(err, "cannot verify dlog proof of Q'")
		}
		if err := dlogVerify(message.BigQDoublePrimeProof, message.BigQDoublePrime, message.BigQPrime, p.sessionId, p.nic, dlogTranscript); err != nil {
			return nil, errs.WrapFailed(err, "cannot verify dlog proof of Q''")
		}
		p.state.theirBigQPrime[sharingId] = message.BigQPrime
		p.state.theirBigQDoublePrime[sharingId] = message.BigQDoublePrime

		// 3.ii. verify that y_j == 3Q'_j + Q''_j and abort if not
		theirBigQ := p.state.theirBigQPrime[sharingId].Mul(p.protocol.Curve().ScalarField().New(3)).Add(message.BigQDoublePrime)
		partialPublicKey, exists := p.publicKeyShares.Shares.Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find participant partial publickey (sharing id=%d)", sharingId)
		}
		if !theirBigQ.Equal(partialPublicKey) {
			return nil, errs.NewIdentifiableAbort(identity.PublicKey().ToAffineCompressed(), "invalid Q' or Q''")
		}
	}

	// 3.iii. generate a Paillier key pair
	p.state.myPaillierPk, p.state.myPaillierSk, err = paillier.NewKeys(lp.PaillierBitSize)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate Paillier keys")
	}
	cKeyPrime, rPrime, err := p.state.myPaillierPk.Encrypt(p.state.myXPrime.Nat())

	// 3.iv. calculate ckey' = Enc(x'; r') and ckey'' = Enc(x''; r'')
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt x'")
	}
	cKeyDoublePrime, rDoublePrime, err := p.state.myPaillierPk.Encrypt(p.state.myXDoublePrime.Nat())
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
	for identity := range p.protocol.Participants().Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		paillierProofsTranscript := p.transcript.Clone()
		sharingId, exists := p.sharingConfig.Reverse().Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find sharign id for participant %x", identity)
		}
		p.state.lpProvers[sharingId], err = lp.NewProver(base.ComputationalSecurity, p.state.myPaillierSk, p.sessionId, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create LP prover")
		}
		p.state.lpdlPrimeProvers[sharingId], err = lpdl.NewProver(p.state.myPaillierSk, p.state.myXPrime, p.state.myRPrime, p.sessionId, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL prover")
		}
		p.state.lpdlDoublePrimeProvers[sharingId], err = lpdl.NewProver(p.state.myPaillierSk, p.state.myXDoublePrime, p.state.myRDoublePrime, p.sessionId, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL prover")
		}
	}

	// 3.v. broadcast (pk, ckey', ckey'')
	p.round++
	return &Round3Broadcast{
		CKeyPrime:         cKeyPrime,
		CKeyDoublePrime:   cKeyDoublePrime,
		PaillierPublicKey: p.state.myPaillierPk,
	}, nil
}

func (p *Participant) Round4(input types.RoundMessages[*Round3Broadcast]) (output types.RoundMessages[*Round4P2P], err error) {
	if p.round != 4 {
		return nil, errs.NewRound("%d != 4", p.round)
	}

	p.state.theirPaillierPublicKeys = hashmap.NewHashableHashMap[types.IdentityKey, *paillier.PublicKey]()
	p.state.theirPaillierEncryptedShares = hashmap.NewHashableHashMap[types.IdentityKey, *paillier.CipherText]()
	p.state.lpVerifiers = make(map[types.SharingID]*lp.Verifier)
	p.state.lpdlPrimeVerifiers = make(map[types.SharingID]*lpdl.Verifier)
	p.state.lpdlDoublePrimeVerifiers = make(map[types.SharingID]*lpdl.Verifier)

	round4Outputs := types.NewRoundMessages[*Round4P2P]()
	for identity := range p.protocol.Participants().Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		sharingId, exists := p.sharingConfig.Reverse().Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find sender sharing id %x", identity.PublicKey())
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
		cKey1, err := theirPaillierPublicKey.Add(theirCKeyPrime, theirCKeyPrime)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}
		cKey2, err := theirPaillierPublicKey.Add(cKey1, theirCKeyPrime)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}
		theirEncryptedShare, err := theirPaillierPublicKey.Add(cKey2, theirCKeyDoublePrime)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}
		p.state.theirPaillierEncryptedShares.Put(identity, theirEncryptedShare)

		// 4.ii. LP and LPDL continue
		paillierProofsTranscript := p.transcript.Clone()
		p.state.lpVerifiers[sharingId], err = lp.NewVerifier(base.ComputationalSecurity, theirPaillierPublicKey, p.sessionId, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create P verifier")
		}
		p.state.lpdlPrimeVerifiers[sharingId], err = lpdl.NewVerifier(theirPaillierPublicKey, p.state.theirBigQPrime[sharingId], theirCKeyPrime, p.sessionId, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL verifier")
		}
		p.state.lpdlDoublePrimeVerifiers[sharingId], err = lpdl.NewVerifier(theirPaillierPublicKey, p.state.theirBigQDoublePrime[sharingId], theirCKeyDoublePrime, p.sessionId, paillierProofsTranscript, p.prng)
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

	p.round++
	return round4Outputs, nil
}

func (p *Participant) Round5(input types.RoundMessages[*Round4P2P]) (output types.RoundMessages[*Round5P2P], err error) {
	if p.round != 5 {
		return nil, errs.NewRound("%d != 5", p.round)
	}

	// 5. LP and LPDL continue
	round5Outputs := types.NewRoundMessages[*Round5P2P]()
	for identity := range p.protocol.Participants().Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		sharingId, exists := p.sharingConfig.Reverse().Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find sender sharing id %x", identity.PublicKey())
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

	p.round++
	return round5Outputs, nil
}

func (p *Participant) Round6(input types.RoundMessages[*Round5P2P]) (output types.RoundMessages[*Round6P2P], err error) {
	if p.round != 6 {
		return nil, errs.NewRound("%d != 6", p.round)
	}

	// 6. LP and LPDL continue
	round6Outputs := types.NewRoundMessages[*Round6P2P]()
	for identity := range p.protocol.Participants().Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		sharingId, exists := p.sharingConfig.Reverse().Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find sender sharing id %x", identity.PublicKey())
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

	p.round++
	return round6Outputs, nil
}

func (p *Participant) Round7(input types.RoundMessages[*Round6P2P]) (output types.RoundMessages[*Round7P2P], err error) {
	if p.round != 7 {
		return nil, errs.NewRound("%d != 7", p.round)
	}

	// 7. LP and LPDL continue
	round7Outputs := types.NewRoundMessages[*Round7P2P]()
	for identity := range p.protocol.Participants().Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		sharingId, exists := p.sharingConfig.Reverse().Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find sender sharing id %x", identity.PublicKey())
		}
		message, exists := input.Get(identity)
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

	p.round++
	return round7Outputs, nil
}

func (p *Participant) Round8(input types.RoundMessages[*Round7P2P]) (shard *lindell17.Shard, err error) {
	if p.round != 8 {
		return nil, errs.NewRound("%d != 8", p.round)
	}

	for identity := range p.protocol.Participants().Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		sharingId, exists := p.sharingConfig.Reverse().Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find sender sharing id %x", identity.PublicKey())
		}
		message, exists := input.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no input from participant with sharing id %d", sharingId)
		}

		if err := p.state.lpVerifiers[sharingId].Round5(message.LpRound4Output); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, sharingId, "failed to verify valid Paillier public-key")
		}
		if err := p.state.lpdlPrimeVerifiers[sharingId].Round5(message.LpdlPrimeRound4Output); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, sharingId, "failed to verify encrypted dlog")
		}
		if err := p.state.lpdlDoublePrimeVerifiers[sharingId].Round5(message.LpdlDoublePrimeRound4Output); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, sharingId, "failed to verify encrypted dlog")
		}
	}

	p.round++
	// 8. store encrypted x_j aka ckey_j (ckey_j = Enc(x_j) = Enc(3x'_j + x''_j)) and pk_j alongside share
	return &lindell17.Shard{
		SigningKeyShare:         p.mySigningKeyShare,
		PublicKeyShares:         p.publicKeyShares,
		PaillierSecretKey:       p.state.myPaillierSk,
		PaillierPublicKeys:      p.state.theirPaillierPublicKeys,
		PaillierEncryptedShares: p.state.theirPaillierEncryptedShares,
	}, nil
}

func commit(prng io.Reader, bigQPrime, bigQDoublePrime curves.Point, sessionId []byte, pid curves.Point) (commitment commitments.Commitment, witness commitments.Witness, err error) {
	return commitments.Commit(
		sessionId,
		prng,
		bigQPrime.ToAffineCompressed(),
		bigQDoublePrime.ToAffineCompressed(),
		pid.ToAffineCompressed(),
	)
}

func openCommitment(commitment commitments.Commitment, witness commitments.Witness, bigQPrime, bigQDoublePrime curves.Point, sessionId []byte, pid curves.Point) (err error) {
	return commitments.Open(sessionId, commitment, witness, bigQPrime.ToAffineCompressed(), bigQDoublePrime.ToAffineCompressed(), pid.ToAffineCompressed())
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
