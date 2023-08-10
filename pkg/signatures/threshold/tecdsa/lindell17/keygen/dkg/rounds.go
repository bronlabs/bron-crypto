package dkg

import (
	"crypto/sha256"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashmap"

	"github.com/copperexchange/knox-primitives/pkg/commitments"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/paillier"
	"github.com/copperexchange/knox-primitives/pkg/proofs/paillier/lp"
	"github.com/copperexchange/knox-primitives/pkg/proofs/paillier/lpdl"
	dlog "github.com/copperexchange/knox-primitives/pkg/proofs/dlog/schnorr"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
)

const (
	paillierBitSize = 1024
)

var (
	commitmentHashFunc = sha256.New
)

type Round1Broadcast struct {
	BigQCommitment commitments.Commitment
}

type Round2Broadcast struct {
	BigQWitness          commitments.Witness
	BigQPrime            curves.Point
	BigQPrimeProof       *dlog.Proof
	BigQDoublePrime      curves.Point
	BigQDoublePrimeProof *dlog.Proof
}

type Round3Broadcast struct {
	CKeyPrime         paillier.CipherText
	CKeyDoublePrime   paillier.CipherText
	PaillierPublicKey *paillier.PublicKey
}

type Round4P2P struct {
	LpRound1Output              *lp.Round1Output
	LpdlPrimeRound1Output       *lpdl.Round1Output
	LpdlDoublePrimeRound1Output *lpdl.Round1Output
}

type Round5P2P struct {
	LpRound2Output              *lp.Round2Output
	LpdlPrimeRound2Output       *lpdl.Round2Output
	LpdlDoublePrimeRound2Output *lpdl.Round2Output
}

type Round6P2P struct {
	LpRound3Output              *lp.Round3Output
	LpdlPrimeRound3Output       *lpdl.Round3Output
	LpdlDoublePrimeRound3Output *lpdl.Round3Output
}

type Round7P2P struct {
	LpRound4Output              *lp.Round4Output
	LpdlPrimeRound4Output       *lpdl.Round4Output
	LpdlDoublePrimeRound4Output *lpdl.Round4Output
}

func (p *Participant) Round1() (output *Round1Broadcast, err error) {
	if p.round != 1 {
		return nil, errs.NewInvalidRound("%d != 1", p.round)
	}

	// 1.i. choose randomly x' and x'' such that x = 3x' + x'' and both x' and x'' are in (q/3, 2q/3) range
	xPrime, xDoublePrime, err := lindell17.DecomposeInQThirdsDeterministically(p.mySigningKeyShare.Share, p.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot split share")
	}

	// 1.ii. calculate Q' and Q''
	bigQPrime := p.cohortConfig.CipherSuite.Curve.ScalarBaseMult(xPrime)
	bigQDoublePrime := p.cohortConfig.CipherSuite.Curve.ScalarBaseMult(xDoublePrime)

	// 1.iii. calculates commitments Qcom to Q' and Q''
	bigQCommitment, bigQWitness, err := commit(bigQPrime, bigQDoublePrime, p.sessionId, p.myIdentityKey.PublicKey())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to (Q', Q'')")
	}

	p.state.myXPrime = xPrime
	p.state.myXDoublePrime = xDoublePrime
	p.state.myBigQPrime = bigQPrime
	p.state.myBigQDoublePrime = bigQDoublePrime
	p.state.myBigQWitness = bigQWitness

	// some paranoid checks
	share, exists := p.publicKeyShares.SharesMap.Get(p.myIdentityKey)
	if !exists {
		return nil, errs.NewFailed("cannot find share")
	}
	if !bigQPrime.Add(bigQPrime).Add(bigQPrime).Add(bigQDoublePrime).Equal(share) {
		return nil, errs.NewFailed("something went really wrong")
	}

	// 1.iv. broadcast commitments
	p.round++
	return &Round1Broadcast{
		bigQCommitment,
	}, nil
}

func (p *Participant) Round2(input *hashmap.HashMap[integration.IdentityKey, *Round1Broadcast]) (output *Round2Broadcast, err error) {
	if p.round != 2 {
		return nil, errs.NewInvalidRound("%d != 2", p.round)
	}

	// 2. store commitments
	p.state.theirBigQCommitment = hashmap.NewHashMap[integration.IdentityKey, commitments.Commitment]()
	for _, identity := range p.cohortConfig.Participants {
		if identity == p.myIdentityKey {
			continue
		}
		identityInput, found := input.Get(identity)
		if !found {
			sharingId, exists := p.idKeyToSharingId.Get(identity)
			if !exists {
				return nil, errs.NewFailed("cannot find sharing id for identity %s", identity)
			}
			return nil, errs.NewFailed("no input from participant with sharing id %d", sharingId)
		}
		p.state.theirBigQCommitment.Put(identity, identityInput.BigQCommitment)
	}

	// 2.i. calculate proofs of dlog knowledge of Q' and Q'' (Qdl' and Qdl'' respectively)
	dlogTranscript := p.transcript.Clone()
	bigQPrimeProof, err := dlogProve(p.state.myXPrime, p.state.myBigQPrime, p.state.myBigQDoublePrime, p.sessionId, dlogTranscript)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog proof of Q'")
	}
	bigQDoublePrimeProof, err := dlogProve(p.state.myXDoublePrime, p.state.myBigQDoublePrime, p.state.myBigQPrime, p.sessionId, dlogTranscript)
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

func (p *Participant) Round3(input *hashmap.HashMap[integration.IdentityKey, *Round2Broadcast]) (output *Round3Broadcast, err error) {
	if p.round != 3 {
		return nil, errs.NewInvalidRound("%d != 3", p.round)
	}

	p.state.theirBigQPrime = hashmap.NewHashMap[integration.IdentityKey, curves.Point]()
	p.state.theirBigQDoublePrime = hashmap.NewHashMap[integration.IdentityKey, curves.Point]()

	// 3.i. verify proofs of dlog knowledge of Qdl'_j Qdl''_j
	for _, identity := range p.cohortConfig.Participants {
		sharingId, exists := p.idKeyToSharingId.Get(identity)
		if !exists {
			return nil, errs.NewFailed("cannot find sharing id for identity %s", identity)
		}
		if identity == p.myIdentityKey {
			continue
		}
		identityInput, found := input.Get(identity)
		if !found {
			return nil, errs.NewFailed("no input from participant with sharing id %d", sharingId)
		}

		// 3.i. open commitments
		bigQComm, exists := p.state.theirBigQCommitment.Get(identity)
		if !exists {
			return nil, errs.NewFailed("cannot find commitment to (Q', Q'') for identity %s", identity)
		}
		if err := openCommitment(bigQComm, identityInput.BigQWitness, identityInput.BigQPrime, identityInput.BigQDoublePrime, p.sessionId, identity.PublicKey()); err != nil {
			return nil, errs.WrapFailed(err, "cannot open (Q', Q'') commitment")
		}

		dlogTranscript := p.transcript.Clone()
		if err := dlogVerify(identityInput.BigQPrimeProof, identityInput.BigQPrime, identityInput.BigQDoublePrime, p.sessionId, dlogTranscript); err != nil {
			return nil, errs.WrapFailed(err, "cannot verify dlog proof of Q'")
		}
		if err := dlogVerify(identityInput.BigQDoublePrimeProof, identityInput.BigQDoublePrime, identityInput.BigQPrime, p.sessionId, dlogTranscript); err != nil {
			return nil, errs.WrapFailed(err, "cannot verify dlog proof of Q''")
		}
		p.state.theirBigQPrime.Put(identity, identityInput.BigQPrime)
		p.state.theirBigQDoublePrime.Put(identity, identityInput.BigQDoublePrime)

		// 3.ii. verify that y_j == 3Q'_j + Q''_j and abort if not
		bigQPrime, exists := p.state.theirBigQPrime.Get(identity)
		if !exists {
			return nil, errs.NewFailed("cannot find Q' for identity %s", identity)
		}
		bigQDoublePrime, exists := p.state.theirBigQDoublePrime.Get(identity)
		if !exists {
			return nil, errs.NewFailed("cannot find Q'' for identity %s", identity)
		}
		theirBigQ := bigQPrime.Mul(p.cohortConfig.CipherSuite.Curve.NewScalar().New(3)).Add(bigQDoublePrime)
		share, exists := p.publicKeyShares.SharesMap.Get(identity)
		if !exists {
			return nil, errs.NewFailed("cannot find public key share for identity %s", identity)
		}
		if !theirBigQ.Equal(share) {
			return nil, errs.NewIdentifiableAbort("invalid Q' or Q''")
		}
	}

	// 3.iii. generate a Paillier key pair
	p.state.myPaillierPk, p.state.myPaillierSk, err = paillier.NewKeys(paillierBitSize)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate Paillier keys")
	}
	cKeyPrime, rPrime, err := p.state.myPaillierPk.Encrypt(p.state.myXPrime.BigInt())

	// 3.iv. calculate ckey' = Enc(x'; r') and ckey'' = Enc(x''; r'')
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt x'")
	}
	cKeyDoublePrime, rDoublePrime, err := p.state.myPaillierPk.Encrypt(p.state.myXDoublePrime.BigInt())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt x''")
	}
	p.state.myRPrime = rPrime
	p.state.myRDoublePrime = rDoublePrime

	// 3.vi. prove pairwise iz ZK that pk was generated correctly (LP)
	//       and that (ckey', ckey'') encrypt dlogs of (Q', Q'') (LPDL)
	p.state.lpProvers = hashmap.NewHashMap[integration.IdentityKey, *lp.Prover]()
	p.state.lpdlPrimeProvers = hashmap.NewHashMap[integration.IdentityKey, *lpdl.Prover]()
	p.state.lpdlDoublePrimeProvers = hashmap.NewHashMap[integration.IdentityKey, *lpdl.Prover]()
	for _, identity := range p.cohortConfig.Participants {
		if identity == p.myIdentityKey {
			continue
		}
		paillierProofsTranscript := p.transcript.Clone()
		proverLp, err := lp.NewProver(128, p.state.myPaillierSk, p.sessionId, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create LP prover")
		}
		p.state.lpProvers.Put(identity, proverLp)
		proverLpdl, err := lpdl.NewProver(p.sessionId, p.state.myPaillierSk, p.state.myXPrime, p.state.myRPrime, p.sessionId, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL prover")
		}
		p.state.lpdlPrimeProvers.Put(identity, proverLpdl)
		proverLpdl, err = lpdl.NewProver(p.sessionId, p.state.myPaillierSk, p.state.myXDoublePrime, p.state.myRDoublePrime, p.sessionId, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL prover")
		}
		p.state.lpdlDoublePrimeProvers.Put(identity, proverLpdl)
	}

	// 3.v. broadcast (pk, ckey', ckey'')
	p.round++
	return &Round3Broadcast{
		CKeyPrime:         cKeyPrime,
		CKeyDoublePrime:   cKeyDoublePrime,
		PaillierPublicKey: p.state.myPaillierPk,
	}, nil
}

func (p *Participant) Round4(input *hashmap.HashMap[integration.IdentityKey, *Round3Broadcast]) (output *hashmap.HashMap[integration.IdentityKey, *Round4P2P], err error) {
	if p.round != 4 {
		return nil, errs.NewInvalidRound("%d != 4", p.round)
	}

	p.state.theirPaillierPublicKeys = hashmap.NewHashMap[integration.IdentityKey, *paillier.PublicKey]()
	p.state.theirPaillierEncryptedShares = hashmap.NewHashMap[integration.IdentityKey, paillier.CipherText]()

	p.state.lpVerifiers = hashmap.NewHashMap[integration.IdentityKey, *lp.Verifier]()
	p.state.lpdlPrimeVerifiers = hashmap.NewHashMap[integration.IdentityKey, *lpdl.Verifier]()
	p.state.lpdlDoublePrimeVerifiers = hashmap.NewHashMap[integration.IdentityKey, *lpdl.Verifier]()

	round4Outputs := hashmap.NewHashMap[integration.IdentityKey, *Round4P2P]()
	for _, identity := range p.cohortConfig.Participants {
		if identity == p.myIdentityKey {
			continue
		}
		sharingId, exists := p.idKeyToSharingId.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no input from participant")
		}
		inputIdentity, exists := input.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no input from participant with sharing id %d", sharingId)
		}

		p.state.theirPaillierPublicKeys.Put(identity, inputIdentity.PaillierPublicKey)
		theirCKeyPrime := inputIdentity.CKeyPrime
		theirCKeyDoublePrime := inputIdentity.CKeyDoublePrime

		// 4.i. calculate and store ckey_j = 3 (*) ckey'_j (+) ckey''_j
		theirPaillierPublicKey, exists := p.state.theirPaillierPublicKeys.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no Paillier public key for participant with sharing id %d", sharingId)
		}
		cKey1, err := theirPaillierPublicKey.Add(theirCKeyPrime, theirCKeyPrime)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}
		cKey2, err := theirPaillierPublicKey.Add(cKey1, theirCKeyPrime)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}
		addedTheirPaillierPublicKey, err := theirPaillierPublicKey.Add(cKey2, theirCKeyDoublePrime)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}
		p.state.theirPaillierEncryptedShares.Put(identity, addedTheirPaillierPublicKey)
		// 4.ii. LP and LPDL continue
		paillierProofsTranscript := p.transcript.Clone()
		lpVerifier, err := lp.NewVerifier(128, theirPaillierPublicKey, p.sessionId, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create P verifier")
		}
		p.state.lpVerifiers.Put(identity, lpVerifier)
		theirBigQPrime, exists := p.state.theirBigQPrime.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no big q prime for participant with sharing id %d", sharingId)
		}
		lpdlNewVerifier, err := lpdl.NewVerifier(p.sessionId, theirPaillierPublicKey, theirBigQPrime, theirCKeyPrime, p.sessionId, paillierProofsTranscript, p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL verifier")
		}
		p.state.lpdlPrimeVerifiers.Put(identity, lpdlNewVerifier)
		theirBigQDoublePrime, exists := p.state.theirBigQDoublePrime.Get(identity)
		lpdlVerifier, err := lpdl.NewVerifier(p.sessionId, theirPaillierPublicKey, theirBigQDoublePrime, theirCKeyDoublePrime, p.sessionId, paillierProofsTranscript, p.prng)
		p.state.lpdlDoublePrimeVerifiers.Put(identity, lpdlVerifier)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL verifier")
		}

		round4P2p := new(Round4P2P)
		lpVerifier, exists = p.state.lpVerifiers.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no LP verifier for participant with sharing id %d", sharingId)
		}
		round4P2p.LpRound1Output, err = lpVerifier.Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 1 of LP verifier")
		}
		lpdlPrimeVerifier, exists := p.state.lpdlPrimeVerifiers.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no LPDL verifier for participant with sharing id %d", sharingId)
		}
		round4P2p.LpdlPrimeRound1Output, err = lpdlPrimeVerifier.Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 1 of LP verifier")
		}
		lpdlDoublePrimeVerifier, exists := p.state.lpdlDoublePrimeVerifiers.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no LPDL verifier for participant with sharing id %d", sharingId)
		}
		round4P2p.LpdlDoublePrimeRound1Output, err = lpdlDoublePrimeVerifier.Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 1 of LP verifier")
		}
		round4Outputs.Put(identity, round4P2p)
	}

	p.round++
	return round4Outputs, nil
}

func (p *Participant) Round5(input *hashmap.HashMap[integration.IdentityKey, *Round4P2P]) (output *hashmap.HashMap[integration.IdentityKey, *Round5P2P], err error) {
	if p.round != 5 {
		return nil, errs.NewInvalidRound("%d != 5", p.round)
	}

	// 5. LP and LPDL continue
	round5Outputs := hashmap.NewHashMap[integration.IdentityKey, *Round5P2P]()
	for _, identity := range p.cohortConfig.Participants {
		if identity == p.myIdentityKey {
			continue
		}
		sharingId, exists := p.idKeyToSharingId.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no input from participant")
		}
		inputIdentity, exists := input.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no input from participant with sharing id %d", sharingId)
		}

		lpProver, exists := p.state.lpProvers.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no LP prover for participant with sharing id %d", sharingId)
		}
		lpdlPrimeProver, exists := p.state.lpdlPrimeProvers.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no LPDL prover for participant with sharing id %d", sharingId)
		}
		lpdlDoublePrimeProver, exists := p.state.lpdlDoublePrimeProvers.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no LPDL prover for participant with sharing id %d", sharingId)
		}

		round5P2p := new(Round5P2P)
		round5P2p.LpRound2Output, err = lpProver.Round2(inputIdentity.LpRound1Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
		round5P2p.LpdlPrimeRound2Output, err = lpdlPrimeProver.Round2(inputIdentity.LpdlPrimeRound1Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LPDL prover")
		}
		round5P2p.LpdlDoublePrimeRound2Output, err = lpdlDoublePrimeProver.Round2(inputIdentity.LpdlDoublePrimeRound1Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LPDL prover")
		}
		round5Outputs.Put(identity, round5P2p)
	}

	p.round++
	return round5Outputs, nil
}

func (p *Participant) Round6(input *hashmap.HashMap[integration.IdentityKey, *Round5P2P]) (output *hashmap.HashMap[integration.IdentityKey, *Round6P2P], err error) {
	if p.round != 6 {
		return nil, errs.NewInvalidRound("%d != 6", p.round)
	}

	// 6. LP and LPDL continue
	round6Outputs := hashmap.NewHashMap[integration.IdentityKey, *Round6P2P]()
	for _, identity := range p.cohortConfig.Participants {
		if identity == p.myIdentityKey {
			continue
		}
		sharingId, exists := p.idKeyToSharingId.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no input from participant")
		}
		inputIdentity, exists := input.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no input from participant with sharing id %d", sharingId)
		}

		lpVerifier, exists := p.state.lpVerifiers.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no LP verifier for participant with sharing id %d", sharingId)
		}
		lpdlPrimeVerifier, exists := p.state.lpdlPrimeVerifiers.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no LPDL verifier for participant with sharing id %d", sharingId)
		}
		lpdlDoublePrimeVerifier, exists := p.state.lpdlDoublePrimeVerifiers.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no LPDL verifier for participant with sharing id %d", sharingId)
		}

		round6P2p := new(Round6P2P)
		round6P2p.LpRound3Output, err = lpVerifier.Round3(inputIdentity.LpRound2Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 3 of LP verifier")
		}
		round6P2p.LpdlPrimeRound3Output, err = lpdlPrimeVerifier.Round3(inputIdentity.LpdlPrimeRound2Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 3 of LP verifier")
		}
		round6P2p.LpdlDoublePrimeRound3Output, err = lpdlDoublePrimeVerifier.Round3(inputIdentity.LpdlDoublePrimeRound2Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 3 of LP verifier")
		}
		round6Outputs.Put(identity, round6P2p)
	}

	p.round++
	return round6Outputs, nil
}

func (p *Participant) Round7(input *hashmap.HashMap[integration.IdentityKey, *Round6P2P]) (output *hashmap.HashMap[integration.IdentityKey, *Round7P2P], err error) {
	if p.round != 7 {
		return nil, errs.NewInvalidRound("%d != 7", p.round)
	}

	// 7. LP and LPDL continue
	round7Outputs := hashmap.NewHashMap[integration.IdentityKey, *Round7P2P]()
	for _, identity := range p.cohortConfig.Participants {
		if identity == p.myIdentityKey {
			continue
		}

		sharingId, exists := p.idKeyToSharingId.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no input from participant")
		}
		inputIdentity, exists := input.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no input from participant with sharing id %d", sharingId)
		}

		lpProver, exists := p.state.lpProvers.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no LP prover for participant with sharing id %d", sharingId)
		}
		lpdlPrimeProver, exists := p.state.lpdlPrimeProvers.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no LPDL prover for participant with sharing id %d", sharingId)
		}
		lpdlDoublePrimeProver, exists := p.state.lpdlDoublePrimeProvers.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no LPDL prover for participant with sharing id %d", sharingId)
		}

		round7P2p := new(Round7P2P)
		round7P2p.LpRound4Output, err = lpProver.Round4(inputIdentity.LpRound3Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
		round7P2p.LpdlPrimeRound4Output, err = lpdlPrimeProver.Round4(inputIdentity.LpdlPrimeRound3Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
		round7P2p.LpdlDoublePrimeRound4Output, err = lpdlDoublePrimeProver.Round4(inputIdentity.LpdlDoublePrimeRound3Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
		round7Outputs.Put(identity, round7P2p)
	}

	p.round++
	return round7Outputs, nil
}

func (p *Participant) Round8(input *hashmap.HashMap[integration.IdentityKey, *Round7P2P]) (shard *lindell17.Shard, err error) {
	if p.round != 8 {
		return nil, errs.NewInvalidRound("%d != 8", p.round)
	}

	for _, identity := range p.cohortConfig.Participants {
		if identity == p.myIdentityKey {
			continue
		}
		sharingId, exists := p.idKeyToSharingId.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no input from participant")
		}
		inputIdentity, exists := input.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no input from participant with sharing id %d", sharingId)
		}

		lpVerifier, exists := p.state.lpVerifiers.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no LP prover for participant with sharing id %d", sharingId)
		}
		lpdlPrimeVerifier, exists := p.state.lpdlPrimeVerifiers.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no LPDL prover for participant with sharing id %d", sharingId)
		}
		lpdlDoublePrimeVerifier, exists := p.state.lpdlDoublePrimeVerifiers.Get(identity)
		if !exists {
			return nil, errs.NewFailed("no LPDL prover for participant with sharing id %d", sharingId)
		}

		err = lpVerifier.Round5(inputIdentity.LpRound4Output)
		if err != nil {
			return nil, errs.WrapIdentifiableAbort(err, "failed to verify valid Paillier public-key")
		}
		err = lpdlPrimeVerifier.Round5(inputIdentity.LpdlPrimeRound4Output)
		if err != nil {
			return nil, errs.WrapIdentifiableAbort(err, "failed to verify encrypted dlog")
		}
		err = lpdlDoublePrimeVerifier.Round5(inputIdentity.LpdlDoublePrimeRound4Output)
		if err != nil {
			return nil, errs.WrapIdentifiableAbort(err, "failed to verify encrypted dlog")
		}
	}

	p.round++
	// 8. store encrypted x_j aka ckey_j (ckey_j = Enc(x_j) = Enc(3x'_j + x''_j)) and pk_j alongside share
	return &lindell17.Shard{
		SigningKeyShare:         p.mySigningKeyShare,
		PaillierSecretKey:       p.state.myPaillierSk,
		PaillierPublicKeys:      p.state.theirPaillierPublicKeys,
		PaillierEncryptedShares: p.state.theirPaillierEncryptedShares,
	}, nil
}

func commit(bigQPrime curves.Point, bigQDoublePrime curves.Point, sid []byte, pid curves.Point) (commitment commitments.Commitment, witness commitments.Witness, err error) {
	message := []byte{}
	message = append(message, bigQPrime.ToAffineCompressed()...)
	message = append(message, bigQDoublePrime.ToAffineCompressed()...)
	message = append(message, sid...)
	message = append(message, pid.ToAffineCompressed()...)
	return commitments.Commit(commitmentHashFunc, message)
}

func openCommitment(commitment commitments.Commitment, witness commitments.Witness, bigQPrime curves.Point, bigQDoublePrime curves.Point, sid []byte, pid curves.Point) (err error) {
	message := []byte{}
	message = append(message, bigQPrime.ToAffineCompressed()...)
	message = append(message, bigQDoublePrime.ToAffineCompressed()...)
	message = append(message, sid...)
	message = append(message, pid.ToAffineCompressed()...)
	return commitments.Open(commitmentHashFunc, message, commitment, witness)
}

func dlogProve(x curves.Scalar, bigQ curves.Point, bigQTwin curves.Point, sid []byte, transcript transcripts.Transcript) (proof *dlog.Proof, err error) {
	transcript.AppendPoints("bigQTwin", bigQTwin)

	curveName := bigQ.CurveName()
	curve, err := curves.GetCurveByName(curveName)
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "invalid curve %s", curveName)
	}
	generator := curve.NewGeneratorPoint()

	prover, err := dlog.NewProver(generator, sid, transcript)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog prover")
	}

	proof, statement, err := prover.Prove(x)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot prove dlog")
	}
	if !bigQ.Equal(statement) {
		return nil, errs.NewFailed("invalid statement")
	}

	return proof, nil
}

func dlogVerify(proof *dlog.Proof, bigQ curves.Point, bigQTwin curves.Point, sid []byte, transcript transcripts.Transcript) (err error) {
	transcript.AppendPoints("bigQTwin", bigQTwin)

	curveName := bigQ.CurveName()
	curve, err := curves.GetCurveByName(curveName)
	if err != nil {
		return errs.WrapInvalidCurve(err, "invalid curve %s", curveName)
	}
	generator := curve.NewGeneratorPoint()

	return dlog.Verify(generator, bigQ, proof, sid, transcript)
}
