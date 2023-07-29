package dkg

import (
	"crypto/sha256"
	"github.com/copperexchange/crypto-primitives-go/pkg/commitments"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/paillier"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17"
	"github.com/copperexchange/crypto-primitives-go/pkg/zkp/paillierdlog"
	"github.com/copperexchange/crypto-primitives-go/pkg/zkp/paillierpk"
	dlog "github.com/copperexchange/crypto-primitives-go/pkg/zkp/schnorr"
)

const (
	paillierBitSize = 1024
)

var (
	commitmentHashFunc = sha256.New
)

type Round1Broadcast struct {
	BigQPrimeCommitment commitments.Commitment
	BigQBisCommitment   commitments.Commitment
}

type Round2Broadcast struct {
	BigQPrime        curves.Point
	BigQPrimeWitness commitments.Witness
	BigQPrimeProof   *dlog.Proof
	BigQBis          curves.Point
	BigQBisWitness   commitments.Witness
	BigQBisProof     *dlog.Proof
}

type Round3Broadcast struct {
	CKeyPrime         paillier.CipherText
	CKeyBis           paillier.CipherText
	PaillierPublicKey *paillier.PublicKey
}

type Round4P2P struct {
	lpRound1Output        *paillierpk.VerifierRound1Output
	lpdlPrimeRound1Output *paillierdlog.VerifierRound1Output
	lpdlBisRound1Output   *paillierdlog.VerifierRound1Output
}

type Round5P2P struct {
	lpRound2Output        *paillierpk.ProverRound2Output
	lpdlPrimeRound2Output *paillierdlog.ProverRound2Output
	lpdlBisRound2Output   *paillierdlog.ProverRound2Output
}

type Round6P2P struct {
	lpRound3Output        *paillierpk.VerifierRound3Output
	lpdlPrimeRound3Output *paillierdlog.VerifierRound3Output
	lpdlBisRound3Output   *paillierdlog.VerifierRound3Output
}

type Round7P2P struct {
	lpRound4Output        *paillierpk.ProverRound4Output
	lpdlPrimeRound4Output *paillierdlog.ProverRound4Output
	lpdlBisRound4Output   *paillierdlog.ProverRound4Output
}

func (participant *Participant) Round1() (output *Round1Broadcast, err error) {
	if participant.round != 1 {
		return nil, errs.NewInvalidRound("%d != 1", participant.round)
	}

	// 1.a + 2.b In the original paper P chooses a random x in [q/3, 2q/3) range and computes Q = x * G.
	// Since this protocol runs on already existing x, we choose x' and x'' in the given range
	// such that x = 3x' + x'', calculate Q', Q'' respectively and proceed with x' and x'' as if they were x.
	xPrime, xBis, _, err := lindell17.Split(participant.mySigningKeyShare.Share, participant.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot split share")
	}
	bigQPrime := participant.cohortConfig.CipherSuite.Curve.ScalarBaseMult(xPrime)
	bigQBis := participant.cohortConfig.CipherSuite.Curve.ScalarBaseMult(xBis)

	bigQPrimeCommitmentMessage := append(participant.myIdentityKey.PublicKey().ToAffineCompressed()[:], bigQPrime.ToAffineCompressed()...)
	bigQPrimeCommitment, bigQPrimeWitness, err := commitments.Commit(commitmentHashFunc, bigQPrimeCommitmentMessage)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to Q'")
	}

	bigQBisCommitmentMessage := append(participant.myIdentityKey.PublicKey().ToAffineCompressed()[:], bigQBis.ToAffineCompressed()...)
	bigQBisCommitment, biqQBisWitness, err := commitments.Commit(commitmentHashFunc, bigQBisCommitmentMessage)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to Q''")
	}

	participant.state.myXPrime = xPrime
	participant.state.myXBis = xBis
	participant.state.myBigQPrime = bigQPrime
	participant.state.myBigQBis = bigQBis
	participant.state.myBigQPrimeWitness = bigQPrimeWitness
	participant.state.myBigQBisWitness = biqQBisWitness

	// some paranoid checks
	if xPrime.Add(xPrime).Add(xPrime).Add(xBis).Cmp(participant.mySigningKeyShare.Share) != 0 {
		return nil, errs.NewFailed("something went really wrong")
	}
	if !bigQPrime.Add(bigQPrime).Add(bigQPrime).Add(bigQBis).Equal(participant.publicKeyShares.SharesMap[participant.myIdentityKey]) {
		return nil, errs.NewFailed("something went really wrong")
	}

	participant.round++
	return &Round1Broadcast{
		BigQPrimeCommitment: bigQPrimeCommitment,
		BigQBisCommitment:   bigQBisCommitment,
	}, nil
}

func (participant *Participant) Round2(input map[integration.IdentityKey]*Round1Broadcast) (output *Round2Broadcast, err error) {
	if participant.round != 2 {
		return nil, errs.NewInvalidRound("%d != 2", participant.round)
	}

	participant.state.theirBigQPrimeCommitment = make(map[integration.IdentityKey]commitments.Commitment)
	participant.state.theirBigQBisCommitment = make(map[integration.IdentityKey]commitments.Commitment)
	for _, identity := range participant.cohortConfig.Participants {
		if identity == participant.myIdentityKey {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with shamir id %d", participant.idKeyToShamirId[identity])
		}
		participant.state.theirBigQPrimeCommitment[identity] = input[identity].BigQPrimeCommitment
		participant.state.theirBigQBisCommitment[identity] = input[identity].BigQBisCommitment
	}

	bigQPrimeProver, err := dlog.NewProver(participant.cohortConfig.CipherSuite.Curve.NewGeneratorPoint(), participant.sessionId, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create prover for Q'")
	}
	bigQPrimeProof, bigQPrimeStatement, err := bigQPrimeProver.Prove(participant.state.myXPrime)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog proof of Q'")
	}
	if !participant.state.myBigQPrime.Equal(bigQPrimeStatement) {
		return nil, errs.NewFailed("invalid statement, something went horribly wrong")
	}

	bigQBisProver, err := dlog.NewProver(participant.cohortConfig.CipherSuite.Curve.NewGeneratorPoint(), participant.sessionId, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create prover for Q'")
	}
	bigQBisProof, bigQBisStatement, err := bigQBisProver.Prove(participant.state.myXBis)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog proof of Q''")
	}
	if !participant.state.myBigQBis.Equal(bigQBisStatement) {
		return nil, errs.NewFailed("invalid statement, something went horribly wrong")
	}

	participant.round++
	return &Round2Broadcast{
		BigQPrime:        participant.state.myBigQPrime,
		BigQPrimeWitness: participant.state.myBigQPrimeWitness,
		BigQPrimeProof:   bigQPrimeProof,
		BigQBis:          participant.state.myBigQBis,
		BigQBisWitness:   participant.state.myBigQBisWitness,
		BigQBisProof:     bigQBisProof,
	}, nil
}

func (participant *Participant) Round3(input map[integration.IdentityKey]*Round2Broadcast) (output *Round3Broadcast, err error) {
	if participant.round != 3 {
		return nil, errs.NewInvalidRound("%d != 3", participant.round)
	}

	// 3.a P receives dlog proof of Q
	participant.state.theirBigQPrime = make(map[integration.IdentityKey]curves.Point)
	participant.state.theirBigQBis = make(map[integration.IdentityKey]curves.Point)

	// 3.b P opens the commitment and verifies dlog proofs
	for _, identity := range participant.cohortConfig.Participants {
		if identity == participant.myIdentityKey {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with shamir id %d", participant.idKeyToShamirId[identity])
		}

		bigQPrimeCommitmentMessage := append(identity.PublicKey().ToAffineCompressed()[:], input[identity].BigQPrime.ToAffineCompressed()...)
		err = commitments.Open(commitmentHashFunc, bigQPrimeCommitmentMessage, participant.state.theirBigQPrimeCommitment[identity], input[identity].BigQPrimeWitness)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot open Q' commitment")
		}
		err = dlog.Verify(participant.cohortConfig.CipherSuite.Curve.NewGeneratorPoint(), input[identity].BigQPrime, input[identity].BigQPrimeProof, participant.sessionId, nil)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot verify dlog proof of Q'")
		}
		participant.state.theirBigQPrime[identity] = input[identity].BigQPrime

		bigQBisCommitmentMessage := append(identity.PublicKey().ToAffineCompressed()[:], input[identity].BigQBis.ToAffineCompressed()...)
		err = commitments.Open(commitmentHashFunc, bigQBisCommitmentMessage, participant.state.theirBigQBisCommitment[identity], input[identity].BigQBisWitness)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot open Q'' commitment")
		}
		err = dlog.Verify(participant.cohortConfig.CipherSuite.Curve.NewGeneratorPoint(), input[identity].BigQBis, input[identity].BigQBisProof, participant.sessionId, nil)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot verify dlog proof of Q''")
		}
		participant.state.theirBigQBis[identity] = input[identity].BigQBis
	}

	// 3.c P generates a Paillier key-pair
	participant.state.myPaillierPk, participant.state.myPaillierSk, err = paillier.NewKeys(paillierBitSize)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate Paillier keys")
	}
	cKeyPrime, rPrime, err := participant.state.myPaillierPk.Encrypt(participant.state.myXPrime.BigInt())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt x'")
	}
	cKeyBis, rBis, err := participant.state.myPaillierPk.Encrypt(participant.state.myXBis.BigInt())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt x''")
	}
	participant.state.myRPrime = rPrime
	participant.state.myRBis = rBis

	participant.state.lpProvers = make(map[integration.IdentityKey]*paillierpk.Prover)
	participant.state.lpdlPrimeProvers = make(map[integration.IdentityKey]*paillierdlog.Prover)
	participant.state.lpdlBisProvers = make(map[integration.IdentityKey]*paillierdlog.Prover)
	for _, identity := range participant.cohortConfig.Participants {
		if identity == participant.myIdentityKey {
			continue
		}

		// 4. P proves in zero knowledge that public-key was generated correctly (L_P)
		// and the encrypted share encrypts dlog of Q (L_PDL)
		participant.state.lpProvers[identity] = paillierpk.NewProver(40, participant.state.myPaillierSk, participant.prng)
		participant.state.lpdlPrimeProvers[identity], err = paillierdlog.NewProver(participant.sessionId, participant.state.myPaillierSk, participant.state.myXPrime, participant.state.myRPrime, participant.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL prover")
		}
		participant.state.lpdlBisProvers[identity], err = paillierdlog.NewProver(participant.sessionId, participant.state.myPaillierSk, participant.state.myXBis, participant.state.myRBis, participant.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL prover")
		}
	}

	// 3.d P sends public-key and encryption of x to other parties
	participant.round++
	return &Round3Broadcast{
		CKeyPrime:         cKeyPrime,
		CKeyBis:           cKeyBis,
		PaillierPublicKey: participant.state.myPaillierPk,
	}, nil
}

func (participant *Participant) Round4(input map[integration.IdentityKey]*Round3Broadcast) (output map[integration.IdentityKey]*Round4P2P, err error) {
	if participant.round != 4 {
		return nil, errs.NewInvalidRound("%d != 4", participant.round)
	}

	participant.state.theirPaillierPublicKeys = make(map[integration.IdentityKey]*paillier.PublicKey)
	participant.state.theirPaillierEncryptedShares = make(map[integration.IdentityKey]paillier.CipherText)

	participant.state.lpVerifiers = make(map[integration.IdentityKey]*paillierpk.Verifier)
	participant.state.lpdlPrimeVerifiers = make(map[integration.IdentityKey]*paillierdlog.Verifier)
	participant.state.lpdlBisVerifiers = make(map[integration.IdentityKey]*paillierdlog.Verifier)

	round4Outputs := make(map[integration.IdentityKey]*Round4P2P)
	for _, identity := range participant.cohortConfig.Participants {
		if identity == participant.myIdentityKey {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with shamir id %d", participant.idKeyToShamirId[identity])
		}

		participant.state.theirPaillierPublicKeys[identity] = input[identity].PaillierPublicKey
		theirCKeyPrime := input[identity].CKeyPrime
		theirCKeyBis := input[identity].CKeyBis

		cKey1, err := participant.state.theirPaillierPublicKeys[identity].Add(theirCKeyPrime, theirCKeyPrime)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}
		cKey2, err := participant.state.theirPaillierPublicKeys[identity].Add(cKey1, theirCKeyPrime)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}
		participant.state.theirPaillierEncryptedShares[identity], err = participant.state.theirPaillierPublicKeys[identity].Add(cKey2, theirCKeyBis)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}

		participant.state.lpVerifiers[identity] = paillierpk.NewVerifier(40, participant.state.theirPaillierPublicKeys[identity], participant.prng)
		participant.state.lpdlPrimeVerifiers[identity], err = paillierdlog.NewVerifier(participant.sessionId, participant.state.theirPaillierPublicKeys[identity], participant.state.theirBigQPrime[identity], theirCKeyPrime, participant.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL verifier")
		}
		participant.state.lpdlBisVerifiers[identity], err = paillierdlog.NewVerifier(participant.sessionId, participant.state.theirPaillierPublicKeys[identity], participant.state.theirBigQBis[identity], theirCKeyBis, participant.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create PDL verifier")
		}

		round4Outputs[identity] = new(Round4P2P)
		round4Outputs[identity].lpRound1Output, err = participant.state.lpVerifiers[identity].Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 1 of LP verifier")
		}
		round4Outputs[identity].lpdlPrimeRound1Output, err = participant.state.lpdlPrimeVerifiers[identity].Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 1 of LP verifier")
		}
		round4Outputs[identity].lpdlBisRound1Output, err = participant.state.lpdlBisVerifiers[identity].Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 1 of LP verifier")
		}
	}

	participant.round++
	return round4Outputs, nil
}

func (participant *Participant) Round5(input map[integration.IdentityKey]*Round4P2P) (output map[integration.IdentityKey]*Round5P2P, err error) {
	if participant.round != 5 {
		return nil, errs.NewInvalidRound("%d != 5", participant.round)
	}

	round5Outputs := make(map[integration.IdentityKey]*Round5P2P)
	for _, identity := range participant.cohortConfig.Participants {
		if identity == participant.myIdentityKey {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with shamir id %d", participant.idKeyToShamirId[identity])
		}

		round5Outputs[identity] = new(Round5P2P)
		round5Outputs[identity].lpRound2Output, err = participant.state.lpProvers[identity].Round2(input[identity].lpRound1Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
		round5Outputs[identity].lpdlPrimeRound2Output, err = participant.state.lpdlPrimeProvers[identity].Round2(input[identity].lpdlPrimeRound1Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
		round5Outputs[identity].lpdlBisRound2Output, err = participant.state.lpdlBisProvers[identity].Round2(input[identity].lpdlBisRound1Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
	}

	participant.round++
	return round5Outputs, nil
}

func (participant *Participant) Round6(input map[integration.IdentityKey]*Round5P2P) (output map[integration.IdentityKey]*Round6P2P, err error) {
	if participant.round != 6 {
		return nil, errs.NewInvalidRound("%d != 6", participant.round)
	}

	round6Outputs := make(map[integration.IdentityKey]*Round6P2P)
	for _, identity := range participant.cohortConfig.Participants {
		if identity == participant.myIdentityKey {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with shamir id %d", participant.idKeyToShamirId[identity])
		}

		round6Outputs[identity] = new(Round6P2P)
		round6Outputs[identity].lpRound3Output, err = participant.state.lpVerifiers[identity].Round3(input[identity].lpRound2Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 3 of LP verifier")
		}
		round6Outputs[identity].lpdlPrimeRound3Output, err = participant.state.lpdlPrimeVerifiers[identity].Round3(input[identity].lpdlPrimeRound2Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 3 of LP verifier")
		}
		round6Outputs[identity].lpdlBisRound3Output, err = participant.state.lpdlBisVerifiers[identity].Round3(input[identity].lpdlBisRound2Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 3 of LP verifier")
		}
	}

	participant.round++
	return round6Outputs, nil
}

func (participant *Participant) Round7(input map[integration.IdentityKey]*Round6P2P) (output map[integration.IdentityKey]*Round7P2P, err error) {
	if participant.round != 7 {
		return nil, errs.NewInvalidRound("%d != 7", participant.round)
	}

	round7Outputs := make(map[integration.IdentityKey]*Round7P2P)
	for _, identity := range participant.cohortConfig.Participants {
		if identity == participant.myIdentityKey {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with shamir id %d", participant.idKeyToShamirId[identity])
		}

		round7Outputs[identity] = new(Round7P2P)
		round7Outputs[identity].lpRound4Output, err = participant.state.lpProvers[identity].Round4(input[identity].lpRound3Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
		round7Outputs[identity].lpdlPrimeRound4Output, err = participant.state.lpdlPrimeProvers[identity].Round4(input[identity].lpdlPrimeRound3Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
		round7Outputs[identity].lpdlBisRound4Output, err = participant.state.lpdlBisProvers[identity].Round4(input[identity].lpdlBisRound3Output)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of LP prover")
		}
	}

	participant.round++
	return round7Outputs, nil
}

func (participant *Participant) Round8(input map[integration.IdentityKey]*Round7P2P) (shard *lindell17.Shard, err error) {
	if participant.round != 8 {
		return nil, errs.NewInvalidRound("%d != 8", participant.round)
	}

	for _, identity := range participant.cohortConfig.Participants {
		if identity == participant.myIdentityKey {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with shamir id %d", participant.idKeyToShamirId[identity])
		}

		err = participant.state.lpVerifiers[identity].Round5(input[identity].lpRound4Output)
		if err != nil {
			return nil, errs.WrapIdentifiableAbort(err, "failed to verify valid Paillier public-key")
		}
		err = participant.state.lpdlPrimeVerifiers[identity].Round5(input[identity].lpdlPrimeRound4Output)
		if err != nil {
			return nil, errs.WrapIdentifiableAbort(err, "failed to verify encrypted dlog")
		}
		err = participant.state.lpdlBisVerifiers[identity].Round5(input[identity].lpdlBisRound4Output)
		if err != nil {
			return nil, errs.WrapIdentifiableAbort(err, "failed to verify encrypted dlog")
		}
	}

	participant.round++
	// 6. P stores encrypted Enc(x) which is Enc(3x' + x'')
	return &lindell17.Shard{
		SigningKeyShare:         participant.mySigningKeyShare,
		PaillierSecretKey:       participant.state.myPaillierSk,
		PaillierPublicKeys:      participant.state.theirPaillierPublicKeys,
		PaillierEncryptedShares: participant.state.theirPaillierEncryptedShares,
	}, nil
}
