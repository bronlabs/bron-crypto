package dkg

import (
	"crypto/sha256"
	"github.com/copperexchange/crypto-primitives-go/pkg/commitments"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/paillier"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17"
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
			return nil, errs.WrapFailed(err, "cannot open Q' commitment")
		}
		err = dlog.Verify(participant.cohortConfig.CipherSuite.Curve.NewGeneratorPoint(), input[identity].BigQBis, input[identity].BigQBisProof, participant.sessionId, nil)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot verify dlog proof of Q'")
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

	// 3.d P sends public-key and encryption of x to other parties
	participant.round++
	return &Round3Broadcast{
		CKeyPrime:         cKeyPrime,
		CKeyBis:           cKeyBis,
		PaillierPublicKey: participant.state.myPaillierPk,
	}, nil
}

func (participant *Participant) Round4(input map[integration.IdentityKey]*Round3Broadcast) (shard *lindell17.Shard, err error) {
	if participant.round != 4 {
		return nil, errs.NewInvalidRound("%d != 4", participant.round)
	}

	// 4. P proves in zero knowledge that public-key was generated correctly (L_P)
	// and the encrypted share encrypts dlog of Q (L_PDL)
	// TODO: add zk-proof when merged (+3 additional rounds)

	paillierPublicKeys := make(map[integration.IdentityKey]*paillier.PublicKey)
	paillierEncryptedShares := make(map[integration.IdentityKey]paillier.CipherText)

	// 6. P stores encrypted Enc(x) which is Enc(3x' + x'')
	for _, identity := range participant.cohortConfig.Participants {
		if identity == participant.myIdentityKey {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with shamir id %d", participant.idKeyToShamirId[identity])
		}
		theirPaillierPk := input[identity].PaillierPublicKey
		theirCKeyPrime := input[identity].CKeyPrime
		theirCKeyBis := input[identity].CKeyBis
		cKey1, err := theirPaillierPk.Add(theirCKeyPrime, theirCKeyPrime)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}
		cKey2, err := theirPaillierPk.Add(cKey1, theirCKeyPrime)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}
		theirCKey, err := theirPaillierPk.Add(cKey2, theirCKeyBis)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot add ciphertexts")
		}

		paillierEncryptedShares[identity] = theirCKey
		paillierPublicKeys[identity] = theirPaillierPk
	}

	participant.round++
	return &lindell17.Shard{
		SigningKeyShare:         participant.mySigningKeyShare,
		PaillierSecretKey:       participant.state.myPaillierSk,
		PaillierPublicKeys:      paillierPublicKeys,
		PaillierEncryptedShares: paillierEncryptedShares,
	}, nil
}
