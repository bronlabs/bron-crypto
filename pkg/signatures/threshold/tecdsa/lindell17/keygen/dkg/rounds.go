package dkg

import (
	"crypto/sha256"
	"encoding/json"
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
	BigQCommitment commitments.Commitment
}

type Round2Broadcast struct {
	BigQWitness    commitments.Witness
	BigQPrimeProof *dlog.Proof
	BigQBisProof   *dlog.Proof
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

	// 1.b P sends commitment of dlog proof of Q
	bigQPrimeSessionId := append([]byte("backupQ'"), participant.sessionId...)
	bigQPrimeProver, err := dlog.NewProver(participant.cohortConfig.CipherSuite.Curve.NewGeneratorPoint(), bigQPrimeSessionId, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create prover for Q'")
	}
	bigQPrimeProof, err := bigQPrimeProver.Prove(xPrime)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog proof of x'")
	}
	bigQBisSessionId := append([]byte("backupQ''"), participant.sessionId...)
	bigQBisProver, err := dlog.NewProver(participant.cohortConfig.CipherSuite.Curve.NewGeneratorPoint(), bigQBisSessionId, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create prover for Q'")
	}
	bigQBisProof, err := bigQBisProver.Prove(xBis)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog proof of x'")
	}
	bigQPrimeProofMessage, err := json.Marshal(bigQPrimeProof)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot serialize dlog proof of Q'")
	}
	bigQBisProofMessage, err := json.Marshal(bigQBisProof)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot serialize dlog proof of Q''")
	}
	bigQMessage := append(bigQPrimeProofMessage[:], bigQBisProofMessage...)
	bigQCommitment, bigQWitness, err := commitments.Commit(commitmentHashFunc, bigQMessage)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to Q' and Q''")
	}

	participant.state.myXPrime = xPrime
	participant.state.myXBis = xBis
	participant.state.myBigQPrimeProof = bigQPrimeProof
	participant.state.myBigQBisProof = bigQBisProof
	participant.state.myBigQWitness = bigQWitness

	// some paranoid checks
	if xPrime.Add(xPrime).Add(xPrime).Add(xBis).Cmp(participant.mySigningKeyShare.Share) != 0 {
		return nil, errs.NewFailed("Something went really wrong")
	}
	if !bigQPrimeProof.Statement.Add(bigQPrimeProof.Statement).Add(bigQPrimeProof.Statement).Add(bigQBisProof.Statement).Equal(participant.publicKeyShares.SharesMap[participant.myIdentityKey]) {
		return nil, errs.NewFailed("Something went really wrong")
	}

	participant.round++
	return &Round1Broadcast{
		BigQCommitment: bigQCommitment,
	}, nil
}

func (participant *Participant) Round2(input map[integration.IdentityKey]*Round1Broadcast) (output *Round2Broadcast, err error) {
	if participant.round != 2 {
		return nil, errs.NewInvalidRound("%d != 2", participant.round)
	}

	// 2.a P receives dlog proof commitment of Q
	// 2.c P sends dlog proof of Q
	participant.state.theirBigQCommitment = make(map[integration.IdentityKey]commitments.Commitment)
	for _, identity := range participant.cohortConfig.Participants {
		if identity == participant.myIdentityKey {
			continue
		}
		if input[identity] == nil {
			return nil, errs.NewFailed("no input from participant with shamir id %d", participant.idKeyToShamirId[identity])
		}
		participant.state.theirBigQCommitment[identity] = input[identity].BigQCommitment
	}

	participant.round++
	return &Round2Broadcast{
		BigQWitness:    participant.state.myBigQWitness,
		BigQPrimeProof: participant.state.myBigQPrimeProof,
		BigQBisProof:   participant.state.myBigQBisProof,
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

		bigQPrimeProofMessage, err := json.Marshal(input[identity].BigQPrimeProof)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot serialize dlog proof of Q'")
		}
		bigQBisProofMessage, err := json.Marshal(input[identity].BigQBisProof)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot serialize dlog proof of Q''")
		}
		bigQMessage := append(bigQPrimeProofMessage[:], bigQBisProofMessage...)
		if err := commitments.Open(commitmentHashFunc, bigQMessage, participant.state.theirBigQCommitment[identity], input[identity].BigQWitness); err != nil {
			return nil, errs.WrapFailed(err, "cannot open commitment")
		}

		bigQPrimeSessionId := append([]byte("backupQ'"), participant.sessionId...)
		if err := dlog.Verify(participant.cohortConfig.CipherSuite.Curve.NewGeneratorPoint(), input[identity].BigQPrimeProof, bigQPrimeSessionId, nil); err != nil {
			return nil, errs.WrapFailed(err, "cannot verify dlog proof of Q'")
		}
		bigQBisSessionId := append([]byte("backupQ''"), participant.sessionId...)
		if err := dlog.Verify(participant.cohortConfig.CipherSuite.Curve.NewGeneratorPoint(), input[identity].BigQBisProof, bigQBisSessionId, nil); err != nil {
			return nil, errs.WrapFailed(err, "cannot verify dlog proof of Q'")
		}

		theirBigQPrime := input[identity].BigQPrimeProof.Statement
		theirBigQBis := input[identity].BigQBisProof.Statement
		theirBigQ := theirBigQPrime.Add(theirBigQPrime).Add(theirBigQPrime).Add(theirBigQBis)
		if !theirBigQ.Equal(participant.publicKeyShares.SharesMap[identity]) {
			return nil, errs.NewVerificationFailed("public key share don't match")
		}

		participant.state.theirBigQPrime[identity] = theirBigQPrime
		participant.state.theirBigQBis[identity] = theirBigQBis
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
