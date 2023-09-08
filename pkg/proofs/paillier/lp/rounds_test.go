package lp_test

import (
	"bytes"
	crand "crypto/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/base/errs"
	"github.com/copperexchange/knox-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/knox-primitives/pkg/proofs/paillier/lp"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

func doProof(k int, pk *paillier.PublicKey, sk *paillier.SecretKey) (err error) {
	prng := crand.Reader
	sessionId := []byte("lpSession")
	transcriptLabel := "LP"

	verifierTranscript := hagrid.NewTranscript(transcriptLabel)
	verifier, err := lp.NewVerifier(k, pk, sessionId, verifierTranscript, prng)
	if err != nil {
		return err
	}

	proverTranscript := hagrid.NewTranscript(transcriptLabel)
	prover, err := lp.NewProver(k, sk, sessionId, proverTranscript, prng)
	if err != nil {
		return err
	}

	r1, err := verifier.Round1()
	if err != nil {
		return err
	}

	r2, err := prover.Round2(r1)
	if err != nil {
		return err
	}

	r3, err := verifier.Round3(r2)
	if err != nil {
		return err
	}

	r4, err := prover.Round4(r3)
	if err != nil {
		return err
	}

	err = verifier.Round5(r4)
	if err != nil {
		return err
	}

	label := "gimme, gimme"
	proverBytes, err := proverTranscript.ExtractBytes(label, 128)
	if err != nil {
		return errs.NewFailed("failed to extract bytes from prover transcript")
	}
	verifierBytes, err := verifierTranscript.ExtractBytes(label, 128)
	if err != nil {
		return errs.NewFailed("failed to extract bytes from prover transcript")
	}
	if !bytes.Equal(proverBytes, verifierBytes) {
		return errs.NewFailed("transcript record different data")
	}

	return nil
}

func Test_HappyPath(t *testing.T) {
	prng := crand.Reader
	pInt, err := crand.Prime(prng, 512)
	require.NoError(t, err)
	p := new(saferith.Nat).SetBig(pInt, 512)
	qInt, err := crand.Prime(prng, 512)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qInt, 512)

	sk, err := paillier.NewSecretKey(p, q)
	require.NoError(t, err)

	err = doProof(40, &sk.PublicKey, sk)
	require.NoError(t, err)
}

func Test_IncorrectPublicKey(t *testing.T) {
	prng := crand.Reader
	p1Int, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	p1 := new(saferith.Nat).SetBig(p1Int, 128)
	p2Int, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	p2 := new(saferith.Nat).SetBig(p2Int, 128)
	qInt, err := crand.Prime(prng, 256)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qInt, 256)

	// p is not a prime number
	p := new(saferith.Nat).Mul(p1, p2, 256)
	sk, err := paillier.NewSecretKey(p, q)
	require.NoError(t, err)

	err = doProof(128, &sk.PublicKey, sk)
	require.Error(t, err)
	require.True(t, errs.IsInvalidArgument(err))
}
