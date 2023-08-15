package nthroot_test

import (
	"bytes"
	crand "crypto/rand"
	"io"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/proofs/paillier/nthroot"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

func doProof(x, y, bigN *big.Int, prng io.Reader) (err error) {
	sessionId := []byte("nthRootSession")
	appLabel := "NthRoot"
	proverTranscript := hagrid.NewTranscript(appLabel)
	prover, err := nthroot.NewProver(bigN, x, y, sessionId, proverTranscript, prng)
	if err != nil {
		return err
	}
	verifierTranscript := hagrid.NewTranscript(appLabel)
	verifier, err := nthroot.NewVerifier(bigN, x, sessionId, verifierTranscript, prng)
	if err != nil {
		return err
	}

	r1, err := prover.Round1()
	if err != nil {
		return err
	}
	r2, err := verifier.Round2(r1)
	if err != nil {
		return err
	}
	r3, err := prover.Round3(r2)
	if err != nil {
		return err
	}

	err = verifier.Round4(r3)
	if err != nil {
		return err
	}

	label := "gimme, gimme"
	proverBytes := proverTranscript.ExtractBytes(label, 128)
	verifierBytes := verifierTranscript.ExtractBytes(label, 128)
	if !bytes.Equal(proverBytes, verifierBytes) {
		return errs.NewFailed("transcript record different data")
	}

	return nil
}

func Test_HappyPath(t *testing.T) {
	prng := crand.Reader
	p, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	q, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	bigN := new(big.Int).Mul(p, q)
	bigNSquared := new(big.Int).Mul(bigN, bigN)

	y, err := crand.Int(prng, bigN)
	require.NoError(t, err)
	x := new(big.Int).Exp(y, bigN, bigNSquared)

	err = doProof(x, y, bigN, prng)
	require.NoError(t, err)
}

func Test_InvalidRoot(t *testing.T) {
	prng := crand.Reader
	p, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	q, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	bigN := new(big.Int).Mul(p, q) // N = p * q
	nSquared := new(big.Int).Mul(bigN, bigN)

	y1, err := crand.Int(prng, bigN)
	require.NoError(t, err)
	x1 := new(big.Int).Exp(y1, bigN, nSquared)

	y2, err := crand.Int(prng, bigN)
	require.NoError(t, err)
	x2 := new(big.Int).Exp(y2, bigN, nSquared)

	err = doProof(x1, y2, bigN, prng)
	require.Error(t, err)
	require.True(t, errs.IsVerificationFailed(err))

	err = doProof(x2, y1, bigN, prng)
	require.Error(t, err)
	require.True(t, errs.IsVerificationFailed(err))
}
