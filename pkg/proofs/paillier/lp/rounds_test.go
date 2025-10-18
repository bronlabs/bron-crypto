package lp_test

import (
	"bytes"
	crand "crypto/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/lp"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	prng := crand.Reader
	pInt, err := crand.Prime(prng, 512)
	require.NoError(t, err)
	pNat := numct.NewNatFromSaferith(new(saferith.Nat).SetBig(pInt, 512))
	qInt, err := crand.Prime(prng, 512)
	require.NoError(t, err)
	qNat := numct.NewNatFromSaferith(new(saferith.Nat).SetBig(qInt, 512))

	p, err := num.NPlus().FromNatCT(pNat)
	require.NoError(t, err)
	q, err := num.NPlus().FromNatCT(qNat)
	require.NoError(t, err)

	group, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	sk, err := paillier.NewPrivateKey(group)
	require.NoError(t, err)

	err = doProof(40, sk.PublicKey(), sk)
	require.NoError(t, err)
}

func doProof(k int, pk *paillier.PublicKey, sk *paillier.PrivateKey) (err error) {
	prng := crand.Reader
	sessionId, err := network.NewSID([]byte("lpSession"))
	if err != nil {
		return err
	}
	transcriptLabel := "LP"

	verifierTranscript := hagrid.NewTranscript(transcriptLabel)
	verifier, err := lp.NewVerifier(sessionId, k, pk, verifierTranscript, prng)
	if err != nil {
		return err
	}

	proverTranscript := hagrid.NewTranscript(transcriptLabel)
	prover, err := lp.NewProver(sessionId, k, sk, proverTranscript, prng)
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
