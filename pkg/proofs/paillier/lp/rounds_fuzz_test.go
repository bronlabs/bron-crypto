package lp_test

import (
	"bytes"
	crand "crypto/rand"
	"math/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/lp"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

func Fuzz_Test(f *testing.F) {
	f.Add(40, []byte("sid"), int64(0))
	f.Fuzz(func(t *testing.T, k int, sid []byte, randomSeed int64) {
		prng := rand.New(rand.NewSource(randomSeed))

		pInt, err := crand.Prime(prng, 256)
		require.NoError(t, err)
		p := new(saferith.Nat).SetBig(pInt, 256)
		qInt, err := crand.Prime(prng, 256)
		require.NoError(t, err)
		q := new(saferith.Nat).SetBig(qInt, 256)

		sk, err := paillier.NewSecretKey(p, q)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip(err.Error())
		}
		transcriptLabel := "LP"

		verifierTranscript := hagrid.NewTranscript(transcriptLabel, nil)
		verifier, err := lp.NewVerifier(k, &sk.PublicKey, sid, verifierTranscript, prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip(err.Error())
		}

		proverTranscript := hagrid.NewTranscript(transcriptLabel, nil)
		prover, err := lp.NewProver(k, sk, sid, proverTranscript, prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip(err.Error())
		}

		r1, err := verifier.Round1()
		require.NoError(t, err)

		r2, err := prover.Round2(r1)
		require.NoError(t, err)

		r3, err := verifier.Round3(r2)
		require.NoError(t, err)

		r4, err := prover.Round4(r3)
		require.NoError(t, err)

		err = verifier.Round5(r4)
		require.NoError(t, err)

		label := "gimme, gimme"
		proverBytes, _ := proverTranscript.ExtractBytes(label, 128)
		verifierBytes, _ := verifierTranscript.ExtractBytes(label, 128)
		if !bytes.Equal(proverBytes, verifierBytes) {
			require.Fail(t, "transcript record different data")
		}
	})
}
