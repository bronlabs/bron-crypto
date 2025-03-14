package nthroots_test

import (
	"bytes"
	crand "crypto/rand"
	"math/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/modular"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/nthroots"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func Fuzz_Test(f *testing.F) {
	f.Add([]byte("sid"), int64(0))
	f.Fuzz(func(t *testing.T, sid []byte, randomSeed int64) {
		prng := rand.New(rand.NewSource(randomSeed))

		pInt, err := crand.Prime(prng, 128)
		require.NoError(t, err)
		p := new(saferith.Nat).SetBig(pInt, 128)
		qInt, err := crand.Prime(prng, 128)
		require.NoError(t, err)
		q := new(saferith.Nat).SetBig(qInt, 128)
		bigN, err := modular.NewCrtResidueParams(p, 1, q, 1)
		require.NoError(t, err)
		bigNSquared, err := modular.NewCrtResidueParams(p, 2, q, 2)
		require.NoError(t, err)
		protocol, err := nthroots.NewSigmaProtocol(bigN, bigNSquared, 1, prng)
		require.NoError(t, err)

		yInt, err := crand.Int(prng, bigN.GetModulus().Big())
		require.NoError(t, err)
		y := new(saferith.Nat).SetBig(yInt, 256)
		x := new(saferith.Nat).Exp(y, bigN.GetModulus().Nat(), bigNSquared.GetModulus())

		appLabel := "NthRoots"
		proverTranscript := hagrid.NewTranscript(appLabel, nil)
		prover, err := sigma.NewProver(sid, proverTranscript, protocol, []*saferith.Nat{x}, []*saferith.Nat{y})
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		verifierTranscript := hagrid.NewTranscript(appLabel, nil)
		verifier, err := sigma.NewVerifier(sid, verifierTranscript, protocol, []*saferith.Nat{x}, prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		r1, err := prover.Round1()
		require.NoError(t, err)
		r2, err := verifier.Round2(r1)
		require.NoError(t, err)
		r3, err := prover.Round3(r2)
		require.NoError(t, err)

		err = verifier.Verify(r3)
		require.NoError(t, err)

		label := "gimme, gimme"
		proverBytes, _ := proverTranscript.ExtractBytes(label, 128)
		verifierBytes, _ := verifierTranscript.ExtractBytes(label, 128)
		if !bytes.Equal(proverBytes, verifierBytes) {
			t.Fail()
		}
	})
}
