package fuzz

import (
	"bytes"
	crand "crypto/rand"
	"math/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/paillierrange"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

func Fuzz_Test(f *testing.F) {
	f.Add([]byte("sid"), int64(0), uint64(3_000_000))
	f.Fuzz(func(t *testing.T, sid []byte, randomSeed int64, qNum uint64) {
		if len(sid) == 0 {
			return
		}

		prng := rand.New(rand.NewSource(randomSeed))

		pk, sk, err := paillier.NewKeys(256)
		require.NoError(t, err)
		q := new(saferith.Nat).SetUint64(qNum)
		l := new(saferith.Nat).Div(q, saferith.ModulusFromUint64(3), -1)
		xInt, err := crand.Int(prng, l.Big())
		require.NoError(t, err)
		x := new(saferith.Nat).SetBig(xInt, xInt.BitLen())

		xEncrypted, r, err := pk.Encrypt(x)
		require.NoError(t, err)

		appLabel := "Range"
		protocol := paillierrange.NewSigmaProtocol(40, q, prng)

		statement := &paillierrange.Statement{
			PaillierPublicKey: pk,
			CipherText:        xEncrypted,
		}
		witness := &paillierrange.Witness{
			PaillierSecretKey: sk,
			PlainText:         x,
			Nonce:             r,
		}
		verifierTranscript := hagrid.NewTranscript(appLabel, nil)
		verifier, err := sigma.NewVerifier(sid, verifierTranscript, protocol, statement, prng)
		if err != nil {
			require.NoError(t, err)
		}

		proverTranscript := hagrid.NewTranscript(appLabel, nil)
		prover, err := sigma.NewProver(sid, proverTranscript, protocol, statement, witness)
		if err != nil {
			require.NoError(t, err)
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
		proverBytes, _ := proverTranscript.ExtractBytes(label, base.ComputationalSecurity)
		verifierBytes, _ := verifierTranscript.ExtractBytes(label, base.ComputationalSecurity)
		if !bytes.Equal(proverBytes, verifierBytes) {
			t.Fail()
		}
	})
}
