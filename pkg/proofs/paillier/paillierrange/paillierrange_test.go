package paillierrange_test

import (
	crand "crypto/rand"
	"fmt"
	"io"
	"strconv"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/paillierrange"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/fiatshamir"
	compilerUtils "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler_utils"
)

func Test_HappyTest(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	primesBitLength := 128
	nIter := 128
	pk, sk, err := paillier.NewKeys(uint(primesBitLength))
	require.NoError(t, err)
	q := new(saferith.Nat).SetUint64(3_000_000)

	for i := 0; i < nIter; i++ {
		sid := append([]byte("sessionId_"), []byte(strconv.Itoa(i))...)
		x, err := randomIntInRange(q, prng)
		require.NoError(t, err)

		t.Run(fmt.Sprintf("in range %s", x.String()), func(t *testing.T) {
			t.Parallel()

			xEncrypted, r, err := pk.Encrypt(x)
			require.NoError(t, err)

			err = doProof(x, xEncrypted, r, q, pk, sk, sid, prng)
			require.NoError(t, err)
		})
	}
}

func Test_HappyPathNonInteractive(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	primesBitLength := 128
	nIter := 128
	pk, sk, err := paillier.NewKeys(uint(primesBitLength))
	require.NoError(t, err)
	q := new(saferith.Nat).SetUint64(3_000_000)

	for i := 0; i < nIter; i++ {
		sid := append([]byte("sessionId_"), []byte(strconv.Itoa(i))...)
		x, err := randomIntInRange(q, prng)
		require.NoError(t, err)

		t.Run(fmt.Sprintf("in range %s", x.String()), func(t *testing.T) {
			t.Parallel()

			xEncrypted, r, err := pk.Encrypt(x)
			require.NoError(t, err)

			witness := &paillierrange.Witness{
				PaillierSecretKey: sk,
				PlainText:         x,
				Nonce:             r,
			}
			statement := &paillierrange.Statement{
				PaillierPublicKey: pk,
				CipherText:        xEncrypted,
			}

			rangeProtocol := paillierrange.NewSigmaProtocol(80, q, prng)
			niRangeProtocol, err := compilerUtils.MakeNonInteractive(fiatshamir.Name, rangeProtocol, prng)
			require.NoError(t, err)

			prover, err := niRangeProtocol.NewProver(sid, nil)
			require.NoError(t, err)

			proof, err := prover.Prove(statement, witness)
			require.NoError(t, err)

			verifier, err := niRangeProtocol.NewVerifier(sid, nil)
			require.NoError(t, err)

			err = verifier.Verify(statement, proof)
			require.NoError(t, err)
		})
	}
}

func Test_Simulator(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	primesBitLength := 128
	nIter := 128
	pk, _, err := paillier.NewKeys(uint(primesBitLength))
	require.NoError(t, err)
	q := new(saferith.Nat).SetUint64(3_000_000)

	for i := 0; i < nIter; i++ {
		x, err := randomIntInRange(q, prng)
		require.NoError(t, err)

		xEncrypted, _, err := pk.Encrypt(x)
		require.NoError(t, err)

		statement := &paillierrange.Statement{
			PaillierPublicKey: pk,
			CipherText:        xEncrypted,
		}

		rangeProtocol := paillierrange.NewSigmaProtocol(80, q, prng)

		e := make([]byte, rangeProtocol.GetChallengeBytesLength())
		_, err = io.ReadFull(prng, e)
		require.NoError(t, err)

		a, z, err := rangeProtocol.RunSimulator(statement, e)
		require.NoError(t, err)

		err = rangeProtocol.Verify(statement, a, e, z)
		require.NoError(t, err)
	}
}

func doProof(x *saferith.Nat, xEncrypted *paillier.CipherText, r *saferith.Nat, q *saferith.Nat, pk *paillier.PublicKey, sk *paillier.SecretKey, sid []byte, prng io.Reader) error {
	sigmaProtocol := paillierrange.NewSigmaProtocol(80, q, prng)

	statement := &paillierrange.Statement{
		PaillierPublicKey: pk,
		CipherText:        xEncrypted,
	}
	witness := &paillierrange.Witness{
		PaillierSecretKey: sk,
		PlainText:         x,
		Nonce:             r,
	}

	prover, err := sigma.NewProver(sid, nil, sigmaProtocol, statement, witness)
	if err != nil {
		return err
	}

	verifier, err := sigma.NewVerifier(sid, nil, sigmaProtocol, statement, prng)
	if err != nil {
		return err
	}

	a, err := prover.Round1()
	if err != nil {
		return err
	}

	e, err := verifier.Round2(a)
	if err != nil {
		return err
	}

	z, err := prover.Round3(e)
	if err != nil {
		return err
	}

	return verifier.Verify(z)
}

func randomIntInRange(q *saferith.Nat, prng io.Reader) (*saferith.Nat, error) {
	l := new(saferith.Nat).Div(q, saferith.ModulusFromUint64(3), -1)
	xInt, err := crand.Int(prng, l.Big())
	if err != nil {
		return nil, err
	}

	return new(saferith.Nat).SetBig(xInt, 256), nil
}
