package lpdl_test

import (
	"bytes"
	crand "crypto/rand"
	"io"
	"math/big"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/lpdl"
)

const paillierGroupNLen = 2048

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	prng := pcg.NewRandomised()
	sk, err := paillier.SampleSecretKey(paillierGroupNLen, prng)
	require.NoError(t, err)
	curve := p256.NewCurve()
	q := curve.Order()

	xNat := randomIntInRange(t, q.Big(), prng)

	xMessage, err := paillier.NewPlaintextFromNat(xNat, sk.Group().N())
	require.NoError(t, err)

	sf := curve.ScalarField()

	qSlice := make([]byte, sf.ElementSize())

	x, err := sf.FromBytes(xNat.Value().FillBytes(qSlice))
	require.NoError(t, err)

	bigQ := curve.ScalarBaseMul(x)
	xEncrypted, r, err := encryption.Encrypt(xMessage, sk, prng)
	require.NoError(t, err)

	err = doProof(t, x, bigQ, curve, xEncrypted, r, sk.Public(), sk, prng)
	require.NoError(t, err)
}

// xEncrypted is not a dlog of Q
func Test_FailVerificationOnFalseClaim(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	sk, err := paillier.SampleSecretKey(paillierGroupNLen, prng)
	require.NoError(t, err)
	curve := p256.NewCurve()
	q := curve.Order()

	x1Nat := randomIntInRange(t, q.Big(), prng)

	x1, err := curve.ScalarField().FromBytesBEReduce(x1Nat.BytesBE())
	require.NoError(t, err)

	x1Message, err := paillier.NewPlaintextFromNat(x1Nat, sk.Group().N())
	require.NoError(t, err)

	x2Nat := randomIntInRange(t, q.Big(), prng)
	x2, err := curve.ScalarField().FromBytesBEReduce(x2Nat.BytesBE())
	require.NoError(t, err)

	bigQ2 := curve.ScalarBaseMul(x2)
	x1Encrypted, r, err := encryption.Encrypt(x1Message, sk.Public(), prng)
	require.NoError(t, err)

	err = doProof(t, x1, bigQ2, curve, x1Encrypted, r, sk.Public(), sk, prng)
	require.Error(t, err)
}

// xEncrypted is not encryption of x
func Test_FailVerificationOnIncorrectDlog(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	sk, err := paillier.SampleSecretKey(paillierGroupNLen, prng)
	require.NoError(t, err)

	curve := p256.NewCurve()
	q := curve.Order()

	xNat := randomIntInRange(t, q.Big(), prng)

	x, err := curve.ScalarField().FromBytesBEReduce(xNat.Bytes())
	require.NoError(t, err)
	require.NoError(t, err)
	bigQ := curve.ScalarBaseMul(x)

	x2Int, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	x2IntNat, err := num.N().FromNatCT(numct.NewNatFromBig(x2Int.Cardinal().Big(), -1))
	require.NoError(t, err)
	x2Message, err := paillier.NewPlaintextFromNat(x2IntNat, sk.Group().N())
	require.NoError(t, err)

	x2Encrypted, r, err := encryption.Encrypt(x2Message, sk.Public(), prng)
	require.NoError(t, err)

	err = doProof(t, x, bigQ, curve, x2Encrypted, r, sk.Public(), sk, prng)
	require.Error(t, err)
}

func randomIntInRange(tb testing.TB, qBig *big.Int, prng io.Reader) *num.Nat {
	tb.Helper()
	q := new(saferith.Nat).SetBig(qBig, paillierGroupNLen)
	l := new(saferith.Nat).Div(q, saferith.ModulusFromUint64(3), paillierGroupNLen)
	xInt, err := crand.Int(prng, l.Big())
	require.NoError(tb, err)
	x := new(saferith.Nat).SetBig(xInt, paillierGroupNLen)
	out, err := num.N().FromNatCT(numct.NewNatFromSaferith(new(saferith.Nat).Add(l, x, paillierGroupNLen)))
	require.NoError(tb, err)
	return out
}

func doProof[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](tb testing.TB, x S, bigQ P, curve curves.Curve[P, B, S], xEncrypted *paillier.Ciphertext, r *paillier.Nonce, pk *paillier.PublicKey, sk *paillier.SecretKey, prng io.Reader) (err error) {
	tb.Helper()
	const proverID = 1
	const verifierID = 2
	quorum := hashset.NewComparable[sharing.ID](proverID, verifierID).Freeze()
	ctxs := session_testutils.MakeRandomContexts(tb, quorum, prng)

	verifier, err := lpdl.NewVerifier(ctxs[proverID], pk, bigQ, xEncrypted, prng)
	if err != nil {
		return err
	}

	prover, err := lpdl.NewProver(ctxs[verifierID], curve, sk, x, r, prng)
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
	proverBytes, err := ctxs[proverID].Transcript().ExtractBytes(label, base.ComputationalSecurityBytesCeil)
	if err != nil {
		return err
	}
	verifierBytes, err := ctxs[verifierID].Transcript().ExtractBytes(label, base.ComputationalSecurityBytesCeil)
	if err != nil {
		return err
	}
	if !bytes.Equal(proverBytes, verifierBytes) {
		return proofs.ErrFailed.WithMessage("transcript record different data")
	}

	return nil
}
