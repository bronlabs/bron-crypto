package lpdl_test

import (
	"bytes"
	crand "crypto/rand"
	"io"
	"math/big"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/lpdl"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	prng := crand.Reader
	scheme := paillier.NewScheme()
	keygen, err := scheme.Keygen()
	require.NoError(t, err)

	sk, pk, err := keygen.Generate(prng)
	require.NoError(t, err)
	curve := p256.NewCurve()
	q := curve.Order()

	xNat, err := randomIntInRange(q.Big(), prng)
	require.NoError(t, err)

	ps := pk.PlaintextSpace()
	xMessage, err := ps.FromNat(xNat)
	require.NoError(t, err)

	sf := curve.ScalarField()

	qSlice := make([]byte, sf.ElementSize())

	x, err := sf.FromBytes(xNat.FillBytes(qSlice))
	require.NoError(t, err)

	senc, err := scheme.SelfEncrypter(sk)
	require.NoError(t, err)

	bigQ := curve.ScalarBaseMul(x)
	xEncrypted, r, err := senc.SelfEncrypt(xMessage, prng)
	require.NoError(t, err)

	sid, err := network.NewSID([]byte("sessionId"))
	require.NoError(t, err)
	err = doProof(x, bigQ, curve, xEncrypted, r, pk, sk, sid, prng)
	require.NoError(t, err)
}

// xEncrypted is not a dlog of Q
func Test_FailVerificationOnFalseClaim(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	scheme := paillier.NewScheme()
	keygen, err := scheme.Keygen(paillier.WithEachPrimeBitLen(1024))
	require.NoError(t, err)

	sk, pk, err := keygen.Generate(prng)
	require.NoError(t, err)
	curve := p256.NewCurve()
	q := curve.Order()

	x1Nat, err := randomIntInRange(q.Big(), prng)
	require.NoError(t, err)

	x1, err := curve.ScalarField().FromNumeric(x1Nat)
	require.NoError(t, err)

	ps := pk.PlaintextSpace()
	x1Message, err := ps.FromNat(x1Nat)
	require.NoError(t, err)

	x2Nat, err := randomIntInRange(q.Big(), prng)
	require.NoError(t, err)
	x2, err := curve.ScalarField().FromNumeric(x2Nat)
	require.NoError(t, err)

	enc, err := scheme.Encrypter()
	require.NoError(t, err)

	bigQ2 := curve.ScalarBaseMul(x2)
	x1Encrypted, r, err := enc.Encrypt(x1Message, pk, prng)
	require.NoError(t, err)

	sid, err := network.NewSID([]byte("sessionId"))
	require.NoError(t, err)
	err = doProof(x1, bigQ2, curve, x1Encrypted, r, pk, sk, sid, prng)
	require.Error(t, err)
}

// xEncrypted is not encryption of x
func Test_FailVerificationOnIncorrectDlog(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	scheme := paillier.NewScheme()
	keygen, err := scheme.Keygen(paillier.WithEachPrimeBitLen(1024))
	require.NoError(t, err)

	sk, pk, err := keygen.Generate(prng)
	require.NoError(t, err)
	curve := p256.NewCurve()
	q := curve.Order()

	xNat, err := randomIntInRange(q.Big(), prng)
	require.NoError(t, err)

	x, err := curve.ScalarField().FromNumeric(xNat)
	require.NoError(t, err)
	require.NoError(t, err)
	bigQ := curve.ScalarBaseMul(x)

	enc, err := scheme.Encrypter()
	require.NoError(t, err)

	ps := pk.PlaintextSpace()
	x2Int, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	x2IntNat := numct.NewNatFromBig(x2Int.Cardinal().Big(), -1)
	require.NoError(t, err)
	x2Message, err := ps.FromNat(x2IntNat)
	require.NoError(t, err)

	x2Encrypted, r, err := enc.Encrypt(x2Message, pk, prng)
	require.NoError(t, err)

	sid, err := network.NewSID([]byte("sessionId"))
	require.NoError(t, err)
	err = doProof(x, bigQ, curve, x2Encrypted, r, pk, sk, sid, prng)
	require.Error(t, err)
}

func randomIntInRange(qBig *big.Int, prng io.Reader) (*numct.Nat, error) {
	q := new(saferith.Nat).SetBig(qBig, 2048)
	l := new(saferith.Nat).Div(q, saferith.ModulusFromUint64(3), 2048)
	xInt, err := crand.Int(prng, l.Big())
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot sample integer")
	}
	x := new(saferith.Nat).SetBig(xInt, 2048)
	return (*numct.Nat)(new(saferith.Nat).Add(l, x, 2048)), nil
}

func doProof[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](x S, bigQ P, curve curves.Curve[P, B, S], xEncrypted *paillier.Ciphertext, r *paillier.Nonce, pk *paillier.PublicKey, sk *paillier.PrivateKey, sessionId network.SID, prng io.Reader) (err error) {
	transcriptLabel := "LPDL"

	verifierTranscript := hagrid.NewTranscript(transcriptLabel)
	verifier, err := lpdl.NewVerifier(sessionId, pk, bigQ, xEncrypted, verifierTranscript, prng)
	if err != nil {
		return err
	}

	proverTranscript := hagrid.NewTranscript(transcriptLabel)
	prover, err := lpdl.NewProver(sessionId, curve, sk, x, r, proverTranscript, prng)
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
		return err
	}
	verifierBytes, err := verifierTranscript.ExtractBytes(label, 128)
	if err != nil {
		return err
	}
	if !bytes.Equal(proverBytes, verifierBytes) {
		return errs.NewFailed("transcript record different data")
	}

	return nil
}
