package lp_test

import (
	"bytes"
	crand "crypto/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/lp"
)

const paillierGroupNLen = 2048

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	pInt, err := crand.Prime(prng, paillierGroupNLen/2)
	require.NoError(t, err)
	pNat := numct.NewNatFromSaferith(new(saferith.Nat).SetBig(pInt, pInt.BitLen()))
	qInt, err := crand.Prime(prng, paillierGroupNLen/2)
	require.NoError(t, err)
	qNat := numct.NewNatFromSaferith(new(saferith.Nat).SetBig(qInt, qInt.BitLen()))

	p, err := num.NPlus().FromNatCT(pNat)
	require.NoError(t, err)
	q, err := num.NPlus().FromNatCT(qNat)
	require.NoError(t, err)

	group, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)

	sk, err := paillier.NewPrivateKey(group)
	require.NoError(t, err)

	err = doProof(t, 40, sk.PublicKey(), sk)
	require.NoError(t, err)
}

func doProof(tb testing.TB, k int, pk *paillier.PublicKey, sk *paillier.PrivateKey) (err error) {
	tb.Helper()

	prng := pcg.NewRandomised()
	const proverID = 1
	const verifierID = 2
	quorum := hashset.NewComparable[sharing.ID](proverID, verifierID).Freeze()

	ctxs := session_testutils.MakeRandomContexts(tb, quorum, prng)
	verifier, err := lp.NewVerifier(ctxs[verifierID], k, pk, prng)
	if err != nil {
		return err
	}

	prover, err := lp.NewProver(ctxs[proverID], k, sk, prng)
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
		return lp.ErrFailed.WithMessage("failed to extract bytes from prover transcript")
	}
	verifierBytes, err := ctxs[verifierID].Transcript().ExtractBytes(label, base.ComputationalSecurityBytesCeil)
	if err != nil {
		return lp.ErrFailed.WithMessage("failed to extract bytes from prover transcript")
	}
	if !bytes.Equal(proverBytes, verifierBytes) {
		return lp.ErrFailed.WithMessage("transcript record different data")
	}

	return nil
}
