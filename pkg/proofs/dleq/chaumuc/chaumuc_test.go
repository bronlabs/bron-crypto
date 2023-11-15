package chaumuc_test

import (
	crand "crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dleq/chaumuc"
)

func doChaum(curve curves.Curve, sid []byte, prng io.Reader) error {
	prover, err := chaumuc.NewProver(sid[:], nil, prng)
	if err != nil {
		return err
	}
	x, err := curve.Scalar().Random(crand.Reader)
	if err != nil {
		return errs.WrapRandomSampleFailed(err, "failed to generate random scalar")
	}
	H1, err := curve.Point().Random(crand.Reader)
	if err != nil {
		return errs.WrapRandomSampleFailed(err, "failed to generate random point")
	}
	H2, err := curve.Point().Random(crand.Reader)
	if err != nil {
		return errs.WrapRandomSampleFailed(err, "failed to generate random point")
	}

	proof, statement, err := prover.Prove(x, H1, H2)
	if err != nil {
		return err
	}

	err = chaumuc.Verify(statement, proof, sid[:])
	if err != nil {
		return err
	}
	return nil
}

func TestZKPOverMultipleCurves(t *testing.T) {
	t.Parallel()
	uniqueSessionId := sha3.Sum256([]byte("random seed"))
	curveInstances := []curves.Curve{
		k256.New(),
		p256.New(),
		edwards25519.New(),
	}
	for _, curve := range curveInstances {
		boundedCurve := curve
		t.Run(fmt.Sprintf("running the test for curve %s", boundedCurve.Name()), func(t *testing.T) {
			t.Parallel()
			if testing.Short() && boundedCurve.Name() != k256.Name {
				t.Skip("only running the K256 curve in short mode")
			}
			err := doChaum(boundedCurve, uniqueSessionId[:], crand.Reader)
			require.NoError(t, err)
		})
	}
}

func TestNotVerifyZKPOverMultipleCurves(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip()
	}

	uniqueSessionId := sha3.Sum256([]byte("random seed"))
	curveInstances := []curves.Curve{
		k256.New(),
		p256.New(),
		edwards25519.New(),
	}
	for _, curve := range curveInstances {
		boundedCurve := curve
		t.Run(fmt.Sprintf("running the test for curve %s", boundedCurve.Name()), func(t *testing.T) {
			t.Parallel()
			prover, err := chaumuc.NewProver(uniqueSessionId[:], nil, crand.Reader)
			require.NoError(t, err)
			require.NotNil(t, prover)

			secret, err := boundedCurve.Scalar().Random(crand.Reader)
			require.NoError(t, err)
			H1, err := boundedCurve.Point().Random(crand.Reader)
			require.NoError(t, err)
			H2, err := boundedCurve.Point().Random(crand.Reader)
			require.NoError(t, err)
			proof, correctStatement, err := prover.Prove(secret, H1, H2)
			require.NoError(t, err)

			H3, err := boundedCurve.Point().Random(crand.Reader)
			require.False(t, H1.Equal(H3), "buy a lotter ticket")
			require.NoError(t, err)
			require.False(t, H2.Equal(H3), "buy a lotter ticket")

			P3 := H3.Mul(secret)

			t.Run("bad H1", func(t *testing.T) {
				t.Parallel()
				statement := &chaumuc.Statement{
					H1: H3,
					H2: H2,
					P1: correctStatement.P1,
					P2: correctStatement.P2,
				}
				err = chaumuc.Verify(statement, proof, uniqueSessionId[:])
				require.True(t, errs.IsVerificationFailed(err))
			})
			t.Run("bad H2", func(t *testing.T) {
				t.Parallel()
				statement := &chaumuc.Statement{
					H1: H1,
					H2: H3,
					P1: correctStatement.P1,
					P2: correctStatement.P2,
				}
				err = chaumuc.Verify(statement, proof, uniqueSessionId[:])
				require.True(t, errs.IsVerificationFailed(err))
			})
			t.Run("can't replace p1 in the proof", func(t *testing.T) {
				t.Parallel()
				statement := &chaumuc.Statement{
					H1: H3,
					H2: H2,
					P1: P3,
					P2: correctStatement.P2,
				}
				err = chaumuc.Verify(statement, proof, uniqueSessionId[:])
				require.True(t, errs.IsVerificationFailed(err))
			})
			t.Run("can't replace p2 in the proof", func(t *testing.T) {
				t.Parallel()
				statement := &chaumuc.Statement{
					H1: H1,
					H2: H3,
					P1: correctStatement.P1,
					P2: P3,
				}
				err = chaumuc.Verify(statement, proof, uniqueSessionId[:])
				require.True(t, errs.IsVerificationFailed(err))
			})
		})
	}
}
