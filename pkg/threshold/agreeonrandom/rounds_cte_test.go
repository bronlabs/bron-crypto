package agreeonrandom_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
)

func Test_MeasureConstantTime(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	curve := k256.NewCurve()
	cipherSuite, _ := ttu.MakeSigningSuite(curve, sha3.New256)
	allIdentities, _ := ttu.MakeTestIdentities(cipherSuite, 3)

	internal.RunMeasurement(500, "agreeonrandom", func(i int) {
		allIdentities, _ = ttu.MakeTestIdentities(cipherSuite, 3)
	}, func() {
		testutils.RunAgreeOnRandom(curve, allIdentities, crand.Reader)
	})
}
