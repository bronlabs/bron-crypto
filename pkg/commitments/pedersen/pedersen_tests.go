package pedersen_tests

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
)

func TestHappyPath(t *testing.T) {
	curve := k256.NewCurve()
	msg := curve.ScalarField().Random(crand.Reader)
	fmt.Println("message to commit to is:", msg)
	com, wit, err := PedersenCommitmentScheme.Commit([]byte(00000001), msg)
}
