package noninteractive_signing_test

import (
	"crypto/sha512"
	"hash"
	"os"
	"strconv"
	"testing"

	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
)

func TestRunProfile(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping profiling test in short mode")
	}
	if os.Getenv("PROFILE_TEST") == "" {
		t.Skip("skipping profiling test")
	}
	var curve curves.Curve
	var h func() hash.Hash
	th := 2
	n := 3
	if os.Getenv("PROFILE_T") != "" {
		th, _ = strconv.Atoi(os.Getenv("PROFILE_T"))
	}
	if os.Getenv("PROFILE_N") != "" {
		n, _ = strconv.Atoi(os.Getenv("PROFILE_N"))
	}
	if os.Getenv("PROFILE_CURVE") == "ED25519" {
		curve = edwards25519.NewCurve()
	} else {
		curve = k256.NewCurve()
	}
	if os.Getenv("PROFILE_HASH") == "SHA3" {
		h = sha3.New256
	} else {
		h = sha512.New
	}
	for i := 0; i < 1000; i++ {
		testHappyPath(t, curve, h, th, n, 10, 0)
	}
}
