package dkg_test

import (
	"crypto/sha512"
	"hash"
	"os"
	"strconv"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"golang.org/x/crypto/sha3"
)

func TestRunProfile(t *testing.T) {
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
		curve = edwards25519.New()
	} else {
		curve = k256.New()
	}
	if os.Getenv("PROFILE_HASH") == "SHA3" {
		h = sha3.New256
	} else {
		h = sha512.New
	}
	for i := 0; i < 1000; i++ {
		testHappyPath(t, curve, h, th, n)
	}
}
