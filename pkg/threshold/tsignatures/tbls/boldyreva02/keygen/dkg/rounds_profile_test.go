package dkg_test

import (
	"os"
	"strconv"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
)

func TestRunProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping profiling test in short mode")
	}
	if os.Getenv("PROFILE_TEST") == "" {
		t.Skip("skipping profiling test")
	}
	var curve curves.Curve
	th := 2
	n := 3
	if os.Getenv("PROFILE_T") != "" {
		th, _ = strconv.Atoi(os.Getenv("PROFILE_T"))
	}
	if os.Getenv("PROFILE_N") != "" {
		n, _ = strconv.Atoi(os.Getenv("PROFILE_N"))
	}
	if os.Getenv("IN_G1") == "true" {
		curve = bls12381.NewG1()
	} else {
		curve = bls12381.NewG2()
	}
	if curve.Name() == bls12381.NameG1 {
		for i := 0; i < 1; i++ {
			testHappyPath[bls.G1](t, th, n)
		}
	} else {
		for i := 0; i < 1; i++ {
			testHappyPath[bls.G2](t, th, n)
		}
	}
}
