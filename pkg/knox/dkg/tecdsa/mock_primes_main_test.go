package tecdsa_test

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	//safePrimeMocker := test_utils.NewSafePrimeMocker()
	//safePrimeMocker.Mock()

	code := m.Run()
	os.Exit(code)
}
