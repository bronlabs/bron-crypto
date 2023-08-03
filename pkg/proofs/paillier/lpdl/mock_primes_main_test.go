package lpdl_test

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration/test_utils"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	safePrimeMocker := test_utils.NewSafePrimeMocker()
	safePrimeMocker.Mock()

	code := m.Run()
	os.Exit(code)
}
