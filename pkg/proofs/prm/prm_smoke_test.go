package prm_test

import (
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/prm"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

func _() {
	var (
		_ sigma.Witness                                                                            = (*prm.Witness)(nil)
		_ sigma.Statement                                                                          = (*prm.Statement)(nil)
		_ sigma.Commitment                                                                         = (*prm.Commitment)(nil)
		_ sigma.State                                                                              = (*prm.State)(nil)
		_ sigma.Response                                                                           = (*prm.Response)(nil)
		_ sigma.Protocol[*prm.Statement, *prm.Witness, *prm.Commitment, *prm.State, *prm.Response] = (*prm.Protocol)(nil)
	)
}
