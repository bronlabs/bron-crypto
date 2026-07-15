package fac_test

import (
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/fac"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

func _() {
	var (
		_ sigma.Witness                                                                            = (*fac.Witness)(nil)
		_ sigma.Statement                                                                          = (*fac.Statement)(nil)
		_ sigma.Commitment                                                                         = (*fac.Commitment)(nil)
		_ sigma.State                                                                              = (*fac.State)(nil)
		_ sigma.Response                                                                           = (*fac.Response)(nil)
		_ sigma.Protocol[*fac.Statement, *fac.Witness, *fac.Commitment, *fac.State, *fac.Response] = (*fac.Protocol)(nil)
	)
}
