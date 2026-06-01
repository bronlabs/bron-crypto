package blummod_test

import (
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/blummod"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

var (
	_ sigma.Witness                                                                                                = (*blummod.Witness)(nil)
	_ sigma.Statement                                                                                              = (*blummod.Statement)(nil)
	_ sigma.Commitment                                                                                             = (*blummod.Commitment)(nil)
	_ sigma.State                                                                                                  = (*blummod.State)(nil)
	_ sigma.Response                                                                                               = (*blummod.Response)(nil)
	_ sigma.Protocol[*blummod.Statement, *blummod.Witness, *blummod.Commitment, *blummod.State, *blummod.Response] = (*blummod.Protocol)(nil)
)
