package fischlin_test

import (
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fischlin"
)

func _[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response]() {
	var (
		_ compiler.NonInteractiveProtocol[X, W] = (*fischlin.Protocol[X, W, A, S, Z])(nil)
		_ compiler.NIProver[X, W]               = (*fischlin.Prover[X, W, A, S, Z])(nil)
		_ compiler.NIVerifier[X]                = (*fischlin.Verifier[X, W, A, S, Z])(nil)
	)
}
