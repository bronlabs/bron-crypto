package proofs_helpers

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dleq/new_chaum"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/batch_schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/new_schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	fiatShamir "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/fiat_shamir"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randomised_fischlin"
)

func NewFiatShamirSchnorr(base curves.Point, prng io.Reader) (compiler.NICompiler[new_schnorr.Statement, new_schnorr.Witness], error) {
	sigma, err := new_schnorr.NewSigmaProtocol(base, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Schnorr protocol")
	}

	fs, err := fiatShamir.NewCompiler(sigma)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create FiatShamir compiler")
	}

	return fs, nil
}

func NewFiatShamirBatchSchnorr(base curves.Point, prng io.Reader) (compiler.NICompiler[batch_schnorr.Statement, batch_schnorr.Witness], error) {
	sigma, err := batch_schnorr.NewSigmaProtocol(base, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Schnorr protocol")
	}

	fs, err := fiatShamir.NewCompiler(sigma)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Fiat-Shamir compiler")
	}

	return fs, nil
}

func NewFiatShamirChaumPedersen(g1, g2 curves.Point, prng io.Reader) (compiler.NICompiler[*new_chaum.Statement, new_chaum.Witness], error) {
	sigma, err := new_chaum.NewSigmaProtocol(g1, g2, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Schnorr protocol")
	}

	fs, err := fiatShamir.NewCompiler(sigma)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Fiat-Shamir compiler")
	}

	return fs, nil
}

func NewRandomisedFischlinSchnorr(base curves.Point, prng io.Reader) (compiler.NICompiler[new_schnorr.Statement, new_schnorr.Witness], error) {
	sigma, err := new_schnorr.NewSigmaProtocol(base, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Schnorr protocol")
	}

	rf, err := randomisedFischlin.NewCompiler(sigma, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Randomised Fischlin compiler")
	}

	return rf, nil
}

func NewRandomisedFischlinBatchSchnorr(base curves.Point, prng io.Reader) (compiler.NICompiler[batch_schnorr.Statement, batch_schnorr.Witness], error) {
	sigma, err := batch_schnorr.NewSigmaProtocol(base, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Schnorr protocol")
	}

	rf, err := randomisedFischlin.NewCompiler(sigma, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Randomised Fischlin compiler")
	}

	return rf, nil
}

func NewRandomisedFischlinChaumPedersen(g1, g2 curves.Point, prng io.Reader) (compiler.NICompiler[*new_chaum.Statement, new_chaum.Witness], error) {
	sigma, err := new_chaum.NewSigmaProtocol(g1, g2, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Schnorr protocol")
	}

	rf, err := randomisedFischlin.NewCompiler(sigma, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Randomised Fischlin compiler")
	}

	return rf, nil
}
