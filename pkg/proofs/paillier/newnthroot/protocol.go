package newnthroot

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/proofs/internal/meta/newmaurer09"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const Name sigma.Name = "PAILLIER_NTH_ROOTS"

type (
	Witness    = newmaurer09.Witness[znstar.Unit]
	Statement  = newmaurer09.Statement[znstar.Unit]
	State      = newmaurer09.State[znstar.Unit]
	Commitment = newmaurer09.Commitment[znstar.Unit]
	Response   = newmaurer09.Response[znstar.Unit]
)

func NewWitness(w znstar.Unit) *Witness {
	return &Witness{W: w}
}

func NewStatement(x znstar.Unit) *Statement {
	return &Statement{X: x}
}

type Protocol struct {
	newmaurer09.Protocol[znstar.Unit, znstar.Unit]
}

func NewProtocol(group znstar.PaillierGroup, prng io.Reader) (*Protocol, error) {
	oneWayHomomorphism := func(x znstar.Unit) znstar.Unit {
		y, _ := group.LiftToNthResidues(x)
		return y
	}
	anc := &anchor{
		n: group.N().Nat(),
	}
	challengeBitLen := 256
	challengeByteLen := 256 / 8
	soundnessError := uint(challengeBitLen / 2)
	proto, err := newmaurer09.NewProtocol(challengeByteLen, soundnessError, Name, group, group, oneWayHomomorphism, anc, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create underlying Maurer09 protocol")
	}
	return &Protocol{*proto}, nil
}

type anchor struct {
	n *num.Nat
}

func (a *anchor) L() *num.Nat {
	return a.n
}

func (a *anchor) PreImage(x znstar.Unit) (w znstar.Unit) {
	return x
}
