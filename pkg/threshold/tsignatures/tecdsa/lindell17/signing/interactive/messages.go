package interactive_signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
)

var _ network.Message[types.Protocol] = (*Round1OutputP2P)(nil)
var _ network.Message[types.Protocol] = (*Round2OutputP2P)(nil)
var _ network.Message[types.Protocol] = (*Round3OutputP2P)(nil)
var _ network.Message[types.Protocol] = (*Round4OutputP2P)(nil)

type Round1OutputP2P struct {
	BigR1Commitment commitments.Commitment

	_ ds.Incomparable
}

type Round2OutputP2P struct {
	BigR2      curves.Point
	BigR2Proof compiler.NIZKPoKProof

	_ ds.Incomparable
}

type Round3OutputP2P struct {
	BigR1Witness commitments.Witness
	BigR1        curves.Point
	BigR1Proof   compiler.NIZKPoKProof

	_ ds.Incomparable
}

type Round4OutputP2P struct {
	C3 *paillier.CipherText

	_ ds.Incomparable
}

func (r1p2p *Round1OutputP2P) Validate(protocol types.Protocol) error {
	if r1p2p.BigR1Commitment == nil {
		return errs.NewIsNil("big r1 commitment")
	}
	return nil
}

func (r2p2p *Round2OutputP2P) Validate(protocol types.Protocol) error {
	if r2p2p.BigR2 == nil {
		return errs.NewIsNil("big r2")
	}
	if r2p2p.BigR2.Curve() != protocol.Curve() {
		return errs.NewCurve("big r2 curve %s does not match protocol curve %s", r2p2p.BigR2.Curve(), protocol.Curve())
	}
	if r2p2p.BigR2.IsIdentity() {
		return errs.NewIsIdentity("big r2")
	}
	if r2p2p.BigR2Proof == nil {
		return errs.NewIsNil("big r2 proof")
	}
	return nil
}

func (r3p2p *Round3OutputP2P) Validate(protocol types.Protocol) error {
	if r3p2p.BigR1Witness == nil {
		return errs.NewIsNil("big r1 witness")
	}
	if r3p2p.BigR1 == nil {
		return errs.NewIsNil("big r1")
	}
	if r3p2p.BigR1.Curve() != protocol.Curve() {
		return errs.NewCurve("big r1 curve %s does not match protocol curve %s", r3p2p.BigR1.Curve(), protocol.Curve())
	}
	if r3p2p.BigR1.IsIdentity() {
		return errs.NewIsIdentity("big r1")
	}
	if r3p2p.BigR1Proof == nil {
		return errs.NewIsNil("big r1 proof")
	}
	return nil
}

func (r4p2p *Round4OutputP2P) Validate(protocol types.Protocol) error {
	if r4p2p.C3 == nil {
		return errs.NewIsNil("c3")
	}
	return nil
}
