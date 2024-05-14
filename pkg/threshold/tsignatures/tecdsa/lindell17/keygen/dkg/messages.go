package dkg

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/lp"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/lpdl"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	hashvectorcommitments "github.com/copperexchange/krypton-primitives/pkg/vector_commitments/hash"
)

var _ network.Message[types.ThresholdProtocol] = (*Round1Broadcast)(nil)
var _ network.Message[types.ThresholdProtocol] = (*Round2Broadcast)(nil)
var _ network.Message[types.ThresholdProtocol] = (*Round3Broadcast)(nil)
var _ network.Message[types.ThresholdProtocol] = (*Round4P2P)(nil)
var _ network.Message[types.ThresholdProtocol] = (*Round5P2P)(nil)
var _ network.Message[types.ThresholdProtocol] = (*Round6P2P)(nil)
var _ network.Message[types.ThresholdProtocol] = (*Round7P2P)(nil)

type Round1Broadcast struct {
	BigQCommitment *hashvectorcommitments.VectorCommitment

	_ ds.Incomparable
}

type Round2Broadcast struct {
	BigQOpening          *hashvectorcommitments.Opening
	BigQPrime            curves.Point
	BigQPrimeProof       compiler.NIZKPoKProof
	BigQDoublePrime      curves.Point
	BigQDoublePrimeProof compiler.NIZKPoKProof

	_ ds.Incomparable
}

type Round3Broadcast struct {
	CKeyPrime         *paillier.CipherText
	CKeyDoublePrime   *paillier.CipherText
	PaillierPublicKey *paillier.PublicKey

	_ ds.Incomparable
}

type Round4P2P struct {
	LpRound1Output              *lp.Round1Output
	LpdlPrimeRound1Output       *lpdl.Round1Output
	LpdlDoublePrimeRound1Output *lpdl.Round1Output

	_ ds.Incomparable
}

type Round5P2P struct {
	LpRound2Output              *lp.Round2Output
	LpdlPrimeRound2Output       *lpdl.Round2Output
	LpdlDoublePrimeRound2Output *lpdl.Round2Output

	_ ds.Incomparable
}

type Round6P2P struct {
	LpRound3Output              *lp.Round3Output
	LpdlPrimeRound3Output       *lpdl.Round3Output
	LpdlDoublePrimeRound3Output *lpdl.Round3Output

	_ ds.Incomparable
}

type Round7P2P struct {
	LpRound4Output              *lp.Round4Output
	LpdlPrimeRound4Output       *lpdl.Round4Output
	LpdlDoublePrimeRound4Output *lpdl.Round4Output

	_ ds.Incomparable
}

func (r1b *Round1Broadcast) Validate(protocol types.ThresholdProtocol) error {
	if r1b.BigQCommitment == nil {
		return errs.NewIsNil("big q commitment")
	}
	return nil
}

func (r2b *Round2Broadcast) Validate(protocol types.ThresholdProtocol) error {
	if err := r2b.BigQOpening.Validate(); err != nil {
		return errs.WrapValidation(err, "could not validate opening")
	}
	if r2b.BigQPrime == nil {
		return errs.NewIsNil("big q prime")
	}
	if r2b.BigQPrime.Curve() != protocol.Curve() {
		return errs.NewCurve("big q prime curve %s does not match protocol curve %s", r2b.BigQPrime.Curve(), protocol.Curve())
	}
	if r2b.BigQPrime.IsAdditiveIdentity() {
		return errs.NewIsIdentity("big q prime")
	}
	if r2b.BigQPrimeProof == nil {
		return errs.NewIsNil("big q prime proof")
	}
	if r2b.BigQDoublePrime == nil {
		return errs.NewIsNil("big q double prime")
	}
	if r2b.BigQDoublePrime.Curve() != protocol.Curve() {
		return errs.NewCurve("big q double prime curve %s does not match protocol curve %s", r2b.BigQDoublePrime.Curve(), protocol.Curve())
	}
	if r2b.BigQDoublePrime.IsAdditiveIdentity() {
		return errs.NewIsIdentity("big q double prime")
	}
	if r2b.BigQDoublePrimeProof == nil {
		return errs.NewIsNil("big q double prime proof")
	}
	return nil
}

func (r3b *Round3Broadcast) Validate(protocol types.ThresholdProtocol) error {
	if r3b.CKeyPrime == nil {
		return errs.NewIsNil("c key prime")
	}
	if r3b.CKeyDoublePrime == nil {
		return errs.NewIsNil("c key double prime")
	}
	if r3b.PaillierPublicKey == nil {
		return errs.NewIsNil("paillier public key")
	}
	return nil
}

func (r4p2p *Round4P2P) Validate(protocol types.ThresholdProtocol) error {
	if r4p2p.LpRound1Output == nil {
		return errs.NewIsNil("lp round 1 output")
	}
	if r4p2p.LpdlPrimeRound1Output == nil {
		return errs.NewIsNil("lpdl prime round 1 output")
	}
	if r4p2p.LpdlDoublePrimeRound1Output == nil {
		return errs.NewIsNil("lpdl double prime round 1 output")
	}
	return nil
}

func (r5p2p *Round5P2P) Validate(protocol types.ThresholdProtocol) error {
	if r5p2p.LpRound2Output == nil {
		return errs.NewIsNil("lp round 2 output")
	}
	if r5p2p.LpdlPrimeRound2Output == nil {
		return errs.NewIsNil("lpdl prime round 2 output")
	}
	if r5p2p.LpdlDoublePrimeRound2Output == nil {
		return errs.NewIsNil("lpdl double prime round 2 output")
	}
	return nil
}

func (r6p2p *Round6P2P) Validate(protocol types.ThresholdProtocol) error {
	if r6p2p.LpRound3Output == nil {
		return errs.NewIsNil("lp round 3 output")
	}
	if r6p2p.LpdlPrimeRound3Output == nil {
		return errs.NewIsNil("lpdl prime round 3 output")
	}
	if r6p2p.LpdlDoublePrimeRound3Output == nil {
		return errs.NewIsNil("lpdl double prime round 3 output")
	}
	return nil
}

func (r7p2p *Round7P2P) Validate(protocol types.ThresholdProtocol) error {
	if r7p2p.LpRound4Output == nil {
		return errs.NewIsNil("lp round 4 output")
	}
	if r7p2p.LpdlPrimeRound4Output == nil {
		return errs.NewIsNil("lpdl prime round 4 output")
	}
	if r7p2p.LpdlDoublePrimeRound4Output == nil {
		return errs.NewIsNil("lpdl double prime round 4 output")
	}
	return nil
}
