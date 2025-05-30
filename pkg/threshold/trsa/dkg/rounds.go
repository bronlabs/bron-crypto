package dkg

import (
	"crypto/rsa"
	"encoding/binary"
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/rep23"
	"github.com/bronlabs/bron-crypto/pkg/threshold/trsa"
)

const (
	n1Label = "BRON_CRYPTO_TRSA_DKG-N1-"
	n2Label = "BRON_CRYPTO_TRSA_DKG-N2-"
	eLabel  = "BRON_CRYPTO_TRSA_DKG-E-"
)

func (p *Participant) Round1() (*Round1Broadcast, network.RoundMessages[types.ThresholdProtocol, *Round1P2P], error) {
	var ok bool

	// steps: 2, 3, 4
	rsaKey, err := rsa.GenerateKey(p.Prng, trsa.RsaBitLen/2)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to generate RSA key")
	}
	if rsaKey.E != trsa.RsaE {
		return nil, nil, errs.NewValidation("wrong RSA E value")
	}

	// step 5
	dealer := rep23.NewIntScheme()
	dShares, err := dealer.Deal(new(saferith.Int).SetBig(rsaKey.D, trsa.RsaBitLen/2), p.Prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to deal shares")
	}

	// step 6
	p2pOut := network.NewRoundMessages[types.ThresholdProtocol, *Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}

		p2p := &Round1P2P{}
		if p.MySharingId == 1 || p.MySharingId == 2 {
			p2p.DShare, ok = dShares[sharingId]
			if !ok {
				return nil, nil, errs.NewFailed("share not found")
			}
		}
		p2pOut.Put(id, p2p)
	}

	// steps: 7, 8, 9
	bOut := &Round1Broadcast{}
	switch p.MySharingId {
	case 1:
		p.State.N1 = saferith.ModulusFromBytes(rsaKey.N.Bytes())
		p.State.DShares1 = dShares
		p.State.DShares2 = make(map[types.SharingID]*rep23.IntShare)
		bOut.N = p.State.N1.Nat()
		bOut.Pi, err = proveCD(p.Tape, p.State.DShares1, p.State.N1)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "failed to prove cd")
		}
	case 2:
		p.State.N2 = saferith.ModulusFromBytes(rsaKey.N.Bytes())
		p.State.DShares1 = make(map[types.SharingID]*rep23.IntShare)
		p.State.DShares2 = dShares
		bOut.N = p.State.N2.Nat()
		bOut.Pi, err = proveCD(p.Tape, p.State.DShares2, p.State.N2)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "failed to prove cd")
		}
	default:
		p.State.DShares1 = make(map[types.SharingID]*rep23.IntShare)
		p.State.DShares2 = make(map[types.SharingID]*rep23.IntShare)
	}

	return bOut, p2pOut, nil
}

func (p *Participant) Round2(bIn network.RoundMessages[types.ThresholdProtocol, *Round1Broadcast], p2pIn network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) (*rsa.PublicKey, *trsa.Shard, error) {
	// step 1
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}

		p2p, ok := p2pIn.Get(id)
		if !ok {
			return nil, nil, errs.NewFailed("p2p message not found")
		}
		b, ok := bIn.Get(id)
		if !ok {
			return nil, nil, errs.NewFailed("b message not found")
		}

		// steps: 2, 3, 4, 5, 6, 7
		switch sharingId {
		case 1:
			p.State.N1 = saferith.ModulusFromNat(b.N)
			p.State.DShares1[p.MySharingId] = p2p.DShare
			err := verifyCD(p.Tape, b.Pi, p.State.N1, p.State.DShares1[p.MySharingId])
			if err != nil {
				return nil, nil, errs.WrapIdentifiableAbort(err, id.PublicKey().ToAffineCompressed(), "invalid shares")
			}
		case 2:
			p.State.N2 = saferith.ModulusFromNat(b.N)
			p.State.DShares2[p.MySharingId] = p2p.DShare
			err := verifyCD(p.Tape, b.Pi, p.State.N2, p.State.DShares2[p.MySharingId])
			if err != nil {
				return nil, nil, errs.WrapIdentifiableAbort(err, id.PublicKey().ToAffineCompressed(), "invalid shares")
			}
		}
	}

	one := big.NewInt(1)
	gcd := new(big.Int).GCD(nil, nil, p.State.N1.Big(), p.State.N2.Big())
	if gcd.Cmp(one) != 0 {
		return nil, nil, errs.NewFailed("invalid moduli")
	}

	p.Tape.AppendMessages(n1Label, p.State.N1.Bytes())
	p.Tape.AppendMessages(n2Label, p.State.N2.Bytes())
	p.Tape.AppendMessages(eLabel, binary.BigEndian.AppendUint64(nil, trsa.RsaE))

	// step 8
	publicKey := &rsa.PublicKey{
		N: new(big.Int).Mul(p.State.N1.Big(), p.State.N2.Big()),
		E: trsa.RsaE,
	}

	shard := &trsa.Shard{
		PublicShard: trsa.PublicShard{
			N1: p.State.N1,
			N2: p.State.N2,
			E:  trsa.RsaE,
		},
		D1Share: p.State.DShares1[p.MySharingId],
		D2Share: p.State.DShares2[p.MySharingId],
	}

	return publicKey, shard, nil
}
