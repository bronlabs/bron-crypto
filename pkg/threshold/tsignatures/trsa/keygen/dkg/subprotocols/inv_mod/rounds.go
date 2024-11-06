package inv_mod

import (
	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/mul_two"
	"io"
	"math/big"
)

func (p *Participant) Round1() network.RoundMessages[types.ThresholdProtocol, *Round1P2P] {
	lambdaBitLen := p.PrimeLen*2 + base.ComputationalSecurity
	lambdaByteLen := (lambdaBitLen + 7) / 8
	lambdaBytes := make([]byte, lambdaByteLen)
	_, err := io.ReadFull(p.Prng, lambdaBytes)
	if err != nil {
		panic(err)
	}
	lambda := new(big.Int).SetBytes(lambdaBytes)
	lambdaShares, err := p.Dealer.Share(lambda, p.Prng)
	if err != nil {
		panic(err)
	}

	rBitLen := p.PrimeLen*4 + base.ComputationalSecurity*2
	rByteLen := (rBitLen + 7) / 8
	rBytes := make([]byte, rByteLen)
	_, err = io.ReadFull(p.Prng, rBytes)
	if err != nil {
		panic(err)
	}
	r := new(big.Int).SetBytes(rBytes)
	rShares, err := p.Dealer.Share(r, p.Prng)
	if err != nil {
		panic(err)
	}

	p2pOut := network.NewRoundMessages[types.ThresholdProtocol, *Round1P2P]()
	for sharingId, identity := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			p.State.rShare = rShares[sharingId]
			p.State.lambdaShare = lambdaShares[sharingId]
		} else {
			p2pOut.Put(identity, &Round1P2P{
				LambdaShare: lambdaShares[sharingId],
				RShare:      rShares[sharingId],
			})
		}
	}

	return p2pOut
}

func (p *Participant) Round2(e uint, phiShare *replicated.IntShare, p2pIn network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) network.RoundMessages[types.ThresholdProtocol, *Round2P2P] {
	for sharingId, identity := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(identity)
		p.State.rShare = p.State.rShare.Add(in.RShare)
		p.State.lambdaShare = p.State.lambdaShare.Add(in.LambdaShare)
	}

	p.State.e = e
	p.State.lambdaPhiMul = mul_two.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.BitLen(p.Dealer.GetBitLen()))
	r1Out := p.State.lambdaPhiMul.Round1(p.State.lambdaShare, phiShare)

	return r1Out
}

func (p *Participant) Round3(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round2P2P]) *Round3Broadcast {
	p.State.lambdaPhiShare = p.State.lambdaPhiMul.Round2(p2pIn)

	reShare := p.State.rShare.MulValue(big.NewInt(int64(p.State.e)))
	gammaShare := p.State.lambdaPhiShare.Add(reShare)

	p.State.gammaShare = gammaShare
	return &Round3Broadcast{
		GammaShare: gammaShare,
	}
}

func (p *Participant) Round4(bIn network.RoundMessages[types.ThresholdProtocol, *Round3Broadcast]) (*replicated.IntShare, bool) {
	gammaShares := []*replicated.IntShare{p.State.gammaShare}
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := bIn.Get(id)
		gammaShares = append(gammaShares, in.GammaShare)
	}

	gamma, err := p.Dealer.Reveal(gammaShares...)
	if err != nil {
		panic(err)
	}

	a := new(big.Int)
	b := new(big.Int)
	gcd := new(big.Int).GCD(a, b, gamma, big.NewInt(int64(p.State.e)))
	if gcd.Cmp(big.NewInt(1)) != 0 {
		return nil, false
	}

	dShare := p.State.rShare.MulValue(a).AddValue(b)
	return dShare, true
}
