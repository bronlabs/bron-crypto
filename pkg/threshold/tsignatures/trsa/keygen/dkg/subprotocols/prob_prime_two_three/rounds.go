package prob_prime_two_three

import (
	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/mul_two"
	"math/big"
)

func (p *Participant) Round1(aShare, bShare *replicated.IntShare) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round1P2P], gamma *big.Int) {
	p.State.aShare = aShare
	p.State.bShare = bShare
	one := big.NewInt(1)
	nMinusOne := new(big.Int).Sub(p.State.n, big.NewInt(1))

	var v *big.Int
	for {
		vByteLen := (p.State.n.BitLen() + base.ComputationalSecurity + 7) / 8
		vBytes, _ := p.Tape.ExtractBytes("MillerRabinWitness", uint(vByteLen))
		v = new(big.Int).SetBytes(vBytes)
		v.Mod(v, p.State.n)
		coprime := new(big.Int).GCD(nil, nil, p.State.n, v)
		if v.Cmp(nMinusOne) < 0 && v.Cmp(one) > 0 && coprime.Cmp(big.NewInt(1)) == 0 {
			break
		}
	}

	prevSharingId := (p.MySharingId-1+2)%3 + 1
	ai, _ := aShare.SubShares[replicated.NewSharingIdSetOf(prevSharingId)]
	exponent := new(big.Int).Rsh(ai, 1)
	gamma = new(big.Int).Exp(v, exponent, p.State.n)

	dealer, err := replicated.NewIntDealer(2, 3, replicated.Modulus(p.State.n))
	if err != nil {
		panic(err)
	}
	gammaShares, err := dealer.Share(gamma, p.Prng)
	if err != nil {
		panic(err)
	}

	p.State.gammaShares = make([]*replicated.IntShare, 3)
	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			p.State.gammaShares[sharingId-1] = gammaShares[sharingId]
		} else {
			p2pOut.Put(id, &Round1P2P{GammaShare: gammaShares[sharingId]})
		}
	}

	return p2pOut, gamma
}

func (p *Participant) Round2(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round2P2P]) {
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(id)
		p.State.gammaShares[sharingId-1] = in.GammaShare
	}

	p.State.gamma12Mul = mul_two.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.Modulus(p.State.n))
	mul12Out := p.State.gamma12Mul.Round1(p.State.gammaShares[0], p.State.gammaShares[1])

	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round2P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		m, _ := mul12Out.Get(id)
		p2pOut.Put(id, &Round2P2P{Mul12R1: m})
	}

	return p2pOut
}

func (p *Participant) Round3(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round2P2P]) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round3P2P]) {
	mul12R2In := network.NewRoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(id)
		mul12R2In.Put(id, in.Mul12R1)
	}

	gamma12Share := p.State.gamma12Mul.Round2(mul12R2In)
	p.State.gamma123Mul = mul_two.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.Modulus(p.State.n))
	mul123R1Out := p.State.gamma123Mul.Round1(gamma12Share, p.State.gammaShares[2])

	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round3P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		m, _ := mul123R1Out.Get(id)
		p2pOut.Put(id, &Round3P2P{Mul123R1: m})
	}

	return p2pOut
}

func (p *Participant) Round4(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round3P2P]) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round4P2P]) {
	mul123R1In := network.NewRoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(id)
		mul123R1In.Put(id, in.Mul123R1)
	}
	p.State.gammaShare = p.State.gamma123Mul.Round2(mul123R1In)

	nInvNom := new(big.Int)
	nInvNom.SetBit(nInvNom, 5*p.State.n.BitLen()/2+2, 1)
	nInvNom.Add(nInvNom, new(big.Int).Rsh(p.State.n, 1))
	nInv := new(big.Int).Div(nInvNom, p.State.n)

	aInvShare := p.State.bShare.MulValue(nInv)
	p.State.gammaAInvMul = mul_two.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.BitLen(3*uint(p.State.n.BitLen())+4))
	gammaAInvR1 := p.State.gammaAInvMul.Round1(p.State.gammaShare, aInvShare)

	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round4P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}

		m, _ := gammaAInvR1.Get(id)
		p2pOut.Put(id, &Round4P2P{MulGammaAInvR1: m})
	}

	return p2pOut
}

func (p *Participant) Round5(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round4P2P]) network.RoundMessages[types.ThresholdProtocol, *Round5P2P] {
	mulR1In := network.NewRoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(id)
		mulR1In.Put(id, in.MulGammaAInvR1)
	}

	gammaAInvShare := p.State.gammaAInvMul.Round2(mulR1In)
	// round
	for sharingIdSet, subShareValue := range gammaAInvShare.SubShares {
		gammaAInvShare.SubShares[sharingIdSet] = new(big.Int).Rsh(subShareValue, uint(5*p.State.n.BitLen()/2+2))
	}

	p.State.yMul = mul_two.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.BitLen(uint(p.State.n.BitLen()+4)))
	yMulR1 := p.State.yMul.Round1(gammaAInvShare, p.State.aShare)
	p2pOut := network.NewRoundMessages[types.ThresholdProtocol, *Round5P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		m, _ := yMulR1.Get(id)
		p2pOut.Put(id, &Round5P2P{YMulR1: m})
	}

	return p2pOut
}

func (p *Participant) Round6(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round5P2P]) network.RoundMessages[types.ThresholdProtocol, *Round6P2P] {
	yMulR1 := network.NewRoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		m, _ := p2pIn.Get(id)
		yMulR1.Put(id, m.YMulR1)
	}

	reducedGammaShare := p.State.yMul.Round2(yMulR1)
	yShare := p.State.gammaShare.Sub(reducedGammaShare)

	za := yShare.Sub(p.State.aShare).Sub(p.State.aShare).Sub(p.State.aShare).Sub(p.State.aShare).AddValue(big.NewInt(1)).Mod(ParamQ)
	zb := yShare.Sub(p.State.aShare).Sub(p.State.aShare).Sub(p.State.aShare).AddValue(big.NewInt(1)).Mod(ParamQ)
	zc := yShare.Sub(p.State.aShare).Sub(p.State.aShare).AddValue(big.NewInt(1)).Mod(ParamQ)
	zd := yShare.Sub(p.State.aShare).AddValue(big.NewInt(1)).Mod(ParamQ)
	ze := yShare.AddValue(big.NewInt(1)).Mod(ParamQ)
	zf := yShare.Add(p.State.aShare).AddValue(big.NewInt(1)).Mod(ParamQ)
	zg := yShare.Add(p.State.aShare).Add(p.State.aShare).AddValue(big.NewInt(1)).Mod(ParamQ)
	zh := yShare.Add(p.State.aShare).Add(p.State.aShare).Add(p.State.aShare).AddValue(big.NewInt(1)).Mod(ParamQ)
	zi := yShare.Add(p.State.aShare).Add(p.State.aShare).Add(p.State.aShare).Add(p.State.aShare).AddValue(big.NewInt(1)).Mod(ParamQ)

	zj := yShare.Sub(p.State.aShare).Sub(p.State.aShare).Sub(p.State.aShare).Sub(p.State.aShare).SubValue(big.NewInt(1)).Mod(ParamQ)
	zk := yShare.Sub(p.State.aShare).Sub(p.State.aShare).Sub(p.State.aShare).SubValue(big.NewInt(1)).Mod(ParamQ)
	zl := yShare.Sub(p.State.aShare).Sub(p.State.aShare).SubValue(big.NewInt(1)).Mod(ParamQ)
	zm := yShare.Sub(p.State.aShare).SubValue(big.NewInt(1)).Mod(ParamQ)
	zn := yShare.SubValue(big.NewInt(1)).Mod(ParamQ)
	zo := yShare.Add(p.State.aShare).SubValue(big.NewInt(1)).Mod(ParamQ)
	zp := yShare.Add(p.State.aShare).Add(p.State.aShare).SubValue(big.NewInt(1)).Mod(ParamQ)
	zq := yShare.Add(p.State.aShare).Add(p.State.aShare).Add(p.State.aShare).SubValue(big.NewInt(1)).Mod(ParamQ)
	zr := yShare.Add(p.State.aShare).Add(p.State.aShare).Add(p.State.aShare).Add(p.State.aShare).SubValue(big.NewInt(1)).Mod(ParamQ)

	p.State.abMul = mul_two.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.Modulus(ParamQ))
	abR1 := p.State.abMul.Round1(za, zb)
	p.State.cdMul = mul_two.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.Modulus(ParamQ))
	cdR1 := p.State.cdMul.Round1(zc, zd)
	p.State.efMul = mul_two.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.Modulus(ParamQ))
	efR1 := p.State.efMul.Round1(ze, zf)
	p.State.ghMul = mul_two.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.Modulus(ParamQ))
	ghR1 := p.State.ghMul.Round1(zg, zh)
	p.State.ijMul = mul_two.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.Modulus(ParamQ))
	ijR1 := p.State.ijMul.Round1(zi, zj)
	p.State.klMul = mul_two.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.Modulus(ParamQ))
	klR1 := p.State.klMul.Round1(zk, zl)
	p.State.mnMul = mul_two.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.Modulus(ParamQ))
	mnR1 := p.State.mnMul.Round1(zm, zn)
	p.State.opMul = mul_two.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.Modulus(ParamQ))
	opR1 := p.State.opMul.Round1(zo, zp)
	p.State.qrMul = mul_two.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.Modulus(ParamQ))
	qrR1 := p.State.qrMul.Round1(zq, zr)

	p2pOut := network.NewRoundMessages[types.ThresholdProtocol, *Round6P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		out := &Round6P2P{}
		out.ABMulR1, _ = abR1.Get(id)
		out.CDMulR1, _ = cdR1.Get(id)
		out.EFMulR1, _ = efR1.Get(id)
		out.GHMulR1, _ = ghR1.Get(id)
		out.IJMulR1, _ = ijR1.Get(id)
		out.KLMulR1, _ = klR1.Get(id)
		out.MNMulR1, _ = mnR1.Get(id)
		out.OPMulR1, _ = opR1.Get(id)
		out.QRMulR1, _ = qrR1.Get(id)
		p2pOut.Put(id, out)
	}

	return p2pOut
}

func (p *Participant) Round7(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round6P2P]) network.RoundMessages[types.ThresholdProtocol, *Round7P2P] {
	abR1 := network.NewRoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P]()
	cdR1 := network.NewRoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P]()
	efR1 := network.NewRoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P]()
	ghR1 := network.NewRoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P]()
	ijR1 := network.NewRoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P]()
	klR1 := network.NewRoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P]()
	mnR1 := network.NewRoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P]()
	opR1 := network.NewRoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P]()
	qrR1 := network.NewRoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(id)
		abR1.Put(id, in.ABMulR1)
		cdR1.Put(id, in.CDMulR1)
		efR1.Put(id, in.EFMulR1)
		ghR1.Put(id, in.GHMulR1)
		ijR1.Put(id, in.IJMulR1)
		klR1.Put(id, in.KLMulR1)
		mnR1.Put(id, in.MNMulR1)
		opR1.Put(id, in.OPMulR1)
		qrR1.Put(id, in.QRMulR1)
	}

	zab := p.State.abMul.Round2(abR1)
	zcd := p.State.cdMul.Round2(cdR1)
	zef := p.State.efMul.Round2(efR1)
	zgh := p.State.ghMul.Round2(ghR1)
	zij := p.State.ijMul.Round2(ijR1)
	zkl := p.State.klMul.Round2(klR1)
	zmn := p.State.mnMul.Round2(mnR1)
	zop := p.State.opMul.Round2(opR1)
	zqr := p.State.qrMul.Round2(qrR1)

	p.State.abcdMul = mul_two.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.Modulus(ParamQ))
	abcdR1 := p.State.abcdMul.Round1(zab, zcd)
	p.State.efghMul = mul_two.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.Modulus(ParamQ))
	efghR1 := p.State.efghMul.Round1(zef, zgh)
	p.State.ijklMul = mul_two.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.Modulus(ParamQ))
	ijklR1 := p.State.ijklMul.Round1(zij, zkl)
	p.State.mnopMul = mul_two.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.Modulus(ParamQ))
	mnopR1 := p.State.mnopMul.Round1(zmn, zop)
	p.State.zQR = zqr

	p2pOut := network.NewRoundMessages[types.ThresholdProtocol, *Round7P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		out := &Round7P2P{}
		out.ABCDMulR1, _ = abcdR1.Get(id)
		out.EFGHMulR1, _ = efghR1.Get(id)
		out.IJKLMulR1, _ = ijklR1.Get(id)
		out.MNOPMulR1, _ = mnopR1.Get(id)
		p2pOut.Put(id, out)
	}

	return p2pOut
}

func (p *Participant) Round8(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round7P2P]) network.RoundMessages[types.ThresholdProtocol, *Round8P2P] {
	abcdR1 := network.NewRoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P]()
	efghR1 := network.NewRoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P]()
	ijklR1 := network.NewRoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P]()
	mnopR1 := network.NewRoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(id)
		abcdR1.Put(id, in.ABCDMulR1)
		efghR1.Put(id, in.EFGHMulR1)
		ijklR1.Put(id, in.IJKLMulR1)
		mnopR1.Put(id, in.MNOPMulR1)
	}

	zabcd := p.State.abcdMul.Round2(abcdR1)
	zefgh := p.State.efghMul.Round2(efghR1)
	zijkl := p.State.ijklMul.Round2(ijklR1)
	zmnop := p.State.mnopMul.Round2(mnopR1)

	p.State.abcdefghMul = mul_two.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.Modulus(ParamQ))
	abcdefghR1 := p.State.abcdefghMul.Round1(zabcd, zefgh)
	p.State.ijklmnopMul = mul_two.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.Modulus(ParamQ))
	ijklmnopR1 := p.State.ijklmnopMul.Round1(zijkl, zmnop)

	p2pOut := network.NewRoundMessages[types.ThresholdProtocol, *Round8P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		out := &Round8P2P{}
		out.ABCDEFGHMulR1, _ = abcdefghR1.Get(id)
		out.IJKLMNOPMulR1, _ = ijklmnopR1.Get(id)
		p2pOut.Put(id, out)
	}

	return p2pOut
}

func (p *Participant) Round9(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round8P2P]) network.RoundMessages[types.ThresholdProtocol, *Round9P2P] {
	abcdefghR1 := network.NewRoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P]()
	ijklmnopR1 := network.NewRoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(id)
		abcdefghR1.Put(id, in.ABCDEFGHMulR1)
		ijklmnopR1.Put(id, in.IJKLMNOPMulR1)
	}

	zabcdefgh := p.State.abcdefghMul.Round2(abcdefghR1)
	zijklmnop := p.State.ijklmnopMul.Round2(ijklmnopR1)

	p.State.abcdefghijklmnopMul = mul_two.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.Modulus(ParamQ))
	abcdefghijklmnopR1 := p.State.abcdefghijklmnopMul.Round1(zabcdefgh, zijklmnop)

	p2pOut := network.NewRoundMessages[types.ThresholdProtocol, *Round9P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		out := &Round9P2P{}
		out.ABCDEFGHIJKLMNOPMulR1, _ = abcdefghijklmnopR1.Get(id)
		p2pOut.Put(id, out)
	}

	return p2pOut
}

func (p *Participant) Round10(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round9P2P]) network.RoundMessages[types.ThresholdProtocol, *Round10P2P] {
	abcdefghijklmnopR1 := network.NewRoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(id)
		abcdefghijklmnopR1.Put(id, in.ABCDEFGHIJKLMNOPMulR1)
	}

	zabcdefghijklmnop := p.State.abcdefghijklmnopMul.Round2(abcdefghijklmnopR1)

	p.State.abcdefghijklmnopqrMul = mul_two.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.Modulus(ParamQ))
	abcdefghijklmnopqrR1 := p.State.abcdefghijklmnopqrMul.Round1(zabcdefghijklmnop, p.State.zQR)

	p2pOut := network.NewRoundMessages[types.ThresholdProtocol, *Round10P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		out := &Round10P2P{}
		out.ABCDEFGHIJKLMNOPQRMulR1, _ = abcdefghijklmnopqrR1.Get(id)
		p2pOut.Put(id, out)
	}

	return p2pOut
}

func (p *Participant) Round11(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round10P2P]) *Round11Broadcast {
	abcdefghijklmnopqrR1 := network.NewRoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(id)
		abcdefghijklmnopqrR1.Put(id, in.ABCDEFGHIJKLMNOPQRMulR1)
	}

	p.State.zShare = p.State.abcdefghijklmnopqrMul.Round2(abcdefghijklmnopqrR1).Mod(ParamQ)

	return &Round11Broadcast{ZShare: p.State.zShare}
}

func (p *Participant) Round12(bIn network.RoundMessages[types.ThresholdProtocol, *Round11Broadcast]) bool {
	zShares := []*replicated.IntShare{p.State.zShare}
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := bIn.Get(id)
		zShares = append(zShares, in.ZShare)
	}

	dealer, err := replicated.NewIntDealer(2, 3, replicated.Modulus(ParamQ))
	if err != nil {
		panic(err)
	}
	z, err := dealer.Reveal(zShares...)
	if err != nil {
		panic(err)
	}
	z.Mod(z, ParamQ)

	return z.Cmp(big.NewInt(0)) == 0
}
