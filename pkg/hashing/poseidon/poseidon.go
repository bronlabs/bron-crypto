package poseidon

// import (
// 	"hash"

// 	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
// 	"github.com/bronlabs/bron-crypto/pkg/base/errs"
// )

// var (
// 	_ hash.Hash = (*Poseidon)(nil)
// )

// type Poseidon struct {
// 	state  *state
// 	offset int
// }

// func NewKimchi() *Poseidon {
// 	return &Poseidon{
// 		state:  newInitialState(poseidonParamsKimchiFp),
// 		offset: 0,
// 	}
// }

// func NewLegacy() *Poseidon {
// 	return &Poseidon{
// 		state:  newInitialState(poseidonParamsLegacyFp),
// 		offset: 0,
// 	}
// }

// func NewLegacyHash() hash.Hash {
// 	return NewLegacy()
// }

// func (p *Poseidon) Rate() int {
// 	return p.state.parameters.rate
// }

// func (p *Poseidon) Update(xs ...*pasta.PallasBaseFieldElement) {
// 	if len(xs) == 0 {
// 		p.state.Permute()
// 		return
// 	}

// 	for range len(xs) % p.Rate() {
// 		xs = append(xs, pasta.NewPallasBaseField().Zero())
// 	}

// 	for blockIndex := 0; blockIndex < len(xs); blockIndex += p.Rate() {
// 		for i := range p.Rate() {
// 			p.state.v[i] = p.state.v[i].Add(xs[blockIndex+i])
// 		}
// 		p.state.Permute()
// 	}
// }

// func (p *Poseidon) Hash(xs ...*pasta.PallasBaseFieldElement) *pasta.PallasBaseFieldElement {
// 	p.state = newInitialState(p.state.parameters)
// 	p.Update(xs...)
// 	return p.Digest()
// }

// func (p *Poseidon) Digest() *pasta.PallasBaseFieldElement {
// 	return p.state.v[0]
// }

// func (p *Poseidon) Write(data []byte) (n int, err error) {
// 	if (len(data) % 32) != 0 {
// 		return 0, errs.NewHashing("data length must be multiple of 32")
// 	}

// 	elems := []*pasta.PallasBaseFieldElement{}
// 	for i := range (len(data) + 31) / 32 {
// 		bytes := data[32*i : 32*(i+1)]
// 		fe, err := pasta.NewPallasBaseField().FromBytes(bytes)
// 		if err != nil {
// 			return 0, errs.WrapHashing(err, "cannot create Pallas base field element")
// 		}
// 		elems = append(elems, fe)
// 	}
// 	p.Hash(elems...)
// 	return len(data), nil
// }

// func (p *Poseidon) Sum(data []byte) []byte {
// 	_, err := p.Write(data)
// 	if err != nil {
// 		panic(err)
// 	}
// 	return p.Digest().Bytes()
// }

// func (p *Poseidon) Reset() {
// 	p.state = newInitialState(p.state.parameters)
// }

// func (*Poseidon) Size() int {
// 	return 32
// }

// func (*Poseidon) BlockSize() int {
// 	return 32
// }

// // exp mutates f by computing x^3, x^5, x^7 or x^-1 as described in
// // https://eprint.iacr.org/2019/458.pdf page 8
// func exp(f *pasta.PallasBaseFieldElement, power int) *pasta.PallasBaseFieldElement {
// 	if power == 3 {
// 		f2 := f.Square()
// 		f3 := f.Mul(f2)
// 		return f3
// 	}
// 	if power == 5 {
// 		f2 := f.Square()
// 		f4 := f2.Square()
// 		f5 := f.Mul(f4)
// 		return f5
// 	}
// 	if power == 7 {
// 		f2 := f.Square()
// 		f4 := f2.Square()
// 		f6 := f2.Mul(f4)
// 		f7 := f.Mul(f6)
// 		return f7
// 	}
// 	if power == -1 {
// 		fInv, err := f.TryInv()
// 		if err != nil {
// 			return pasta.NewPallasBaseField().Zero()
// 		}
// 		return fInv
// 	}
// 	return pasta.NewPallasBaseField().Zero()
// }

// type state struct {
// 	v          []*pasta.PallasBaseFieldElement
// 	parameters *Parameters
// }

// func newInitialState(parameters *Parameters) *state {
// 	s := &state{
// 		v:          make([]*pasta.PallasBaseFieldElement, parameters.stateSize),
// 		parameters: parameters,
// 	}
// 	for i := range s.v {
// 		s.v[i] = pasta.NewPallasBaseField().Zero()
// 	}
// 	return s
// }

// // Permute from: https://github.com/o1-labs/o1js-bindings/blob/df8c87ed6804465f79196fdff84e5147ae71e92d/crypto/poseidon.ts#L125
// // Standard Poseidon (without "partial rounds") goes like this:
// //
// //	ARK_0 -> SBOX -> MDS
// //
// // -> ARK_1 -> SBOX -> MDS
// // -> ...
// // -> ARK_{rounds - 1} -> SBOX -> MDS
// //
// // where all computation operates on a vector of field elements, the "state", and
// // - ARK  ... add vector of round constants to the state, element-wise (different vector in each round)
// // - SBOX ... raise state to a power, element-wise
// // - MDS  ... multiply the state by a constant matrix (same matrix every round)
// // (these operations are done modulo p of course)
// //
// // For constraint efficiency reasons, in Mina's implementation the first round constant addition is left out
// // and is done at the end instead, so that effectively the order of operations in each iteration is rotated:
// //
// //	SBOX -> MDS -> ARK_0
// //
// // -> SBOX -> MDS -> ARK_1
// // -> ...
// // -> SBOX -> MDS -> ARK_{rounds - 1}
// //
// // If `hasInitialRoundConstant` is true, another ARK step is added at the beginning.
// //
// // See also Snarky.Sponge.Poseidon.block_cipher.
// func (s *state) Permute() {
// 	roundKeysOffset := 0
// 	if s.parameters.hashInitialRoundConstant {
// 		for i := range s.parameters.stateSize {
// 			s.v[i] = s.v[i].Add(s.parameters.roundConstants[0][i])
// 		}
// 		roundKeysOffset = 1
// 	}
// 	for round := range s.parameters.fullRounds {
// 		s.sbox()
// 		s.mds()
// 		s.ark(round, roundKeysOffset)
// 	}
// }

// func (s *state) sbox() {
// 	for i := range s.parameters.stateSize {
// 		s.v[i] = exp(s.v[i], s.parameters.power)
// 	}
// }

// func (s *state) mds() {
// 	state2 := newInitialState(s.parameters)
// 	for row := range s.parameters.stateSize {
// 		for col := range s.parameters.stateSize {
// 			state2.v[row] = state2.v[row].Add(s.v[col].Mul(s.parameters.mds[row][col]))
// 		}
// 	}
// 	for i, v2 := range state2.v { //nolint:gosimple // false positive
// 		s.v[i] = v2
// 	}
// }

// func (s *state) ark(round, offset int) {
// 	for i := range s.parameters.stateSize {
// 		s.v[i] = s.v[i].Add(s.parameters.roundConstants[round+offset][i])
// 	}
// }
