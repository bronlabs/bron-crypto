package pedersen

import (
	"io"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
)

const Name commitments.Name = "pedersen"

type (
	Group[E GroupElement[E, S], S Scalar[S]]                     = algebra.PrimeGroup[E, S]
	GroupElement[E algebra.PrimeGroupElement[E, S], S Scalar[S]] = algebra.PrimeGroupElement[E, S]

	ScalarField[S Scalar[S]] interface {
		algebra.PrimeField[S]
		algebra.FiniteStructure[S]
	}
	Scalar[S algebra.PrimeFieldElement[S]] algebra.PrimeFieldElement[S]
)

type (
	Key[E GroupElement[E, S], S Scalar[S]] struct {
		g     E
		h     E
		group Group[E, S]
		sf    ScalarField[S]
	}
	Commitment[E GroupElement[E, S], S Scalar[S]] struct {
		v E
	}
	Message[S Scalar[S]] struct {
		v S
	}

	Witness[S Scalar[S]] struct {
		v S
	}
)

func NewScheme[E GroupElement[E, S], S Scalar[S]](key *Key[E, S]) (commitments.HomomorphicScheme[*Witness[S], S, *Message[S], S, *Commitment[E, S], E], error) {
	if key == nil {
		return nil, errs.NewIsNil("key cannot be nil")
	}
	return &Scheme[E, S]{key: key, witnessLength: key.sf.ElementSize()}, nil
}

type Scheme[E GroupElement[E, S], S Scalar[S]] struct {
	key           *Key[E, S]
	witnessLength int
}

func (s *Scheme[_, _]) Name() commitments.Name {
	return Name
}

func (s *Scheme[E, S]) Committer() commitments.Committer[*Witness[S], *Message[S], *Commitment[E, S]] {
	return &Committer[E, S]{
		key:           s.key,
		witnessLength: s.witnessLength,
	}
}

func (s *Scheme[E, S]) Verifier() commitments.Verifier[*Witness[S], *Message[S], *Commitment[E, S]] {
	committingParty := &Committer[E, S]{
		key:           s.key,
		witnessLength: s.witnessLength,
	}
	generic := commitments.NewGenericVerifier(committingParty, func(c1, c2 *Commitment[E, S]) bool {
		return c1.Equal(c2)
	})
	out := &Verifier[E, S]{GenericVerifier: *generic}
	return out
}

type Committer[E GroupElement[E, S], S Scalar[S]] struct {
	key           *Key[E, S]
	witnessLength int
}

func (c *Committer[E, S]) Commit(message *Message[S], prng io.Reader) (*Commitment[E, S], *Witness[S], error) {
	if prng == nil {
		return nil, nil, errs.NewArgument("prng cannot be nil")
	}
	if message == nil {
		return nil, nil, errs.NewArgument("message cannot be nil")
	}
	wvBytes := make([]byte, c.witnessLength)
	if _, err := io.ReadFull(prng, wvBytes); err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot read random bytes for witness")
	}
	wv, err := c.key.sf.FromBytes(wvBytes)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot generate random witness")
	}
	witness := &Witness[S]{v: wv}
	com, err := c.CommitWithWitness(message, witness)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot commit with witness")
	}
	return com, witness, nil
}

func (c *Committer[E, S]) CommitWithWitness(message *Message[S], witness *Witness[S]) (*Commitment[E, S], error) {
	if message == nil {
		return nil, errs.NewIsNil("message cannot be nil")
	}
	if witness == nil {
		return nil, errs.NewIsNil("witness cannot be nil")
	}
	// Compute g^m * h^r
	v, err := c.key.group.MultiScalarOp(
		[]S{message.v, witness.v},
		[]E{c.key.g, c.key.h},
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute multi-scalar operation")
	}
	return &Commitment[E, S]{v: v}, nil
}

type Verifier[E GroupElement[E, S], S Scalar[S]] struct {
	commitments.GenericVerifier[*Committer[E, S], *Witness[S], *Message[S], *Commitment[E, S]]
}

// ================= Types =================

func NewCommitmentKey[E GroupElement[E, S], S Scalar[S]](g, h E) (*Key[E, S], error) {
	if g.IsOpIdentity() || h.IsOpIdentity() {
		return nil, errs.NewIsIdentity("g or h cannot be the identity element")
	}
	if g.Equal(h) {
		return nil, errs.NewValue("g and h cannot be equal")
	}
	group, ok := g.Structure().(Group[E, S])
	if !ok {
		return nil, errs.NewType("g must have a prime group structure")
	}
	sf, ok := group.ScalarStructure().(ScalarField[S])
	if !ok {
		return nil, errs.NewType("g must have a prime scalar field structure")
	}
	return &Key[E, S]{g: g, h: h, group: group, sf: sf}, nil
}

func (k *Key[E, S]) G() E {
	return k.g
}

func (k *Key[E, S]) H() E {
	return k.h
}

func NewCommitmentKeyFromBytes[E GroupElement[E, S], S Scalar[S]](group Group[E, S], input []byte) (*Key[E, S], error) {
	if group == nil {
		return nil, errs.NewIsNil("group cannot be nil")
	}
	if len(input) != 2*group.ElementSize() {
		return nil, errs.NewArgument("input length must be twice the group element size")
	}
	g, err := group.FromBytes(input[:group.ElementSize()])
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot deserialize g from bytes")
	}
	h, err := group.FromBytes(input[group.ElementSize():])
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot deserialize h from bytes")
	}
	return NewCommitmentKey(g, h)
}

func (k *Key[E, S]) Bytes() []byte {
	return slices.Concat(k.g.Bytes(), k.h.Bytes())
}

func NewCommitment[E GroupElement[E, S], S Scalar[S]](v E) (*Commitment[E, S], error) {
	if v.IsOpIdentity() {
		return nil, errs.NewIsIdentity("commitment value cannot be the identity element")
	}
	return &Commitment[E, S]{v: v}, nil
}

func (c *Commitment[E, S]) Value() E {
	return c.v
}

func (c *Commitment[E, S]) Equal(other *Commitment[E, S]) bool {
	if c == nil || other == nil {
		return c == other
	}
	return c.v.Equal(other.v)
}

func (c *Commitment[E, S]) Op(other *Commitment[E, S]) *Commitment[E, S] {
	if other == nil {
		return c
	}
	return &Commitment[E, S]{v: c.v.Op(other.v)}
}

func (c *Commitment[E, S]) ScalarOp(message *Message[S]) *Commitment[E, S] {
	if message == nil {
		return c
	}
	return &Commitment[E, S]{v: c.v.ScalarOp(message.v)}
}

func (c *Commitment[E, S]) ReRandomiseWith(key *Key[E, S], r *Witness[S]) (*Commitment[E, S], error) {
	if r == nil {
		return nil, errs.NewIsNil("witness cannot be nil")
	}
	if key == nil {
		return nil, errs.NewIsNil("key cannot be nil")
	}
	if c == nil {
		return nil, errs.NewIsNil("commitment cannot be nil")
	}
	newCom := &Commitment[E, S]{v: c.v.Op(key.h.ScalarOp(r.v))}
	return newCom, nil
}

func (c *Commitment[E, S]) ReRandomise(key *Key[E, S], prng io.Reader) (*Commitment[E, S], *Witness[S], error) {
	if key == nil {
		return nil, nil, errs.NewIsNil("key cannot be nil")
	}
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng cannot be nil")
	}
	wv, err := key.sf.Random(prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot generate random witness")
	}
	witness := &Witness[S]{v: wv}
	commitment, err := c.ReRandomiseWith(key, witness)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot re-randomise commitment with witness")
	}
	return commitment, witness, nil
}

func (c *Commitment[E, S]) Clone() *Commitment[E, S] {
	if c == nil {
		return nil
	}
	return &Commitment[E, S]{v: c.v.Clone()}
}

func (c *Commitment[E, S]) HashCode() base.HashCode {
	return c.v.HashCode()
}

func NewMessage[S Scalar[S]](v S) *Message[S] {
	return &Message[S]{v: v}
}

func (m *Message[S]) Value() S {
	return m.v
}

func (m *Message[S]) Op(other *Message[S]) *Message[S] {
	return m.Add(other)
}

func (m *Message[S]) Add(other *Message[S]) *Message[S] {
	if other == nil {
		return m
	}
	return &Message[S]{v: m.v.Add(other.v)}
}

func (m *Message[S]) OtherOp(other *Message[S]) *Message[S] {
	return m.Mul(other)
}
func (m *Message[S]) Mul(other *Message[S]) *Message[S] {
	if other == nil {
		return m
	}
	return &Message[S]{v: m.v.Mul(other.v)}
}

func (m *Message[S]) Clone() *Message[S] {
	if m == nil {
		return nil
	}
	return &Message[S]{v: m.v.Clone()}
}

func (m *Message[S]) Equal(other *Message[S]) bool {
	if m == nil || other == nil {
		return m == other
	}
	return m.v.Equal(other.v)
}

func (m *Message[S]) HashCode() base.HashCode {
	return m.v.HashCode()
}

func NewWitness[S Scalar[S]](v S) (*Witness[S], error) {
	if v.IsZero() {
		return nil, errs.NewIsZero("witness value cannot be zero")
	}
	return &Witness[S]{v: v}, nil
}

func (w *Witness[S]) Value() S {
	return w.v
}

func (w *Witness[S]) Op(other *Witness[S]) *Witness[S] {
	return w.Add(other)
}

func (w *Witness[S]) Add(other *Witness[S]) *Witness[S] {
	if other == nil {
		return w
	}
	return &Witness[S]{v: w.v.Add(other.v)}
}

func (w *Witness[S]) OtherOp(other *Witness[S]) *Witness[S] {
	return w.Mul(other)
}

func (w *Witness[S]) Mul(other *Witness[S]) *Witness[S] {
	if other == nil {
		return w
	}
	return &Witness[S]{v: w.v.Mul(other.v)}
}

func (w *Witness[S]) Equal(other *Witness[S]) bool {
	if w == nil || other == nil {
		return w == other
	}
	return w.v.Equal(other.v)
}

func (w *Witness[S]) Clone() *Witness[S] {
	if w == nil {
		return nil
	}
	return &Witness[S]{v: w.v.Clone()}
}

func (w *Witness[S]) HashCode() base.HashCode {
	return w.v.HashCode()
}

func _[E GroupElement[E, S], S Scalar[S]]() {
	var (
		_ commitments.HomomorphicScheme[*Witness[S], S, *Message[S], S, *Commitment[E, S], E] = &Scheme[E, S]{}
		_ algebra.Actable[*Commitment[E, S], *Message[S]]                                     = (*Commitment[E, S])(nil)
	)
}
