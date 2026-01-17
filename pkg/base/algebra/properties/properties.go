package properties

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

type Axiom struct {
	Name      string
	CheckFunc func(t *testing.T)
}

// ReflexivityProperty verifies that aRa is always true.
func ReflexivityProperty[S algebra.Structure[E], E algebra.Element[E]](
	t *testing.T, c *Carrier[S, E], R *Relation[E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "Reflexivity",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")
				require.True(t, R.Func(a, a), "reflexivity failed: aRa should be true")
			})
		},
	}
}

func SymmetryProperty[S algebra.Structure[E], E algebra.Element[E]](
	t *testing.T, c *Carrier[S, E], R *Relation[E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "Symmetry",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")
				b := c.Dist.Draw(rt, "b")
				if R.Func(a, b) {
					require.True(t, R.Func(b, a), "symmetry failed: aRb but not bRa")
				}
			})
		},
	}
}

func TransitiveProperty[S algebra.Structure[E], E algebra.Element[E]](
	t *testing.T, c *Carrier[S, E], R *Relation[E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "Transitivity",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")
				b := c.Dist.Draw(rt, "b")
				c := c.Dist.Draw(rt, "c")
				if R.Func(a, b) && R.Func(b, c) {
					require.True(t, R.Func(a, c), "transitivity failed: aRb && bRc but not aRc")
				}
			})
		},
	}
}

func EqualityProperties[S algebra.Structure[E], E algebra.Element[E]](
	t *testing.T, c *Carrier[S, E], R *Relation[E],
) []Axiom {
	t.Helper()
	return []Axiom{
		ReflexivityProperty(t, c, R),
		SymmetryProperty(t, c, R),
		TransitiveProperty(t, c, R),
	}
}

func ClosureProperty[S algebra.Magma[E], E algebra.MagmaElement[E]](
	t *testing.T, c *Carrier[S, E], op *BinaryOperator[E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: op.Name + "_Closure",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")
				b := c.Dist.Draw(rt, "b")
				c := op.Func(a, b)
				require.NotNil(t, c, "closure failed: operation should return non-nil result")
			})
		},
	}
}

func AssociativityProperty[S algebra.SemiGroup[E], E algebra.SemiGroupElement[E]](
	t *testing.T, c *Carrier[S, E], op *BinaryOperator[E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: op.Name + "_Associativity",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")
				b := c.Dist.Draw(rt, "b")
				c := c.Dist.Draw(rt, "c")
				left := op.Func(op.Func(a, b), c)
				right := op.Func(a, op.Func(b, c))
				require.True(t, left.Equal(right), "associativity failed: (a op b) op c != a op (b op c)")
			})
		},
	}
}

func CommutativityProperty[S algebra.Magma[E], E algebra.MagmaElement[E]](
	t *testing.T, c *Carrier[S, E], op *BinaryOperator[E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: op.Name + "_Commutativity",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")
				b := c.Dist.Draw(rt, "b")
				left := op.Func(a, b)
				right := op.Func(b, a)
				require.True(t, left.Equal(right), "commutativity failed: a op b != b op a")
			})
		},
	}
}

func CyclicProperty[S algebra.CyclicSemiGroup[E], E algebra.CyclicSemiGroupElement[E]](
	t *testing.T, c *Carrier[S, E], op *BinaryOperator[E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: op.Name + "_Cyclic",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				g := c.Value.Generator()
				require.NotNil(t, g, "cyclic property failed: generator is nil")
				require.True(t, g.IsDesignatedGenerator(), "cyclic property failed: generator is not designated")
				x := c.Dist.Draw(rt, "x")
				require.Equal(t, x.Equal(g), x.IsDesignatedGenerator(), "cyclic property failed: more than one designated generator found")
			})
		},
	}
}

func IdentityProperty[S algebra.Monoid[E], E algebra.MonoidElement[E]](
	t *testing.T, c *Carrier[S, E], op *BinaryOperator[E], identity *Constant[E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: identity.Name,
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")

				// Left identity: identity op a = a
				left := op.Func(identity.Value(), a)
				require.True(t, left.Equal(a), "left identity failed: identity op a != a")

				// Right identity: a op identity = a
				right := op.Func(a, identity.Value())
				require.True(t, right.Equal(a), "right identity failed: a op identity != a")
			})
		},
	}
}

func CanDoubleProperty[S algebra.AdditiveSemiGroup[E], E algebra.AdditiveSemiGroupElement[E]](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "CanDouble",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")
				expected := a.Add(a)
				actual := a.Double()
				require.True(t, actual.Equal(expected), "can double failed: a + a != Double(a)")
			})
		},
	}
}

func CanSquareProperty[S algebra.MultiplicativeSemiGroup[E], E algebra.MultiplicativeSemiGroupElement[E]](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "CanSquare",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")
				expected := a.Mul(a)
				actual := a.Square()
				require.True(t, actual.Equal(expected), "can square failed: a * a != Square(a)")
			})
		},
	}
}

func CanDistinguishAdditiveIdentity[S algebra.AdditiveMonoid[E], E algebra.AdditiveMonoidElement[E]](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "CanDistinguishZeroElement",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				zero := c.Value.Zero()
				require.True(t, zero.IsZero(), "zero element is not marked as identity")
				x := c.Dist.Draw(rt, "x")
				require.Equal(t, x.Equal(zero), x.IsOpIdentity(), "can distinguish zero failed: more than one zero element found")
			})
		},
	}
}

func CanDistinguishMultiplicativeIdentity[S algebra.MultiplicativeMonoid[E], E algebra.MultiplicativeMonoidElement[E]](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "CanDistinguishOneElement",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				one := c.Value.One()
				require.True(t, one.IsOne(), "one element is not marked as identity")
				x := c.Dist.Draw(rt, "x")
				require.Equal(t, x.Equal(one), x.IsOpIdentity(), "can distinguish one failed: more than one one element found")
			})
		},
	}
}

func CanTrySub[S algebra.AdditiveMonoid[E], E algebra.AdditiveMonoidElement[E]](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "CanTrySub",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")
				b := c.Dist.Draw(rt, "b")
				diff, err := a.TrySub(b)
				if err == nil {
					// Verify that a = b + diff
					sum := b.Add(diff)
					require.True(t, sum.Equal(a), "can try sub failed: a != b + (a - b)")
				} else {
					require.Nil(t, diff)
				}
			})
		},
	}
}

func CanTryNeg[S algebra.AdditiveMonoid[E], E algebra.AdditiveMonoidElement[E]](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "CanTryNeg",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")
				neg, err := a.TryNeg()
				if err == nil {
					// Verify that a + (-a) = 0
					sum := a.Add(neg)
					zero := c.Value.Zero()
					require.True(t, sum.Equal(zero), "can try neg failed: a + (-a) != 0")
				} else {
					require.Nil(t, neg)
				}
			})
		},
	}
}

func CanTryDiv[S algebra.MultiplicativeMonoid[E], E algebra.MultiplicativeMonoidElement[E]](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "CanTryDiv",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")
				b := c.Dist.Draw(rt, "b")
				quotient, err := a.TryDiv(b)
				if err == nil {
					// Verify that a = b * quotient
					product := b.Mul(quotient)
					require.True(t, product.Equal(a), "can try div failed: a != b * (a / b)")
				} else {
					require.Nil(t, quotient)
				}
			})
		},
	}
}

func CanTryInv[S algebra.MultiplicativeMonoid[E], E algebra.MultiplicativeMonoidElement[E]](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "CanTryInv",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")
				inv, err := a.TryInv()
				if err == nil {
					// Verify that a * a^-1 = 1
					product := a.Mul(inv)
					one := c.Value.One()
					require.True(t, product.Equal(one), "can try inv failed: a * a^-1 != 1")
				} else {
					require.Nil(t, inv)
				}
			})
		},
	}
}

func GroupInverseProperty[S algebra.Group[E], E algebra.GroupElement[E]](
	t *testing.T, c *Carrier[S, E], op *BinaryOperator[E],
	identity *Constant[E], inv *UnaryOperator[E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: inv.Name,
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")
				invA := inv.Func(a)

				// Right inverse: a op inv(a) = identity
				right := op.Func(a, invA)
				require.True(t, right.Equal(identity.Value()), "right inverse failed: a op inv(a) != identity")
				// Left inverse: inv(a) op a = identity
				left := op.Func(invA, a)
				require.True(t, left.Equal(identity.Value()), "left inverse failed: inv(a) op a != identity")
			})
		},
	}
}

func GroupInverseIsNeg[S algebra.AdditiveGroup[E], E algebra.AdditiveGroupElement[E]](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "InverseIsNeg",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")
				invA := a.OpInv()
				negA := a.Neg()
				require.True(t, invA.Equal(negA), "inverse is neg failed: inv(a) != -a")
			})
		},
	}
}

func CanSub[S algebra.AdditiveGroup[E], E algebra.AdditiveGroupElement[E]](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "CanSub",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")
				b := c.Dist.Draw(rt, "b")
				diff := a.Sub(b)
				// Verify that a = b + diff
				sum := b.Add(diff)
				require.True(t, sum.Equal(a), "can sub failed: a != b + (a - b)")
			})
		},
	}
}

func GroupInverseIsInv[S algebra.MultiplicativeGroup[E], E algebra.MultiplicativeGroupElement[E]](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "InverseIsInv",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")
				invA := a.OpInv()
				invFuncA := a.Inv()
				require.True(t, invA.Equal(invFuncA), "inverse is inv failed: inv(a) != a^-1")
			})
		},
	}
}

func CanDiv[S algebra.MultiplicativeGroup[E], E algebra.MultiplicativeGroupElement[E]](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "CanDiv",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")
				b := c.Dist.Draw(rt, "b")
				quotient := a.Div(b)
				// Verify that a = b * quotient
				product := b.Mul(quotient)
				require.True(t, product.Equal(a), "can div failed: a != b * (a / b)")
			})
		},
	}
}

func HemiRingIsStandardProperty[S algebra.HemiRing[E], E algebra.HemiRingElement[E]](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "HemiRingIsStandard",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")
				b := c.Dist.Draw(rt, "b")

				aOpB := a.Op(b)
				aAddB := a.Add(b)

				require.True(t, aOpB.Equal(aAddB), "hemi-ring is standard failed: a.Op(b) != a.Add(b)")

				aOtherOpB := a.OtherOp(b)
				aMulB := a.Mul(b)

				require.True(t, aOtherOpB.Equal(aMulB), "hemi-ring is standard failed: a.OtherOp(b) != a.Mul(b)")
			})
		},
	}
}

func DistributivityOfMulOverAddProperty[S algebra.HemiRing[E], E algebra.HemiRingElement[E]](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "Mul_DistributesOver_Add",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")
				b := c.Dist.Draw(rt, "b")
				d := c.Dist.Draw(rt, "c")

				// a * (b + c)
				left1 := a.Mul(b.Add(d))
				// (a * b) + (a * c)
				right1 := a.Mul(b).Add(a.Mul(d))

				require.True(t, left1.Equal(right1), "distributivity failed: a * (b + c) != (a * b) + (a * c)")

				// (a + b) * c
				left2 := a.Add(b).Mul(d)
				// (a * c) + (b * c)
				right2 := a.Mul(d).Add(b.Mul(d))

				require.True(t, left2.Equal(right2), "distributivity failed: (a + b) * c != (a * c) + (b * c)")
			})
		},
	}
}

func EuclideanDivisionProperty[S algebra.EuclideanSemiDomain[E], E algebra.EuclideanSemiDomainElement[E]](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "Euclidean_Division",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")
				b := c.Dist.Draw(rt, "b")
				for b.IsZero() {
					b = c.Dist.Draw(rt, "b")
				}

				q, r, err := a.EuclideanDiv(b)
				require.NoError(t, err)

				// Verify a = q*b + r
				qb := q.Mul(b)
				reconstructed := qb.Add(r)
				require.True(t, a.Equal(reconstructed), "Euclidean division failed: a != q*b + r")

				if !r.IsZero() {
					require.True(
						t,
						base.Compare(r.EuclideanValuation(), b.EuclideanValuation()).IsLessThan() &&
							!base.Compare(r.EuclideanValuation(), b.EuclideanValuation()).IsEqual(),
						"Euclidean division failed: r >= |b|")
				}
			})
		},
	}
}

func EveryNonZeroElementHasMultiplicativeInverseProperty[S algebra.Field[E], E algebra.FieldElement[E]](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "EveryNonZeroElementHasMultiplicativeInverse",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Filter(func(x E) bool { return !x.IsZero() }).Draw(rt, "a")
				aInv, err := a.TryInv()
				require.NoError(t, err, "multiplicative inverse failed: TryInv returned error for non-zero element")
				require.True(t, a.Mul(aInv).IsOne(), "multiplicative inverse failed: a * a^-1 != 1")
			})
		},
	}
}

func FieldExtensionComponentBytesRoundTripProperty[S algebra.FieldExtension[E], E algebra.FieldExtensionElement[E]](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "FieldExtension_ComponentBytes_RoundTrip",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")
				b := a.ComponentsBytes()
				require.Greater(t, len(b), 0, "Field extension component bytes round-trip failed: ComponentsBytes returned empty byte slice")

				aReconstructed, err := c.Value.FromComponentsBytes(b)
				require.NoError(t, err, "ElementFromComponentBytes returned error")

				require.True(t, a.Equal(aReconstructed), "Field extension component bytes round-trip failed: reconstructed element does not equal original")
			})
		},
	}
}

func LeftDistributivityOfActionOverSemiModuleOperationProperty[S algebra.SemiModule[E, RE], R algebra.SemiRing[RE], E algebra.SemiModuleElement[E, RE], RE algebra.SemiRingElement[RE]](
	t *testing.T, c *Carrier2[S, R, E, RE],
) Axiom {
	t.Helper()
	return Axiom{
		Name: c.Action.Name + "_DistributesOver_Op",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.First.Dist.Draw(rt, "a")
				b := c.First.Dist.Draw(rt, "b")
				sc := c.Second.Dist.Draw(rt, "sc")

				// sc * (a + b)
				left1 := a.Op(b).ScalarOp(sc)
				// (sc * a) + (sc * b)
				right1 := a.ScalarOp(sc).Op(b.ScalarOp(sc))

				require.True(t, left1.Equal(right1), "distributivity of scalar multiplication over addition failed: sc * (a + b) != (sc * a) + (sc * b)")
			})
		},
	}
}

func RightDistributivityOfSemiModuleOperationOverBaseSemiRingAdditionProperty[S algebra.SemiModule[E, RE], R algebra.SemiRing[RE], E algebra.SemiModuleElement[E, RE], RE algebra.SemiRingElement[RE]](
	t *testing.T, c *Carrier2[S, R, E, RE],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "Op_DistributesOver_" + c.Action.Name,
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.First.Dist.Draw(rt, "a")
				sc1 := c.Second.Dist.Draw(rt, "sc1")
				sc2 := c.Second.Dist.Draw(rt, "sc2")

				// (sc1 + sc2) (*) a
				left1 := a.ScalarOp(sc1.Add(sc2))
				// (sc1 (*) a) + (sc2 (*) a)
				right1 := a.ScalarOp(sc1).Op(a.ScalarOp(sc2))

				require.True(t, left1.Equal(right1), "distributivity of addition over scalar multiplication failed: (sc1 + sc2) (*) a != (sc1 (*) a) + (sc2 (*) a)")
			})
		},
	}
}

func AssociativityOfScalarsWRTRingMultiplicationProperty[S algebra.SemiModule[E, RE], R algebra.SemiRing[RE], E algebra.SemiModuleElement[E, RE], RE algebra.SemiRingElement[RE]](
	t *testing.T, c *Carrier2[S, R, E, RE],
) Axiom {
	t.Helper()
	return Axiom{
		Name: c.Action.Name + "_Associativity_WRT_Ring_Multiplication",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.First.Dist.Draw(rt, "a")
				sc1 := c.Second.Dist.Draw(rt, "sc1")
				sc2 := c.Second.Dist.Draw(rt, "sc2")

				// (sc1 * sc2) (*) a
				left1 := a.ScalarOp(sc1.Mul(sc2))
				// sc1 (*) (sc2 (*) a)
				right1 := a.ScalarOp(sc2).ScalarOp(sc1)

				require.True(t, left1.Equal(right1), "associativity of scalars wrt ring multiplication failed: (sc1 * sc2) (*) a != sc1 (*) (sc2 (*) a)")
			})
		},
	}
}

func ScalarOpIsScalarMultiplicationProperty[S algebra.AdditiveSemiModule[E, RE], R algebra.SemiRing[RE], E algebra.AdditiveSemiModuleElement[E, RE], RE algebra.SemiRingElement[RE]](
	t *testing.T, c *Carrier2[S, R, E, RE],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "ScalarOp_Is_ScalarMultiplication",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.First.Dist.Draw(rt, "a")
				sc := c.Second.Dist.Draw(rt, "sc")

				expected := a.ScalarMul(sc)
				actual := a.ScalarOp(sc)

				require.True(t, actual.Equal(expected), "scalar op is scalar multiplication failed: ScalarOp(sc) != ScalarMul(sc)")
			})
		},
	}
}

func ScalarOpIsScalarExponentiationProperty[S algebra.MultiplicativeSemiModule[E, RE], R algebra.SemiRing[RE], E algebra.MultiplicativeSemiModuleElement[E, RE], RE algebra.SemiRingElement[RE]](
	t *testing.T, c *Carrier2[S, R, E, RE],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "ScalarOp_Is_ScalarExponentiation",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.First.Dist.Draw(rt, "a")
				sc := c.Second.Dist.Draw(rt, "sc")

				expected := a.ScalarExp(sc)
				actual := a.ScalarOp(sc)

				require.True(t, actual.Equal(expected), "scalar op is scalar exponentiation failed: ScalarOp(sc) != ScalarExp(sc)")
			})
		},
	}
}

func BaseRingIdentityActsAsModuleIdentityProperty[S algebra.Module[E, RE], R algebra.Ring[RE], E algebra.ModuleElement[E, RE], RE algebra.RingElement[RE]](
	t *testing.T, c *Carrier2[S, R, E, RE],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "BaseRingIdentity_ActsAs_ModuleIdentity",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.First.Dist.Draw(rt, "a")
				one := c.Second.Value.One()

				result := a.ScalarOp(one)

				require.True(t, result.Equal(a), "base ring identity does not act as module identity: 1 (*) a != a")
			})
		},
	}
}

func NumericStructureFromBytesBERoundTripProperty[S interface {
	algebra.NumericStructure[E]
	Structure
}, E interface {
	algebra.Numeric
	base.Equatable[E]
}](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "NumericSerialisationRoundTrip",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				value := c.Dist.Draw(rt, "value")

				serialised := value.BytesBE()
				deserialised, err := c.Value.FromBytesBE(serialised)
				require.NoError(t, err, "numeric serialization round trip failed: FromBytesBE returned error")

				require.True(t, value.Equal(deserialised), "numeric serialization round trip failed: value != Deserialize(Serialize(value))")
			})
		},
	}
}

func FromCardinalRoundTripProperty[S algebra.NPlusLike[E], E algebra.NatPlusLike[E]](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "FromCardinal_RoundTrip",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				original := c.Dist.Draw(rt, "original")

				cardinal := original.Cardinal()
				reconstructed, err := c.Value.FromCardinal(cardinal)
				require.NoError(t, err, "FromCardinal returned error")

				require.True(t, original.Equal(reconstructed), "FromCardinal round trip failed: original != FromCardinal(ToCardinal(original))")
			})
		},
	}
}

func AnyNumberIsEitherOddOrEvenProperty[S algebra.Structure[E], E interface {
	algebra.Element[E]
	IsOdd() bool
	IsEven() bool
}](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "AnyNumberIsEitherOddOrEven",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")

				isOdd := a.IsOdd()
				isEven := a.IsEven()

				require.True(t, isOdd || isEven, "any number is either odd or even failed: number is neither odd nor even")
				require.False(t, isOdd && isEven, "any number is either odd or even failed: number is both odd and even")
			})
		},
	}
}

func AnyNaturalNumberIsEitherZeroOrPositiveProperty[S algebra.NLike[E], E algebra.NatLike[E]](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "AnyNaturalNumberIsEitherZeroOrPositive",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")

				isZero := a.IsZero()
				isPositive := a.IsPositive()

				require.True(t, isZero || isPositive, "any natural number is either zero or positive failed: number is neither zero nor positive")
				require.False(t, isZero && isPositive, "any natural number is either zero or positive failed: number is both zero and positive")
			})
		},
	}
}

func AnyIntegerIsEitherPositiveOrNegativeOrZero[S algebra.ZLike[E], E algebra.IntLike[E]](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "AnyIntegerIsEitherPositiveOrNegativeOrZero",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := c.Dist.Draw(rt, "a")

				isPositive := a.IsPositive()
				isNegative := a.IsNegative()
				isZero := a.IsZero()

				require.True(t, isPositive || isNegative || isZero, "any integer is either positive, negative, or zero failed: number is neither positive, negative, nor zero")
				require.False(t, (isPositive && isNegative) || (isPositive && isZero) || (isNegative && isZero), "any integer is either positive, negative, or zero failed: number is more than one of positive, negative, or zero")
			})
		},
	}
}

func ZModFromBytesBEReduceRoundTripProperty[S algebra.ZModLike[E], E algebra.UintLike[E]](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "ZModFromBytesBE_Reduce_RoundTrip",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				modulus := c.Value.Characteristic()
				extraCardinal := cardinal.New(rapid.Uint64Range(0, modulus.Uint64()-1).Draw(rt, "extra"))
				extra, err := c.Value.FromBytes(extraCardinal.Bytes())
				require.NoError(t, err)

				modulusWithExtra := modulus.Add(extraCardinal)
				reduced, err := c.Value.FromBytesBEReduce(modulusWithExtra.Bytes())
				require.NoError(t, err, "ZMod FromBytesBE Reduce returned error")

				require.True(t, extra.Equal(reduced), "ZMod FromBytesBE Reduce round trip failed: original != FromBytesBEReduce(BytesBE(original))")
			})
		},
	}
}

func FromWideBytesRoundTripProperty[S algebra.PrimeField[E], E algebra.PrimeFieldElement[E]](
	t *testing.T, c *Carrier[S, E],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "FromWideBytes_RoundTrip",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				original := c.Dist.Draw(rt, "original")

				serialised := original.Bytes()
				require.Equal(t, c.Value.ElementSize(), len(serialised), "FromWideBytes round trip failed: Bytes() returned byte slice of incorrect length")
				reconstructed, err := c.Value.FromWideBytes(serialised)
				require.NoError(t, err, "FromWideBytes returned error")
				require.True(t, original.Equal(reconstructed), "FromWideBytes round trip failed: original != FromWideBytes(WideBytes(original))")

				padded := sliceutils.PadToLeft(serialised, c.Value.WideElementSize()-len(serialised))
				_, err = c.Value.FromWideBytes(padded)
				require.Error(t, err, "FromWideBytes should return error for too big input")
			})
		},
	}
}

func CanScalarBaseOp[S algebra.PrimeGroup[E, FE], F algebra.PrimeField[FE], E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](
	t *testing.T, c *Carrier2[S, F, E, FE],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "CanScalarBaseOp",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				sc := c.Second.Dist.Draw(rt, "sc")
				result := c.First.Value.ScalarBaseOp(sc)
				expected := c.First.Value.Generator().ScalarOp(sc)
				require.True(t, result.Equal(expected), "can scalar base op failed: ScalarBaseOp(sc) != ScalarOp(FromBytesBE(sc))")
			})
		},
	}
}

func CanScalarBaseMul[S algebra.AdditivePrimeGroup[E, FE], F algebra.PrimeField[FE], E algebra.AdditivePrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](
	t *testing.T, c *Carrier2[S, F, E, FE],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "CanScalarBaseMul",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				sc := c.Second.Dist.Draw(rt, "sc")
				result := c.First.Value.ScalarBaseMul(sc)
				expected := c.First.Value.Generator().ScalarMul(sc)
				require.True(t, result.Equal(expected), "can scalar base mul failed: ScalarBaseMul(sc) != ScalarMul(FromBytesBE(sc))")
			})
		},
	}
}

func PolynomialLikeConstantTermProperty[
	PS algebra.PolynomialLikeStructure[P, S, C], SS algebra.Ring[S], CS algebra.Group[C],
	P algebra.PolynomialLike[P, S, C], S algebra.RingElement[S], C algebra.GroupElement[C],
](
	t *testing.T, c *Carrier[PS, P],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "PolynomialLike_ConstantTerm",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				p := c.Dist.Draw(rt, "p")
				constantTerm := p.ConstantTerm()
				coeffs := p.Coefficients()
				require.Equal(t, constantTerm.Equal(coeffs[0]), true, "polynomial-like constant term failed: ConstantTerm() != Coefficients()[0]")
			})
		},
	}
}

func PolynomialLikeIsConstantProperty[
	PS algebra.PolynomialLikeStructure[P, S, C], SS algebra.Ring[S], CS algebra.Group[C],
	P algebra.PolynomialLike[P, S, C], S algebra.RingElement[S], C algebra.GroupElement[C],
](
	t *testing.T, c *Carrier[PS, P],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "PolynomialLike_IsConstant",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				p := c.Dist.Draw(rt, "p")
				coeffs := p.Coefficients()
				isConstant := true
				for i := 1; i < len(coeffs); i++ {
					if !coeffs[i].IsOpIdentity() {
						isConstant = false
						break
					}
				}
				require.Equal(t, p.IsConstant(), isConstant, "polynomial-like is constant failed: IsConstant() does not match coefficients")
			})
		},
	}
}

func UnivariatePolynomialLikeFromCoefficientsRoundTripProperty[
	PS algebra.UnivariatePolynomialLikeStructure[P, S, C, SS, CS], SS algebra.Ring[S], CS algebra.Group[C],
	P algebra.UnivariatePolynomialLike[P, S, C, SS, CS], S algebra.RingElement[S], C algebra.GroupElement[C],
](
	t *testing.T, c *Carrier[PS, P],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "PolynomialLike_FromCoefficients_RoundTrip",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				p := c.Dist.Draw(rt, "p")
				coeffs := p.Coefficients()
				reconstructed, err := c.Value.New(coeffs...)
				require.NoError(t, err, "FromCoefficients returned error")

				require.True(t, p.Equal(reconstructed), "polynomial-like from coefficients round trip failed: original != FromCoefficients(Coefficients(original))")
			})
		},
	}
}

func PolynomialLikeDegreeProperty[
	PS algebra.PolynomialLikeStructure[P, S, C], SS algebra.Ring[S], CS algebra.Group[C],
	P algebra.PolynomialLike[P, S, C], S algebra.RingElement[S], C algebra.GroupElement[C],
](
	t *testing.T, c *Carrier[PS, P],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "PolynomialLike_Degree",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				p := c.Dist.Draw(rt, "p")
				coeffs := p.Coefficients()
				expectedDegree := -1
				for i := len(coeffs) - 1; i >= 0; i-- {
					if !coeffs[i].IsOpIdentity() {
						expectedDegree = i
						break
					}
				}
				require.Equal(t, expectedDegree, p.Degree(), "polynomial-like degree failed: Degree() does not match highest non-zero coefficient index")
			})
		},
	}
}

func PolynomialLikeDerivativeDegreeDeclinesProperty[
	PS algebra.PolynomialLikeStructure[P, S, C], SS algebra.Ring[S], CS algebra.Group[C],
	P algebra.PolynomialLike[P, S, C], S algebra.RingElement[S], C algebra.GroupElement[C],
](
	t *testing.T, c *Carrier[PS, P],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "PolynomialLike_Derivative_DegreeDeclines",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				p := c.Dist.Draw(rt, "p")
				deg := p.Degree()
				deriv := p.Derivative()
				derivDeg := deriv.Degree()
				if deg <= 0 {
					require.Equal(t, -1, derivDeg, "polynomial-like derivative degree failed: derivative of constant should have degree -1")
				} else {
					require.LessOrEqual(t, derivDeg, deg-1, "polynomial-like derivative degree failed: derivative degree should be at most deg-1")
				}
			})
		},
	}
}

func PolynomialLikeDerivativeOfConstantIsZeroProperty[
	PS algebra.PolynomialLikeStructure[P, S, C], SS algebra.Ring[S], CS algebra.Group[C],
	P algebra.PolynomialLike[P, S, C], S algebra.RingElement[S], C algebra.GroupElement[C],
](
	t *testing.T, c *Carrier[PS, P],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "PolynomialLike_Derivative_ConstantIsZero",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				p := c.Dist.Draw(rt, "p")
				if p.IsConstant() {
					deriv := p.Derivative()
					require.True(t, deriv.IsOpIdentity(), "polynomial-like derivative failed: derivative of constant should be zero")
				}
			})
		},
	}
}

func UnivariatePolynomialLikeLeadingCoefficientProperty[
	PS algebra.UnivariatePolynomialLikeStructure[P, S, C, SS, CS], SS algebra.Ring[S], CS algebra.Group[C],
	P algebra.UnivariatePolynomialLike[P, S, C, SS, CS], S algebra.RingElement[S], C algebra.GroupElement[C],
](
	t *testing.T, c *Carrier[PS, P],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "UnivariatePolynomialLike_LeadingCoefficient",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				p := c.Dist.Draw(rt, "p")
				deg := p.Degree()
				lc := p.LeadingCoefficient()
				if deg >= 0 {
					coeffs := p.Coefficients()
					require.True(t, lc.Equal(coeffs[deg]), "univariate polynomial-like leading coefficient failed: LeadingCoefficient() != Coefficients()[Degree()]")
				} else {
					require.True(t, lc.IsOpIdentity(), "univariate polynomial-like leading coefficient failed: zero polynomial should have zero leading coefficient")
				}
			})
		},
	}
}

func UnivariatePolynomialLikeEvalAtZeroProperty[
	PS algebra.UnivariatePolynomialLikeStructure[P, S, C, SS, CS], SS algebra.Ring[S], CS algebra.Group[C],
	P algebra.UnivariatePolynomialLike[P, S, C, SS, CS], S algebra.RingElement[S], C algebra.GroupElement[C],
](
	t *testing.T, c *Carrier[PS, P], scalarStructure SS,
) Axiom {
	t.Helper()
	return Axiom{
		Name: "UnivariatePolynomialLike_EvalAtZero",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				p := c.Dist.Draw(rt, "p")
				zero := scalarStructure.Zero()
				evalAtZero := p.Eval(zero)
				constantTerm := p.ConstantTerm()
				require.True(t, evalAtZero.Equal(constantTerm), "univariate polynomial-like eval at zero failed: Eval(0) != ConstantTerm()")
			})
		},
	}
}

func UnivariatePolynomialLikeEvalConstantProperty[
	PS algebra.UnivariatePolynomialLikeStructure[P, S, C, SS, CS], SS algebra.Ring[S], CS algebra.Group[C],
	P algebra.UnivariatePolynomialLike[P, S, C, SS, CS], S algebra.RingElement[S], C algebra.GroupElement[C],
](
	t *testing.T, c *Carrier[PS, P], scalarDist *rapid.Generator[S],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "UnivariatePolynomialLike_EvalConstant",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				p := c.Dist.Draw(rt, "p")
				if p.IsConstant() {
					x := scalarDist.Draw(rt, "x")
					evalAtX := p.Eval(x)
					constantTerm := p.ConstantTerm()
					require.True(t, evalAtX.Equal(constantTerm), "univariate polynomial-like eval constant failed: constant polynomial should evaluate to its constant term at any point")
				}
			})
		},
	}
}

func PolynomialLeadingCoefficientProperty[
	PS algebra.PolynomialRing[P, S],
	P algebra.Polynomial[P, S], S algebra.RingElement[S],
](
	t *testing.T, c *Carrier[PS, P],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "Polynomial_LeadingCoefficient",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				p := c.Dist.Draw(rt, "p")
				deg := p.Degree()
				lc := p.LeadingCoefficient()
				if deg >= 0 {
					coeffs := p.Coefficients()
					require.True(t, lc.Equal(coeffs[deg]), "polynomial leading coefficient failed: LeadingCoefficient() != Coefficients()[Degree()]")
				} else {
					require.True(t, lc.IsOpIdentity(), "polynomial leading coefficient failed: zero polynomial should have zero leading coefficient")
				}
			})
		},
	}
}

func PolynomialEvalAtZeroProperty[
	PS algebra.PolynomialRing[P, S],
	P algebra.Polynomial[P, S], S algebra.RingElement[S],
](
	t *testing.T, c *Carrier[PS, P], scalarStructure algebra.Ring[S],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "Polynomial_EvalAtZero",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				p := c.Dist.Draw(rt, "p")
				zero := scalarStructure.Zero()
				evalAtZero := p.Eval(zero)
				constantTerm := p.ConstantTerm()
				require.True(t, evalAtZero.Equal(constantTerm), "polynomial eval at zero failed: Eval(0) != ConstantTerm()")
			})
		},
	}
}

func PolynomialEvalConstantProperty[
	PS algebra.PolynomialRing[P, S],
	P algebra.Polynomial[P, S], S algebra.RingElement[S],
](
	t *testing.T, c *Carrier[PS, P], scalarDist *rapid.Generator[S],
) Axiom {
	t.Helper()
	return Axiom{
		Name: "Polynomial_EvalConstant",
		CheckFunc: func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				p := c.Dist.Draw(rt, "p")
				if p.IsConstant() {
					x := scalarDist.Draw(rt, "x")
					evalAtX := p.Eval(x)
					constantTerm := p.ConstantTerm()
					require.True(t, evalAtX.Equal(constantTerm), "polynomial eval constant failed: constant polynomial should evaluate to its constant term at any point")
				}
			})
		},
	}
}
