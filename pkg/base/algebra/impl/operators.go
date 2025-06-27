package impl

type (
	Operand[E any]      interface{ Op(E) E }
	MaybeOperand[E any] interface{ TryOp(E) (E, error) }

	DualOperand[E any]      interface{ OtherOp(E) E }
	MaybeDualOperand[E any] interface{ TryOtherOp(E) (E, error) }

	Summand[E any]      interface{ Add(E) E }
	MaybeSummand[E any] interface{ TryAdd(E) (E, error) }

	Minuend[E any]      interface{ Sub(E) E }
	MaybeMinuend[E any] interface{ TrySub(E) (E, error) }

	Multiplicand[E any]      interface{ Mul(E) E }
	MaybeMultiplicand[E any] interface{ TryMul(E) (E, error) }

	Dividend[E any]      interface{ Div(E) E }
	MaybeDividend[E any] interface{ TryDiv(E) (E, error) }

	ExponentiationBase[B, E any]      interface{ Exp(E) B }
	MaybeExponentiationBase[B, E any] interface{ TryExp(E) (B, error) }

	Conjunct[E any]      interface{ And(E) E }
	MaybeConjunct[E any] interface{ TryAnd(E) (E, error) }

	Disjunct[E any]      interface{ Or(E) E }
	MaybeDisjunct[E any] interface{ TryOr(E) (E, error) }

	ExclusiveDisjunct[E any]      interface{ Xor(E) E }
	MaybeExclusiveDisjunct[E any] interface{ TryXor(E) (E, error) }

	ArithmeticNegand[E any]      interface{ Neg() E }
	MaybeArithmeticNegand[E any] interface{ TryNeg() (E, error) }

	Inversand[E any]      interface{ Inv() E }
	MaybeInversand[E any] interface{ TryInv() (E, error) }

	BooleanNegand[E any]      interface{ Not() E }
	MaybeBooleanNegand[E any] interface{ TryNot() (E, error) }
)
