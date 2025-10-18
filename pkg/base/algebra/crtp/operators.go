package crtp

type (
	NAry[C any] interface {
		Arity() Cardinal
		Components() []C
	}

	Mapping[E, C any] interface {
		NAry[C]
		New(...C) (E, error)
	}

	Product[P, C any] interface {
		NAry[C]
		Diagonal(C) P
	}

	CoProduct[P, C any] interface {
		NAry[C]
		CoDiagonal() C
	}
	Power[P, C any] interface {
		Product[P, C]
		Factor() C
	}

	TensorProduct[E, C, S any] interface {
		Module[E, S]
		Mapping[E, C]
	}

	Tensor[E, S any] ModuleElement[E, S]
)

type (
	Operand[E any]              interface{ Op(E) E }
	FixedCapacityOperand[E any] interface{ OpCap(E, int) E }

	DualOperand[E any]              interface{ OtherOp(E) E }
	FixedCapacityDualOperand[E any] interface{ OtherOpCap(E, int) E }

	Summand[E any]                   interface{ Add(E) E }
	FixedCapacitySummand[E any]      interface{ AddCap(E, int) E }
	MaybeSummand[E any]              interface{ TryAdd(E) (E, error) }
	MaybeFixedCapacitySummand[E any] interface{ TryAddCap(E, int) (E, error) }

	Minuend[E any]                   interface{ Sub(E) E }
	FixedCapacityMinuend[E any]      interface{ SubCap(E, int) E }
	MaybeMinuend[E any]              interface{ TrySub(E) (E, error) }
	MaybeFixedCapacityMinuend[E any] interface{ TrySubCap(E, int) (E, error) }

	Multiplicand[E any]                   interface{ Mul(E) E }
	FixedCapacityMultiplicand[E any]      interface{ MulCap(E, int) E }
	MaybeMultiplicand[E any]              interface{ TryMul(E) (E, error) }
	MaybeFixedCapacityMultiplicand[E any] interface{ TryMulCap(E, int) (E, error) }

	Dividend[E any]                   interface{ Div(E) E }
	FixedCapacityDividend[E any]      interface{ DivCap(E, int) E }
	MaybeDividend[E any]              interface{ TryDiv(E) (E, error) }
	MaybeFixedCapacityDividend[E any] interface{ TryDivCap(E, int) (E, error) }

	Residuand[M, Q any] interface{ Mod(M) (Q, error) }

	ExponentiationBase[B, E any]                   interface{ Exp(E) B }
	FixedCapacityExponentiationBase[B, E any]      interface{ ExpCap(E, int) B }
	MaybeExponentiationBase[B, E any]              interface{ TryExp(E) (B, error) }
	MaybeFixedCapacityExponentiationBase[B, E any] interface{ TryExpCap(E, int) (B, error) }

	IntegerExponentiationBase[B, I any]                   interface{ ExpI(I) B }
	FixedCapacityIntegerExponentiationBase[B, I any]      interface{ ExpICap(I, int) B }
	MaybeIntegerExponentiationBase[B, I any]              interface{ TryExpI(I) (B, error) }
	MaybeFixedCapacityIntegerExponentiationBase[B, I any] interface{ TryExpICap(I, int) (B, error) }

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

	Shiftable[E, S any]      interface{ Shift(S) E }
	MaybeShiftable[E, S any] interface{ TryShift(S) (E, error) }

	LeftBitwiseShiftable[E any]            interface{ Lsh(uint) E }
	FixedLengthLeftBitwiseShiftable[E any] interface{ LshCap(uint, int) E }

	RightBitwiseShiftable[E any]            interface{ Rsh(uint) E }
	FixedLengthRightBitwiseShiftable[E any] interface{ RshCap(uint, int) E }

	Resizable[E, C any]      interface{ Resize(C) E }
	ResizableCapacity[E any] Resizable[E, int]
)
