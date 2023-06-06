package errs

type ErrorType string

const (
	IsNil                 ErrorType = "[IS_NIL]"
	InvalidArgument       ErrorType = "[INVALID_ARGUMENT]"
	NotOnCurve            ErrorType = "[NOT_ON_CURVE]"
	InvalidCurve          ErrorType = "[INVALID_CURVE]"
	IsZero                ErrorType = "[IS_ZERO]"
	IsIdentity            ErrorType = "[IS_IDENTITY]"
	InvalidRound          ErrorType = "[INVALID_ROUND]"
	IncorrectCount        ErrorType = "[INCORRECT_COUNT]"
	VerificationFailed    ErrorType = "[VERIFICATION_FAILED]"
	DivisionByZero        ErrorType = "[DIVISION_BY_ZERO]"
	InvalidIdentifier     ErrorType = "[INVALID_IDENTIFIER]"
	DeserializationFailed ErrorType = "[DESERIALIZATION_FAILED]"
	Missing               ErrorType = "[MISSING]"
	Duplicate             ErrorType = "[DUPLICATE]"
	IdentifiableAbort     ErrorType = "[ABORT]"
	Failed                ErrorType = "[Failed]"
)
