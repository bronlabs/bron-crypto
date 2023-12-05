//nolint:nolintlint,gci,gofmt // we want to use pkg/errors only here, but nowhere else
package errs

var knownErrors = []ErrorType{
    DivisionByZero,
    Duplicate,
    Failed,
    IdentifiableAbort,
    IncorrectCount,
    InvalidArgument,
    InvalidCoordinates,
    InvalidCurve,
    InvalidIdentifier,
    InvalidLength,
    InvalidRange,
    InvalidRound,
    InvalidType,
    IsIdentity,
    IsNil,
    IsZero,
    Membership,
    Missing,
    Serialisation,
    RandomSampleFailed,
    HashingFailed,
    TotalAbort,
    VerificationFailed,
}
