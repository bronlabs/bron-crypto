package errs2

func Must(err error) {
	if err != nil {
		panic(err)
	}
}

func Must1[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func Must2[T1, T2 any](v1In T1, v2In T2, err error) (v1Out T1, v2Out T2) {
	if err != nil {
		panic(err)
	}
	return v1In, v2In
}
