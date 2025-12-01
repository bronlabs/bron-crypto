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

func Maybe(err error) error {
	if err != nil {
		return Wrap(err)
	}
	return nil
}

func Maybe1[T any](v T, err error) (T, error) {
	if err != nil {
		return v, Wrap(err)
	}
	return v, nil
}

func Maybe2[T1, T2 any](v1 T1, v2 T2, err error) (T1, T2, error) {
	if err != nil {
		return v1, v2, Wrap(err)
	}
	return v1, v2, nil
}
