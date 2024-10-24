package errs2_test

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs2"
	"github.com/stretchr/testify/require"
)

func TestTagString(t *testing.T) {
	t.Parallel()
	t.Run("regular tag", func(t *testing.T) {
		t.Parallel()
		first := errs2.Tag0("first")
		require.Equal(t, "FIRST", first.String())
		second := errs2.Tag0("SEcoNd tAg")
		require.Equal(t, "SECOND_TAG", second.String())
	})
	t.Run("tag1", func(t *testing.T) {
		t.Parallel()
		first := errs2.Tag1[string]("first")
		require.Equal(t, "FIRST<string>", first.String())
		second := errs2.Tag1[string]("SEcoNd tAg")
		require.Equal(t, "SECOND_TAG<string>", second.String())
		type myString string
		third := errs2.Tag1[myString]("third")
		require.True(t, regexp.MustCompile(`^THIRD<([^>]+)\.myString>$`).MatchString(third.String()))
	})
	t.Run("tag2", func(t *testing.T) {
		t.Parallel()
		first := errs2.Tag2[string, int]("first")
		require.Equal(t, "FIRST<string, int>", first.String())
		second := errs2.Tag2[any, any]("SEcoNd tAg")
		require.Equal(t, "SECOND_TAG<any, any>", second.String())
		type myString string
		third := errs2.Tag2[myString, string]("third")
		require.True(t, regexp.MustCompile(`^THIRD<([^>]+)\.myString, string>$`).MatchString(third.String()))
	})
}

func TestTagCreation(t *testing.T) {
	t.Parallel()
	t.Run("regular tag", func(t *testing.T) {
		t.Parallel()
		tag := errs2.Tag0("tag")
		t.Run("errorf", func(t *testing.T) {
			t.Parallel()
			err := tag.Errorf("message %s", "here")
			require.Equal(t, "[TAG] message here", err.Error())
		})
		t.Run("new", func(t *testing.T) {
			t.Parallel()
			err := tag.New("something")
			require.Equal(t, "[TAG] something", err.Error())
			err = tag.New()
			require.Equal(t, "[TAG]", err.Error(), "could not create tag with no message")
		})
	})
	t.Run("tag1", func(t *testing.T) {
		t.Parallel()
		tag := errs2.Tag1[int]("tag")
		t.Run("errorf", func(t *testing.T) {
			t.Parallel()
			err := tag.Errorf(42, "message %s", "here")
			require.Equal(t, "[TAG<int>](42) message here", err.Error())
		})
		t.Run("new", func(t *testing.T) {
			t.Parallel()
			err := tag.New(42, "something")
			require.Equal(t, "[TAG<int>](42) something", err.Error())
			err = tag.New(10)
			require.Equal(t, "[TAG<int>](10)", err.Error(), "could not create tag with no message")
		})
	})
	t.Run("tag2", func(t *testing.T) {
		t.Parallel()
		tag := errs2.Tag2[int, uint]("tag")
		t.Run("errorf", func(t *testing.T) {
			t.Parallel()
			err := tag.Errorf(42, 42, "message %s", "here")
			require.Equal(t, "[TAG<int, uint>](42, 42) message here", err.Error())
		})
		t.Run("new", func(t *testing.T) {
			t.Parallel()
			err := tag.New(42, 42, "something")
			require.Equal(t, "[TAG<int, uint>](42, 42) something", err.Error())
			err = tag.New(-2, 3)
			require.Equal(t, "[TAG<int, uint>](-2, 3)", err.Error(), "could not create tag with no message")

		})
	})
}

func TestTagChecking(t *testing.T) {
	t.Parallel()
	tag0 := errs2.Tag0("tag")
	tag1 := errs2.Tag1[int]("tag1")
	tag2 := errs2.Tag2[string, uint]("tag2")

	errs := []error{
		tag0.New("something"),
		tag1.New(1, "something else"),
		tag2.New("param", 0, "yet another thing"),
	}
	wrapped := [][]error{
		{
			tag0.Wrap(errs[0], "wrapped 0"),
			tag0.Wrap(errs[1], "wrapped 1"),
			tag0.Wrap(errs[2], "wrapped 2"),
		},
		{
			tag1.Wrap(errs[0], 1, "wrapped 0"),
			tag1.Wrap(errs[1], 1, "wrapped 1"),
			tag1.Wrap(errs[2], 1, "wrapped 2"),
		},
		{
			tag2.Wrap(errs[0], "param", 0, "wrapped 0"),
			tag2.Wrap(errs[1], "param", 0, "wrapped 1"),
			tag2.Wrap(errs[2], "param", 0, "wrapped 2"),
		},
	}

	iss := []func(error) bool{tag0.IsTagging, tag1.IsTagging, tag2.IsTagging}
	funcs := []func(error) bool{
		func(err error) bool { return errs2.IsTaggedWith(err, tag0) },
		func(err error) bool { return errs2.IsTaggedWith(err, tag1) },
		func(err error) bool { return errs2.IsTaggedWith(err, tag2) },
	}

	t.Run("regular errors", func(t *testing.T) {
		t.Parallel()
		for i, is := range iss {
			for j, err := range errs {
				if i == j {
					msg := fmt.Sprintf("tag %d should be in error %s", i, err.Error())
					require.True(t, is(err), msg)
					require.True(t, funcs[i](err), msg)
				} else {
					msg := fmt.Sprintf("tag %d should not be in error %s", i, err.Error())
					require.False(t, is(err), msg)
					require.False(t, funcs[i](err), msg)
				}
			}
		}
	})

	t.Run("wrapped errors", func(t *testing.T) {
		t.Parallel()
		for i, f := range iss {
			for j, errs := range wrapped {
				for _, err := range errs {
					if i == j {
						msg := fmt.Sprintf("tag %d should be in error %s", i, err.Error())
						require.True(t, f(err), msg)
						require.True(t, funcs[i](err), msg)
					} else {
						msg := fmt.Sprintf("tag %d should not be in error %s", i, err.Error())
						require.False(t, f(err), msg)
						require.False(t, funcs[i](err), msg)
					}
				}
			}
		}
	})
}

func TestCanExtractAndCheckTagFromErrorChain(t *testing.T) {
	t.Parallel()
	tag0 := errs2.Tag0("tag")
	tag1 := errs2.Tag1[int]("tag1")
	tag2 := errs2.Tag2[string, uint]("tag2")

	errs := []error{
		tag0.New("something"),
		tag1.New(1, "something else"),
		tag2.New("param", 0, "yet another thing"),
	}
	wrapped := [][]error{
		{
			tag0.Wrap(errs[0], "wrapped 0"),
			tag0.Wrap(errs[1], "wrapped 1"),
			tag0.Wrap(errs[2], "wrapped 2"),
		},
		{
			tag1.Wrap(errs[0], 1, "wrapped 0"),
			tag1.Wrap(errs[1], 1, "wrapped 1"),
			tag1.Wrap(errs[2], 1, "wrapped 2"),
		},
		{
			tag2.Wrap(errs[0], "param", 0, "wrapped 0"),
			tag2.Wrap(errs[1], "param", 0, "wrapped 1"),
			tag2.Wrap(errs[2], "param", 0, "wrapped 2"),
		},
	}

	isins := []func(error) bool{
		func(err error) bool { return errs2.Has(err, tag0) },
		func(err error) bool { return errs2.Has(err, tag1) },
		func(err error) bool { return errs2.Has(err, tag2) },
	}
	extractors := []func(error) error{
		func(err error) error { return errs2.Extract(err, tag0) },
		func(err error) error { return errs2.Extract(err, tag1) },
		func(err error) error { return errs2.Extract(err, tag2) },
	}

	t.Run("unwrapped errors", func(t *testing.T) {
		t.Parallel()
		t.Run("check", func(t *testing.T) {
			t.Parallel()
			iss := []func(error) bool{tag0.IsTagging, tag1.IsTagging, tag2.IsTagging}
			for i, f := range isins {
				for _, err := range errs {
					require.Equal(t, f(err), iss[i](err), fmt.Sprintf("tag %d should be in error %s", i, err.Error()))
				}
			}
		})
		t.Run("extract", func(t *testing.T) {
			t.Parallel()
			for i, f := range extractors {
				for j, err := range errs {
					if i == j {
						require.Equal(t, err, f(err), fmt.Sprintf("tag %d should be in error %s", i, err.Error()))
					} else {
						require.Nil(t, f(err), fmt.Sprintf("tag %d should not be in error %s", i, err.Error()))
					}
				}
			}
		})
	})

	t.Run("wrapped errors", func(t *testing.T) {
		t.Parallel()
		t.Run("check", func(t *testing.T) {
			t.Parallel()
			for i, f := range isins {
				for j, wrappedErrs := range wrapped {
					for k, err := range wrappedErrs {
						if i == j || i == k {
							require.True(t, f(err), fmt.Sprintf("tag %d should be in error %s", i, err.Error()))
						} else {
							require.False(t, f(err), fmt.Sprintf("tag %d should not be in error %s", i, err.Error()))
						}
					}
				}
			}
		})
		t.Run("extract", func(t *testing.T) {
			t.Parallel()
			for i, f := range extractors {
				for j, wrappedErrs := range wrapped {
					for k, err := range wrappedErrs {
						if i == j {
							require.Equal(t, err, f(err), fmt.Sprintf("tag %d should be in error %s", i, err.Error()))
							require.NotEqual(t, errs[i], f(err), fmt.Sprintf("tag %d should be in error %s", i, err.Error()))
						} else if i == k {
							require.NotEqual(t, err, f(err), fmt.Sprintf("tag %d should be in error %s", i, err.Error()))
							require.Equal(t, errs[i], f(err), fmt.Sprintf("tag %d should be in error %s", i, err.Error()))
						} else {
							require.Nil(t, f(err), fmt.Sprintf("tag %d should not be in error %s", i, err.Error()))
						}
					}
				}
			}
		})

	})
}

func TestIsTagged(t *testing.T) {
	t.Parallel()
	tag0 := errs2.Tag0("tag")
	tag1 := errs2.Tag1[int]("tag1")
	tag2 := errs2.Tag2[string, uint]("tag2")

	untaggedErrs := []error{
		fmt.Errorf("fmt error"),
		errors.New("errors package"),
	}
	for _, err := range untaggedErrs {
		require.False(t, errs2.IsTagged(err), err.Error())
	}

	taggedErrs := []error{
		tag0.New("something"),
		tag1.New(1, "something else"),
		tag2.New("param", 0, "yet another thing"),
	}
	for i, err := range slices.Clone(untaggedErrs) {
		taggedErrs = append(taggedErrs, errs2.Wrapf(err, "wrapped untagged %d", i))
	}
	for i, err := range slices.Clone(taggedErrs) {
		taggedErrs = append(taggedErrs, errs2.Wrapf(err, "wrapped tagged %d", i))
	}

	for _, err := range taggedErrs {
		require.True(t, errs2.IsTagged(err), err.Error())
	}
}

func TestTagWrapping(t *testing.T) {
	t.Parallel()
	tag0 := errs2.Tag0("tag")
	tag1 := errs2.Tag1[int]("tag1")
	tag2 := errs2.Tag2[string, uint]("tag2")

	a := fmt.Errorf("A")
	b := tag0.Wrap(a, "B")
	c := tag1.Wrap(b, 1, "C")
	d := tag2.Wrap(c, "param", 0, "D")

	chain := []error{d, c, b, a}

	t.Run("cause", func(t *testing.T) {
		t.Parallel()
		expected := a
		for i, x := range chain {
			if i < len(chain)-1 {
				err, ok := x.(errs2.Wrapped0Error)
				require.True(t, ok)
				require.Equal(t, expected, err.Cause())
			} else {
				_, ok := x.(errs2.Wrapped0Error)
				require.False(t, ok)
				require.Equal(t, expected, x)
			}
		}
	})

	t.Run("unwrap", func(t *testing.T) {
		for i, x := range chain {
			if i < len(chain)-1 {
				err, ok := x.(errs2.Wrapped0Error)
				require.True(t, ok)
				require.Equal(t, chain[i+1], err.Unwrap())
			} else {
				_, ok := x.(errs2.Wrapped0Error)
				require.False(t, ok)
			}
		}
	})
}
