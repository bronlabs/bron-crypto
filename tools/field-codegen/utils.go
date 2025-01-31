package main

import (
	"github.com/testcontainers/testcontainers-go"
	"io"
)

func Must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func MustOk[T any](v T, ok bool) T {
	if !ok {
		panic("not ok")
	}
	return v
}

func Must0(err error) {
	if err != nil {
		panic(err)
	}
}

type writerLogConsumer struct {
	w io.Writer
}

func NewWriterLogConsumer(w io.Writer) testcontainers.LogConsumer {
	return &writerLogConsumer{w}
}

func (c *writerLogConsumer) Accept(log testcontainers.Log) {
	if log.LogType == "STDOUT" {
		_ = Must(c.w.Write(log.Content))
	}
}
