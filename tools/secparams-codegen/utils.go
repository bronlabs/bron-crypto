package main

import (
	"github.com/testcontainers/testcontainers-go"
	"io"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

type writerLogConsumer struct {
	w io.Writer
}

func newWriterLogConsumer(w io.Writer) testcontainers.LogConsumer {
	return &writerLogConsumer{w}
}

func (c *writerLogConsumer) Accept(log testcontainers.Log) {
	if log.LogType == "STDOUT" {
		_ = must(c.w.Write(log.Content))
	}
}
