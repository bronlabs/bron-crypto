# Hagrid Transcript

This package implements a transcript functionality. We use this transcript object to glue protocols together and get a context-dependent string whenever one needs it. We DO NOT directly use this transcript as means to do Fiat-Shamir within the protocols.

### Transcript

Transcript is inspired by gtank/merlin, but without the Strobe.
* The initial state is a hash of the protocol name.
* Appending a message is done by hashing previous state and the message.
* ExtractBytes with output size is done by hashing the state with Cshake.

## Usage

```go
// Create a new transcript
t := NewTranscript("protocol_name")
// Append a message
t.AppendMessage("message label", []byte("message"))
// Extract bytes
t.ExtractBytes("output label", 32)
```

