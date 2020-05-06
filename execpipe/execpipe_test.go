package execpipe

import (
	"bytes"
	"context"
	"log"
	"testing"
)

func TestCommand(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	err := Command(
		ctx,
		&buf,
		&buf,
		[]string{"echo", "1"},
		[]string{"grep", "2"},
	)
	if err == nil {
		log.Fatal(err)
	}
	if buf.String() != "" {
		log.Fatal("output is not empty.")
	}

	var buf2 bytes.Buffer
	err = Command(
		ctx,
		&buf2,
		&buf2,
		[]string{"echo", "1"},
		[]string{"rmdir", "tmptmptmp"},
	)
	if err == nil {
		log.Fatal(err)
	}
	if buf2.String() == "" {
		log.Fatal("output is empty.")
	}
}
