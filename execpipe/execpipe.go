package execpipe

import (
	"context"
	"io"
	"os/exec"
	"sync"
)

// Writer : io.Writer with sync.Mutex
type Writer struct {
	w io.Writer
	m *sync.Mutex
}

func (w *Writer) Write(p []byte) (n int, err error) {
	w.m.Lock()
	defer w.m.Unlock()
	return w.w.Write(p)
}

// Command : Copy from mattn/go-pipeline
func Command(ctx context.Context, stdout, stderr io.Writer, commands ...[]string) error {
	cmds := make([]*exec.Cmd, len(commands))
	var err error
	m := &sync.Mutex{}
	outWriter := &Writer{stdout, m}
	errWriter := &Writer{stderr, m}
	for i, c := range commands {
		cmds[i] = exec.CommandContext(ctx, c[0], c[1:]...)
		if i > 0 {
			if cmds[i].Stdin, err = cmds[i-1].StdoutPipe(); err != nil {
				return err
			}
		}
		cmds[i].Stderr = errWriter
	}
	cmds[len(cmds)-1].Stdout = outWriter
	for _, c := range cmds {
		if err = c.Start(); err != nil {
			return err
		}
	}
	for _, c := range cmds {
		if err = c.Wait(); err != nil {
			return err
		}
	}
	return nil
}
