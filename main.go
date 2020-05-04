package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/mackerelio/checkers"
)

// Version by Makefile
var Version string

type cmdOpts struct {
	Host       string        `short:"H" long:"host" default:"localhost" description:"Hostname"`
	Port       string        `short:"p" long:"port" default:"443" description:"Port"`
	ServerName string        `long:"servername" default:"" description:"servername in ClientHello"`
	Timeout    time.Duration `long:"timeout" default:"5s" description:"Timeout to connect mysql"`
	RSA        bool          `long:"rsa" description:"Preferred aRSA cipher to use"`
	ECDSA      bool          `long:"ecdsa" description:"Preferred aECDSA cipher to use"`
	Crit       int64         `short:"c" long:"critical" default:"14" description:"The critical threshold in days before expiry"`
	Warn       int64         `short:"w" long:"warning" default:"30" description:"The threshold in days before expiry"`
}

var layout = "Jan 2 15:04:05 2006 MST"
var notAfterRegexp = regexp.MustCompile(`notAfter=(.+)$`)

// Buffer for openssl s_client | openssl x509
type Buffer struct {
	b bytes.Buffer
	m sync.Mutex
}

func (b *Buffer) Write(p []byte) (n int, err error) {
	b.m.Lock()
	defer b.m.Unlock()
	return b.b.Write(p)
}

func (b *Buffer) String() string {
	b.m.Lock()
	defer b.m.Unlock()
	out := strings.TrimRight(b.b.String(), "\n")
	out = strings.NewReplacer(
		"\r\n", "\\r\\n",
		"\r", "\\r",
		"\n", "\\n",
	).Replace(out)
	return out
}

// GetNotAfter parse and get NotAfter
func (b *Buffer) GetNotAfter() (time.Time, error) {
	s := b.String()
	match := notAfterRegexp.FindAllStringSubmatch(s, -1)
	if len(match) != 1 {
		return time.Time{}, fmt.Errorf("Output not >contain notAfter=: %s", s)
	}

	notAfter, err := time.Parse(layout, match[0][1])
	if err != nil {
		return time.Time{}, err
	}
	return notAfter, nil
}

// runCommand : Copy from mattn/go-pipeline
func runPipeline(ctx context.Context, stdout, stderr io.Writer, commands ...[]string) error {
	cmds := make([]*exec.Cmd, len(commands))
	var err error

	for i, c := range commands {
		cmds[i] = exec.CommandContext(ctx, c[0], c[1:]...)
		if i > 0 {
			if cmds[i].Stdin, err = cmds[i-1].StdoutPipe(); err != nil {
				return err
			}
		}
		cmds[i].Stderr = stderr
	}
	cmds[len(cmds)-1].Stdout = stdout
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

func getNotAfter(opts cmdOpts) (*time.Time, error) {
	sClientCmd := []string{"openssl", "s_client"}
	if opts.ServerName != "" {
		sClientCmd = append(sClientCmd, "-servername")
		sClientCmd = append(sClientCmd, opts.ServerName)
	}
	sClientCmd = append(sClientCmd, "-connect")
	sClientCmd = append(sClientCmd, fmt.Sprintf("%s:%s", opts.Host, opts.Port))
	if opts.RSA && opts.ECDSA {
		return nil, fmt.Errorf("cannot use --rsa and --ecdsa at the same time")
	}
	if opts.RSA {
		sClientCmd = append(sClientCmd, "-cipher")
		sClientCmd = append(sClientCmd, "aRSA")
	}
	if opts.ECDSA {
		sClientCmd = append(sClientCmd, "-cipher")
		sClientCmd = append(sClientCmd, "aECDSA")
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()
	ch := make(chan time.Time, 1)
	errCh := make(chan error, 1)

	go func() {
		var buf Buffer
		err := runPipeline(
			ctx,
			&buf,
			&buf,
			[]string{"echo", "QUIT"},
			sClientCmd,
			[]string{"openssl", "x509", "-noout", "-dates"},
		)

		if err != nil {
			errCh <- fmt.Errorf("%s:%s", err, buf.String())
			return
		}

		notAfter, err := buf.GetNotAfter()
		if err != nil {
			errCh <- err
			return
		}

		ch <- notAfter
	}()

	select {
	case notAfter := <-ch:
		return &notAfter, nil
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		return nil, fmt.Errorf("Command timeout")
	}

}

func checkCertNet(opts cmdOpts) *checkers.Checker {
	notAfter, err := getNotAfter(opts)
	if err != nil {
		return checkers.Critical(err.Error())
	}

	daysRemain := int64(notAfter.Sub(time.Now().UTC()).Hours() / 24)
	msg := fmt.Sprintf("Expiration date: %s, %d days remaining", notAfter.Format("2006-01-02"), daysRemain)

	if daysRemain < opts.Crit {
		return checkers.Critical(msg)
	} else if daysRemain < opts.Warn {
		return checkers.Warning(msg)
	}
	return checkers.Ok(msg)
}

func main() {
	opts := cmdOpts{}
	psr := flags.NewParser(&opts, flags.Default)
	_, err := psr.Parse()
	if err != nil {
		os.Exit(1)
	}
	ckr := checkCertNet(opts)
	ckr.Name = "check-cert-net"
	ckr.Exit()
}
