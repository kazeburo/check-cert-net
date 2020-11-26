package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/kazeburo/check-cert-net/execpipe"
	"github.com/mackerelio/checkers"
)

// version by Makefile
var version string

type cmdOpts struct {
	Host       string        `short:"H" long:"host" default:"localhost" description:"Hostname"`
	Port       string        `short:"p" long:"port" default:"443" description:"Port"`
	ServerName string        `long:"servername" default:"" description:"servername in ClientHello"`
	Timeout    time.Duration `long:"timeout" default:"5s" description:"Timeout to connect mysql"`
	RSA        bool          `long:"rsa" description:"Preferred aRSA cipher to use"`
	ECDSA      bool          `long:"ecdsa" description:"Preferred aECDSA cipher to use"`
	Crit       int64         `short:"c" long:"critical" default:"14" description:"The critical threshold in days before expiry"`
	Warn       int64         `short:"w" long:"warning" default:"30" description:"The threshold in days before expiry"`
	Version    bool          `short:"v" long:"version" description:"Show version"`
}

var layout = "Jan 2 15:04:05 2006 MST"
var notAfterRegexp = regexp.MustCompile(`notAfter=(\w\w\w +\d+ \d\d:\d\d:\d\d \d\d\d\d \w\w\w)`)

func fmtString(s string) string {
	out := strings.TrimRight(s, "\n")
	out = strings.NewReplacer(
		"\r\n", "\\r\\n",
		"\r", "\\r",
		"\n", "\\n",
	).Replace(out)
	return out
}

func findNotAfter(s string) (time.Time, error) {
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
		var buf bytes.Buffer
		err := execpipe.Command(
			ctx,
			&buf,
			&buf,
			[]string{"echo", "QUIT"},
			sClientCmd,
			[]string{"openssl", "x509", "-noout", "-dates"},
		)
		s := fmtString(buf.String())
		if err != nil {
			errCh <- fmt.Errorf("%s:%s", err, s)
			return
		}

		notAfter, err := findNotAfter(s)
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

func printVersion() {
	fmt.Printf(`%s %s
Compiler: %s %s
`,
		os.Args[0],
		version,
		runtime.Compiler,
		runtime.Version())
}

func main() {
	opts := cmdOpts{}
	psr := flags.NewParser(&opts, flags.HelpFlag|flags.PassDoubleDash)
	_, err := psr.Parse()
	if opts.Version {
		printVersion()
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	ckr := checkCertNet(opts)
	ckr.Name = "check-cert-net"
	ckr.Exit()
}
