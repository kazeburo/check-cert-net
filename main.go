package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
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

type cmdResult struct {
	StdOut []byte
	StdErr []byte
	Error  error
}

func (res *cmdResult) fmtStdErr() string {
	str := strings.TrimRight(string(res.StdErr), "\n")
	return strings.NewReplacer(
		"\r\n", "\\r\\n",
		"\r", "\\r",
		"\n", "\\n",
	).Replace(str)
}

func (res *cmdResult) fmtStdOut() string {
	str := strings.TrimRight(string(res.StdOut), "\n")
	return strings.NewReplacer(
		"\r\n", "\\r\\n",
		"\r", "\\r",
		"\n", "\\n",
	).Replace(str)
}

// runCommand :
func runCommand(ctx context.Context, commands ...[]string) ([]byte, []byte, error) {
	cmds := make([]*exec.Cmd, len(commands))
	var err error
	var stderr bytes.Buffer

	for i, c := range commands {
		cmds[i] = exec.CommandContext(ctx, c[0], c[1:]...)
		if i > 0 {
			if cmds[i].Stdin, err = cmds[i-1].StdoutPipe(); err != nil {
				return nil, stderr.Bytes(), err
			}
		}
		cmds[i].Stderr = &stderr
	}
	var out bytes.Buffer
	cmds[len(cmds)-1].Stdout = &out
	for _, c := range cmds {
		if err = c.Start(); err != nil {
			return nil, stderr.Bytes(), err
		}
	}
	for _, c := range cmds {
		if err = c.Wait(); err != nil {
			return nil, stderr.Bytes(), err
		}
	}
	return out.Bytes(), stderr.Bytes(), nil
}

func fetchDates(opts cmdOpts) (*time.Time, error) {
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
	ch := make(chan cmdResult, 1)
	var res cmdResult

	go func() {
		stdout, stderr, err := runCommand(
			ctx,
			[]string{"echo", "QUIT"},
			sClientCmd,
			[]string{"openssl", "x509", "-noout", "-dates"},
		)
		ch <- cmdResult{stdout, stderr, err}
	}()

	select {
	case res = <-ch:
		// nothing
	case <-ctx.Done():
		res = cmdResult{nil, nil, fmt.Errorf("Command timeout")}
	}

	if res.Error != nil {
		return nil, fmt.Errorf("%s: %s", res.Error.Error(), res.fmtStdErr())
	}

	r := regexp.MustCompile(`notAfter=(.+)$`)
	result := r.FindAllStringSubmatch(res.fmtStdOut(), -1)
	if len(result) != 1 {
		return nil, fmt.Errorf("Output not contain notAfter=: %s", res.fmtStdOut())
	}

	const layout = "Jan 2 15:04:05 2006 MST"
	notAfter, err := time.Parse(layout, result[0][1])
	if err != nil {
		return nil, err
	}
	return &notAfter, nil
}

func checkCertNet(opts cmdOpts) *checkers.Checker {
	notAfter, err := fetchDates(opts)
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
