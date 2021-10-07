package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
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
	Host             string        `short:"H" long:"host" default:"localhost" description:"Hostname"`
	Port             string        `short:"p" long:"port" default:"443" description:"Port"`
	ServerName       string        `long:"servername" default:"" description:"servername in ClientHello"`
	VerifyServerName bool          `long:"verify-servername" description:"verify servername"`
	Timeout          time.Duration `long:"timeout" default:"5s" description:"Timeout to connect to server"`
	RSA              bool          `long:"rsa" description:"Preferred aRSA cipher to use"`
	ECDSA            bool          `long:"ecdsa" description:"Preferred aECDSA cipher to use"`
	Crit             int64         `short:"c" long:"critical" default:"14" description:"The critical threshold in days before expiry"`
	Warn             int64         `short:"w" long:"warning" default:"30" description:"The threshold in days before expiry"`
	Version          bool          `short:"v" long:"version" description:"Show version"`
}

type certInfo struct {
	notAfter *time.Time
	subjects []string
}

var layout = "Jan 2 15:04:05 2006 MST"

func fmtString(s string) string {
	out := strings.TrimRight(s, "\n")
	out = strings.NewReplacer(
		"\r\n", "\\r\\n",
		"\r", "\\r",
		"\n", "\\n",
	).Replace(out)
	return out
}

func getCertInfo(opts cmdOpts) (*certInfo, error) {
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
	ch := make(chan certInfo, 1)
	errCh := make(chan error, 1)

	go func() {
		var buf bytes.Buffer
		var ebuf bytes.Buffer
		err := execpipe.Command(
			ctx,
			&buf,
			&ebuf,
			[]string{"echo", "QUIT"},
			sClientCmd,
			[]string{"openssl", "x509", "-noout", "-text"},
		)
		if err != nil {
			errCh <- fmt.Errorf("%s:%s", err, fmtString(ebuf.String()))
			return
		}
		s := bufio.NewScanner(&buf)
		subjects := make([]string, 0)
		ms := make(map[string]struct{})
		var notAfter *time.Time
		prev := ""
		for s.Scan() {
			l := strings.TrimSpace(s.Text())
			if strings.Index(l, "Subject: CN=") == 0 {
				cn := l[len("Subject: CN="):]
				subjects = append(subjects, cn)
			}
			if strings.Index(l, "Not After : ") == 0 {
				na, err := time.Parse(layout, l[len("Not After : "):])
				if err != nil {
					errCh <- fmt.Errorf("%s:%s", err, l)
				}
				notAfter = &na
			}
			if strings.Index(prev, "Subject Alternative Name:") > 0 {
				if strings.Index(l, "DNS:") == 0 {
					for _, d := range strings.Split(l, ",") {
						d2 := strings.TrimSpace(d)
						if strings.Index(d2, "DNS:") == 0 {
							d3 := d2[len("DNS:"):]
							if _, ok := ms[d3]; !ok {
								subjects = append(subjects, d3)
								ms[d3] = struct{}{}
							}
						}
					}
				}
			}
			prev = l
		}
		if notAfter == nil {
			errCh <- fmt.Errorf("could not find notAfter in result")
			return
		}
		ch <- certInfo{notAfter, subjects}
	}()

	select {
	case ci := <-ch:
		return &ci, nil
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		return nil, fmt.Errorf("command timeout")
	}

}

func checkCertNet(opts cmdOpts) *checkers.Checker {
	cert, err := getCertInfo(opts)
	if err != nil {
		return checkers.Critical(err.Error())
	}

	if opts.VerifyServerName {
		verifiedHostname := false
		for _, d := range cert.subjects {
			if strings.Index(d, "*.") == 0 {
				d2 := strings.Split(d, ".")
				s2 := strings.Split(opts.ServerName, ".")
				if strings.Join(d2[1:], ".") == strings.Join(s2[1:], ".") {
					verifiedHostname = true
					break
				}
			} else if d == opts.ServerName {
				verifiedHostname = true
				break
			}
		}
		if !verifiedHostname {
			return checkers.Critical(fmt.Sprintf("servername:%s is not included in %s", opts.ServerName, strings.Join(cert.subjects, ",")))
		}
	}

	daysRemain := int64(cert.notAfter.Sub(time.Now().UTC()).Hours() / 24)
	msg := fmt.Sprintf("Expiration date: %s, %d days remaining", cert.notAfter.Format("2006-01-02"), daysRemain)

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
