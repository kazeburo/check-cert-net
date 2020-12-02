VERSION=0.0.6
LDFLAGS=-ldflags "-w -s -X main.version=${VERSION}"

all: check-cert-net

check-cert-net: main.go execpipe/*.go
	go build $(LDFLAGS) -o check-cert-net main.go

linux: main.go execpipe/*.go
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o check-cert-net main.go

check:
	go test ./...

fmt:
	go fmt ./...

tag:
	git tag v${VERSION}
	git push origin v${VERSION}
	git push origin master
