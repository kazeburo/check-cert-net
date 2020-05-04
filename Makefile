VERSION=0.0.2
LDFLAGS=-ldflags "-X main.Version=${VERSION}"

all: check-cert-net

check-cert-net: main.go
	go build $(LDFLAGS) -o check-cert-net main.go

linux: main.go
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o check-cert-net main.go

check:
	go test ./...

fmt:
	go fmt ./...

tag:
	git tag v${VERSION}
	git push origin v${VERSION}
	git push origin master
	goreleaser --rm-dist
