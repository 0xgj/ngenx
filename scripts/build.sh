#!/bin/bash
set -x

GIT_COMMIT="$(git rev-parse HEAD)"
DEPS=$(go list -f '{{range .TestImports}}{{.}} {{end}}' ./...)
go get $DEP_ARGS ./... $DEPS
go build -ldflags "-X main.GitCommit='${GIT_COMMIT}'"
