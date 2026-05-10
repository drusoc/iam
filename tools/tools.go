//go:build tools

// Используем название бинарника отличное от gomock,
// чтобы никто не вызывал gomock, установленный локально
//go:generate go build -o ../bin/mocks go.uber.org/mock/mockgen

// Package tools contains go:generate commands for all project tools with versions stored in local go.mod file
// See https://github.com/golang/go/wiki/Modules#how-can-i-track-tool-dependencies-for-a-module
package tools

import (
	_ "go.uber.org/mock/mockgen"
)
