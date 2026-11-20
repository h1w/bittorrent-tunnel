//go:build !linux

package purego

import "golang.org/x/net/ipv4"

func (*udpWriteBatch) trySegment([]ipv4.Message) bool { return false }
