package service

import (
	"fmt"
	"strings"
	"unicode"
)

// ValidateInterface checks a Linux interface name or prefix before saving it.
func ValidateInterface(name string, maxBytes int) error {
	if name == "" || len(name) > maxBytes || name == "." || name == ".." ||
		strings.ContainsAny(name, "/:") || strings.ContainsFunc(name, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r)
	}) {
		return fmt.Errorf("invalid TUN name: use 1–%d bytes without spaces, slashes or colons", maxBytes)
	}
	return nil
}
