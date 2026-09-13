package wg

import (
	"bytes"
	"fmt"

	"github.com/skip2/go-qrcode"
)

// QRPNG renders the peer config as a scannable PNG for phone apps
// (WireGuard → + → Create from QR code).
func QRPNG(conf string, size int) ([]byte, error) {
	if size <= 0 {
		size = 512
	}
	png, err := qrcode.Encode(conf, qrcode.Medium, size)
	if err != nil {
		return nil, fmt.Errorf("qr encode: %w", err)
	}
	return png, nil
}

// QRTerminal returns the config as terminal-friendly QR lines (half blocks).
func QRTerminal(conf string) (string, error) {
	q, err := qrcode.New(conf, qrcode.Medium)
	if err != nil {
		return "", fmt.Errorf("qr encode: %w", err)
	}
	q.DisableBorder = false
	var b bytes.Buffer
	m := q.Bitmap()
	// 2 rows per character using ▀ upper-half block for density.
	for y := 0; y < len(m); y += 2 {
		for x := 0; x < len(m[0]); x++ {
			top, bottom := m[y][x], false
			if y+1 < len(m) {
				bottom = m[y+1][x]
			}
			switch {
			case top && !bottom:
				b.WriteString("\033[7m \033[0m")
			case !top && bottom:
				b.WriteString("\033[7m▀\033[0m")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}
