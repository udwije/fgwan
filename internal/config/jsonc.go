package config

import (
	"bytes"
	"io"
)

// newCommentStripper lets the config file carry // line comments, which plain
// encoding/json rejects. String literals are left untouched.
func newCommentStripper(b []byte) io.Reader {
	out := make([]byte, 0, len(b))
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			out = append(out, c)
			continue
		}
		if c == '/' && i+1 < len(b) && b[i+1] == '/' {
			for i < len(b) && b[i] != '\n' {
				i++
			}
			if i < len(b) {
				out = append(out, '\n')
			}
			continue
		}
		out = append(out, c)
	}
	return bytes.NewReader(out)
}
