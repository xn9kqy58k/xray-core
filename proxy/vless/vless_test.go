package vless_test

import (
	"bytes"
	"crypto/tls"
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/reality"
	"github.com/xtls/xray-core/proxy/vless"
)

type inlineTLSBuffers struct {
	net.Conn
	input    bytes.Reader
	rawInput bytes.Buffer
}

type pointerTLSBuffers struct {
	net.Conn
	input    bytes.Reader
	rawInput *bytes.Buffer
}

func TestAccessTLSBuffers(t *testing.T) {
	for _, test := range []struct {
		name string
		conn net.Conn
	}{
		{name: "standard_tls", conn: &tls.Conn{}},
		{name: "utls", conn: &utls.Conn{}},
		{name: "reality", conn: &reality.Conn{}},
		{name: "inline_layout", conn: &inlineTLSBuffers{}},
		{name: "pointer_layout", conn: &pointerTLSBuffers{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			input, rawInput := vless.AccessTLSBuffers(test.conn)
			input.Reset([]byte("decrypted"))
			if *rawInput == nil {
				*rawInput = new(bytes.Buffer)
			}
			(*rawInput).WriteString("encrypted")

			// A second access must refer to the connection's real buffers, not
			// copies. For a pointer field, this also verifies initialization
			// through the returned **bytes.Buffer updates the connection.
			inputAgain, rawAgain := vless.AccessTLSBuffers(test.conn)
			if inputAgain != input {
				t.Fatal("input does not refer to the same connection field")
			}
			if *rawAgain != *rawInput {
				t.Fatal("rawInput does not refer to the same connection buffer")
			}
			if inputAgain.Len() != len("decrypted") || (*rawAgain).String() != "encrypted" {
				t.Fatal("connection buffers lost their contents")
			}
			(*rawAgain).WriteString(" tail")
			if (*rawInput).String() != "encrypted tail" {
				t.Fatal("rawInput mutations are not shared")
			}
		})
	}
}
