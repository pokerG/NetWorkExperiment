package rdt

import (
	"bytes"
	// "net"
	// "bufio"
	"testing"
)

func TestWR(t *testing.T) {
	hd := &Header{Seq: 12303123, Ack: 884423}
	buf := bytes.NewBuffer([]byte{})
	hd.Write(buf)
	hd.Seq = 1
	hd.Ack = 1
	hd.Read(buf)
	if hd.Seq != 12303123 {
		t.Error("Seq Error", hd, buf.Bytes())
	}
	if hd.Ack != 884423 {
		t.Error("Ack Error", hd, buf.Bytes())
	}
}
