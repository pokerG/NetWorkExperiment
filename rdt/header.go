package rdt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	// "net"
)

type Header struct {
	Seq int32
	Ack int32
}

func (h *Header) Write(w io.Writer) error {
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, h.Seq)
	_, err := w.Write(buf.Bytes())

	if err != nil {
		return err
	}
	buf = bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, h.Ack)
	_, err = w.Write(buf.Bytes())
	if err != nil {
		return err
	}
	return nil
}

func (h *Header) Read(r io.Reader) <-chan bool {
	fmt.Println("!!!!!!!")
	b := make([]byte, 8)
	ch := make(chan bool)
	if _, err := r.Read(b); err != nil {
		ch <- false
		fmt.Println("#####")
		return ch
	}
	fmt.Println("@@@@@")
	buf := bytes.NewBuffer(b[:4])
	err := binary.Read(buf, binary.LittleEndian, &(h.Seq))
	if err != nil {
		ch <- false
		fmt.Println("#####")
		return ch
	}
	buf = bytes.NewBuffer(b[4:])
	err = binary.Read(buf, binary.LittleEndian, &(h.Ack))
	if err != nil {
		ch <- false
		fmt.Println("#####")
		return ch
	}
	ch <- true
	fmt.Println("#####")
	return ch
}
