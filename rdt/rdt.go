package rdt

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"net"
	"time"
)

const MSS int = 1024 // max segment size

type RdtConn struct {
	conn    *net.UDPConn
	addr    *net.UDPAddr
	header  *Header
	content []byte
	length  int
	read    chan bool
}

func NewRdtConn(conn *net.UDPConn) *RdtConn {
	return &RdtConn{
		conn:   conn,
		header: &Header{},
		read:   make(chan bool),
	}
}

func (r *RdtConn) ReadHeaderUDP() error {
	b := make([]byte, 8+MSS)
	var err error
	r.length, r.addr, err = r.conn.ReadFromUDP(b[0:])
	r.content = b[8:r.length]
	if err != nil {
		return err
	}
	buf := bytes.NewBuffer(b[:4])
	err = binary.Read(buf, binary.LittleEndian, &(r.header.Seq))
	if err != nil {
		return err
	}
	buf = bytes.NewBuffer(b[4:])
	err = binary.Read(buf, binary.LittleEndian, &(r.header.Ack))
	if err != nil {
		return err
	}
	return nil
}
func (r *RdtConn) WriteHeaderUDP() error {
	var ret []byte
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, r.header.Seq)
	ret = append(ret, buf.Bytes()...)
	buf = bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, r.header.Ack)
	ret = append(ret, buf.Bytes()...)
	_, err := r.conn.WriteToUDP(ret, r.addr)
	if err != nil {
		return err
	}
	return nil
}

func (r *RdtConn) ReadHeader() error {
	b := make([]byte, 8+MSS)
	if _, err := r.conn.Read(b[0:]); err != nil {
		r.read <- false
		return err
	}
	buf := bytes.NewBuffer(b[:4])
	err := binary.Read(buf, binary.LittleEndian, &(r.header.Seq))
	if err != nil {
		r.read <- false
		return err
	}
	buf = bytes.NewBuffer(b[4:8])
	err = binary.Read(buf, binary.LittleEndian, &(r.header.Ack))
	if err != nil {
		r.read <- false
		return err
	}
	r.read <- true
	return nil
}

func (r *RdtConn) Write(ct []byte) {
	var ret []byte
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, r.header.Seq)
	ret = append(ret, buf.Bytes()...)
	buf = bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, r.header.Ack)
	ret = append(ret, buf.Bytes()...)
	ret = append(ret, ct...)
	r.conn.Write(ret)
}

type Server struct {
	laddr string
	seq   int32
}

func NewServer(laddr string) *Server {
	return &Server{
		laddr: laddr,
		seq:   0,
	}
}
func (s *Server) Serve() {
	udpAddr, err := net.ResolveUDPAddr("udp4", s.laddr)
	log.Println("Start To Listening " + s.laddr)
	if err != nil {
		log.Println(err)
		panic(err)
	}
	defer func() {
		// listener.Close()
	}()
	conn, err := net.ListenUDP("udp", udpAddr)
	if err == nil {
		for {
			s.Handle(conn)
		}

	} else {
		log.Println(err)
	}

}

var filename string
var contt []byte

func (s *Server) Handle(conn *net.UDPConn) {
	rdt := NewRdtConn(conn)
	rdt.ReadHeaderUDP()
	log.Println("Recive Seq:", rdt.header.Seq)
	end := false
	if rdt.header.Seq == s.seq {
		if s.seq == 0 {
			filename = string(rdt.content)
			log.Println(filename)
		} else {
			if eof(rdt.content) {
				// log.Println(filename, contt)
				err := ioutil.WriteFile(filename, contt, 0666)
				log.Println(err)
				log.Println("Finish upload")
				end = true
			} else {
				// log.Println(rdt.content)
				contt = append(contt, rdt.content...)

			}
		}
		s.seq += 1
	}
	rdt.header.Ack = s.seq
	if rand.Intn(100) > 10 {
		rdt.WriteHeaderUDP()
	}
	if end {
		s.seq = 0
	}
}

func toBufioReader(r io.Reader) *bufio.Reader {
	if casted, ok := r.(*bufio.Reader); ok {
		return casted
	} else {
		return bufio.NewReader(r)
	}
}

func (r *RdtConn) BodyRead() []byte {
	var ret [MSS]byte
	var err error
	log.Println("@@@@@@@@@@@")
	_, _, err = r.conn.ReadFromUDP(ret[0:])
	log.Println("@@@@@@@@@@@")
	if err != nil {
		log.Println(err)
		return nil
	}
	return ret[0:]
}

type Client struct {
	address  string
	filename string
	timeout  time.Duration
}

func NewClient(ad string, fn string, to time.Duration) *Client {
	return &Client{
		address:  ad,
		filename: fn,
		timeout:  to,
	}
}

func (c *Client) Start() {
	ct, err := ioutil.ReadFile(c.filename)
	if err != nil {
		log.Println(err)
		return
	}
	numseg := int(math.Ceil(float64(len(ct)) / float64(MSS)))
	udpAddr, err := net.ResolveUDPAddr("udp4", c.address)
	if err != nil {
		panic(err)
	}
	// deadtime := <-time.After(c.timeout)
	for i := 0; i < numseg+2; i++ {
		conn, err := net.DialUDP("udp", nil, udpAddr)

		if err != nil {
			panic(err)
		}
		// err = conn.SetDeadline(deadtime)
		// log.Println(err)
		rdt := NewRdtConn(conn)
		rdt.header.Seq = int32(i)
		var ww []byte
		if i == 0 {
			ww = []byte(c.filename)
		} else if i == numseg {
			ww = ct[(i-1)*MSS:]
		} else if i == numseg+1 {
			ww = []byte{}
		} else {
			ww = ct[(i-1)*MSS : i*MSS]
		}
		rdt.Write(ww)
		log.Println("Send Seq :", rdt.header.Seq)
		go rdt.ReadHeader()
		for {
			select {
			case <-rdt.read:
				log.Println("Recived")
				if rdt.header.Ack != int32(i+1) {
					rdt.Write(ww)
					log.Println("Send Seq :", rdt.header.Seq)
				} else {
					goto l1
				}
			case <-time.After(c.timeout):
				log.Println("TimeOut")
				rdt.Write(ww)
				log.Println("Send Seq :", rdt.header.Seq)

			}
		}
	l1:
	}

	defer func() {

		// conn.Close()
	}()

}

func eof(c []byte) bool {
	for _, v := range c {
		if v != 0 {
			return false
		}
	}
	return true
}
