package SR

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
	"strings"
	"sync"
	"time"
)

const MSS int = 512 // max segment size

var incSeq sync.Mutex

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
func (r *RdtConn) WriteUDP(ct []byte) error {
	var ret []byte
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, r.header.Seq)
	ret = append(ret, buf.Bytes()...)
	buf = bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, r.header.Ack)
	ret = append(ret, buf.Bytes()...)
	ret = append(ret, ct...)
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

func (r *RdtConn) Read() error {
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
	r.content = b[8:]
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

const (
	UNKNOWN = iota
	PUT
	GET
)

type Server struct {
	laddr  string
	style  int
	sendwd *SlidingWindow
	recvwd *SlidingWindow
}

func NewServer(laddr string, windowSize int32) *Server {
	return &Server{
		laddr:  laddr,
		style:  UNKNOWN,
		sendwd: NewSlidingWindow(windowSize),
		recvwd: NewSlidingWindow(windowSize),
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
var content []byte
var endsingal int32

func (s *Server) Handle(conn *net.UDPConn) {
	rdt := NewRdtConn(conn)
	rdt.ReadHeaderUDP()
	ctn := string(rdt.content)
	if rand.Intn(100) < 10 {
		return
	}
	log.Println("Recive ", rdt.header.Seq)
	if s.style == PUT {
		if rdt.header.Seq < s.recvwd.base {
			rdt.header.Ack = rdt.header.Seq
			rdt.WriteHeaderUDP()
			return
		} else if rdt.header.Seq >= s.recvwd.base+s.recvwd.size {
			// log.Println("4ACK:", rdt.header.Ack)
			return
		}
		// if eof([]byte(ctn)) {
		// 	rdt.header.Ack = rdt.header.Seq
		// 	rdt.WriteHeaderUDP()

		// 	// log.Println("1ACK:", rdt.header.Ack)
		// 	return
		// }
		if s.recvwd.Recv(*rdt) {
			if eof([]byte(ctn)) {
				endsingal = rdt.header.Seq
			} else {
				content = append(content, s.recvwd.Sliding()...)
			}
			rdt.header.Ack = rdt.header.Seq
			rdt.WriteHeaderUDP()
			if endsingal != -1 {
				for i := s.recvwd.base; i <= endsingal; i++ {
					if s.recvwd.ack[i-s.recvwd.base] != true {
						return
					}
				}
				err := ioutil.WriteFile(filename, content, 0666)
				// log.Println(string(content))
				if err != nil {
					log.Println(err)
				}
				log.Println("Finish upload")
				// log.Println(s.recvwd.seq, len(s.recvwd.seq))
				s.style = UNKNOWN
				content = nil
				filename = ""
				s.recvwd = NewSlidingWindow(s.recvwd.size)
			}
			return
		}
	}

	if ctn == "-time" {
		s.style = UNKNOWN
		rdt.header.Ack = rdt.header.Seq
		// log.Println(rdt.header)
		rdt.WriteUDP([]byte(time.Now().String()))

	} else if ctn == "-quit" {
		s.style = UNKNOWN
		rdt.header.Ack = rdt.header.Seq
		rdt.WriteUDP([]byte("Good bye!"))
		s.recvwd = NewSlidingWindow(s.recvwd.size)
		s.sendwd = NewSlidingWindow(s.sendwd.size)
	} else if strings.HasPrefix(ctn, "-put") {
		s.style = PUT
		filename = strings.TrimPrefix(ctn, "-put ")
		rdt.header.Ack = rdt.header.Seq
		rdt.WriteHeaderUDP()
		s.recvwd = NewSlidingWindow(s.recvwd.size)
		endsingal = -1
	}
	// log.Println("ACK:", rdt.header.Ack)
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
	_, _, err = r.conn.ReadFromUDP(ret[0:])
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
	sendwd   *SlidingWindow
	recvwd   *SlidingWindow
}

func NewClient(ad string, fn string, windowSize int32, to time.Duration) *Client {
	return &Client{
		address:  ad,
		filename: fn,
		timeout:  to,
		sendwd:   NewSlidingWindow(windowSize),
		recvwd:   NewSlidingWindow(windowSize),
	}
}

func (c *Client) Start(cmd string) {
	udpAddr, err := net.ResolveUDPAddr("udp4", c.address)
	if err != nil {
		panic(err)
	}
	if cmd == "-time" || cmd == "-quit" {
		conn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			panic(err)
		}
		rdt := NewRdtConn(conn)
		rdt.header.Seq = int32(0)
		ww := []byte(cmd)
		rdt.Write(ww)
		log.Println("Send Seq :", rdt.header.Seq)
		go rdt.Read()
		for {
			select {
			case <-rdt.read:
				log.Println("Recived: ", rdt.header.Ack)
				if rdt.header.Ack != int32(0) {
					rdt.Write(ww)
					log.Println("Send Seq :", rdt.header.Seq)
				} else {
					log.Println(string(rdt.content))
					goto l1
				}
			case <-time.After(c.timeout):
				log.Println("TimeOut")
				rdt.Write(ww)
				log.Println("Send Seq :", rdt.header.Seq)
			}
		}
	} else if cmd == "-put" {
		conn, err := net.DialUDP("udp", nil, udpAddr)
		rdt := NewRdtConn(conn)
		rdt.header.Seq = int32(0)
		ww := []byte(cmd + " " + c.filename)
		rdt.Write(ww)
		log.Println("Send Seq :", rdt.header.Seq)
		go rdt.ReadHeader()
		for {
			select {
			case <-rdt.read:
				log.Println("Recived: ", rdt.header.Ack)
				if rdt.header.Ack != int32(0) {
					rdt.Write(ww)
					log.Println("Send Seq :", rdt.header.Seq)
				} else {
					goto l2
				}
			case <-time.After(c.timeout):
				log.Println("TimeOut")
				rdt.Write(ww)
				log.Println("Send Seq :", rdt.header.Seq)
			}
		}
	l2:
		ct, err := ioutil.ReadFile(c.filename)
		if err != nil {
			log.Println(err)
			return
		}
		c.sendwd = NewSlidingWindow(c.sendwd.size)
		numseg := int(math.Ceil(float64(len(ct)) / float64(MSS)))
		for i := 0; i < numseg+1; i++ {
			var ww []byte

			if i == numseg {
				ww = []byte{}
			} else if i == numseg-1 {
				ww = ct[i*MSS:]
			} else {
				ww = ct[i*MSS : (i+1)*MSS]
			}
			if c.sendwd.nextSeq < c.sendwd.base+c.sendwd.size {
				log.Println(c.sendwd.base, i)
				conn, err := net.DialUDP("udp", nil, udpAddr)
				if err != nil {
					panic(err)
				}
				rdt := NewRdtConn(conn)
				rdt.header.Seq = c.sendwd.nextSeq
				c.sendwd.nextSeq++
				rdt.Write(ww)
				log.Println("Send Seq :", rdt.header.Seq)
				go func() {
					go rdt.ReadHeader()
					for {
						select {
						case <-rdt.read:
							log.Println("Recived", rdt.header.Ack)
							if rdt.header.Ack != rdt.header.Seq {
								rdt.Write(ww)
								log.Println("Resend Seq :", rdt.header.Seq)
							} else {
								goto l3
							}
						case <-time.After(c.timeout):
							log.Println("TimeOut")
							rdt.Write(ww)
							log.Println("Resend Seq :", rdt.header.Seq)

						}
					}
				l3:
					// log.Println("!!!!!!!!!!")
					incSeq.Lock()
					if rdt.header.Ack < c.sendwd.base+c.sendwd.size && rdt.header.Ack >= c.sendwd.base {
						c.sendwd.ack[rdt.header.Ack-c.sendwd.base] = true
					}
					// log.Println(c.sendwd.base, c.sendwd.ack)
					c.sendwd.Sliding()
					// log.Println(c.sendwd.base, c.sendwd.ack)
					incSeq.Unlock()
				}()
			} else {
				i--
			}
			// time.Sleep(time.Second)
		}
	}
l1:
	defer func() {

		// conn.Close()
	}()

}

/*func (c *Client) Send(w []byte, udpAddr *net.UDPAddr) {
	log.Println("!!!!!!", c.sendwd.base, c.sendwd.nextSeq)
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		panic(err)
	}
	rdt := NewRdtConn(conn)
	incSeq.Lock()
	rdt.header.Seq = c.sendwd.nextSeq
	c.sendwd.nextSeq++
	// log.Println("!!!!!!", c.sendwd.base, c.sendwd.nextSeq)
	incSeq.Unlock()

}*/
func eof(c []byte) bool {
	for _, v := range c {
		if v != 0 {
			return false
		}
	}
	return true
}
