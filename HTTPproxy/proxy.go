package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

func appendPortIfNeeded(h string) string {
	// TODO: support https
	pos := strings.LastIndex(h, ":")
	if pos == -1 {
		return h + ":80"
	}
	p, err := strconv.Atoi(h[pos+1:])
	if err != nil || p == 0 {
		return h + ":80"
	}
	return h
}

func contentLength(h HTTPHeader) (int, error) {
	cls, ok := h["content-length"]
	if !ok {
		return 0, fmt.Errorf("No Content-Length")
	}
	cl, err := strconv.Atoi(cls)
	if err != nil {
		return 0, fmt.Errorf("Invalid Content-Length")
	}
	return cl, nil
}

func isTransferEncodingChunked(h HTTPHeader) bool {
	te, ok := h["transfer-encoding"]
	if !ok {
		return false
	}
	return te == "chunked"
}

func createBodyReader(r io.Reader, h HTTPHeader) BodyReader {
	if cl, err := contentLength(h); err == nil {
		return NewFixedLengthBodyReader(r, cl)
	}
	if isTransferEncodingChunked(h) {
		return NewChunkedBodyReader(r)
	}
	return nil
}

type DialerFunc func(string) (net.Conn, error)

// Used to connect server. Can be mocked.
var serverDialer = func(addr string) (net.Conn, error) {
	return net.Dial("tcp", addr)
}

type bodyTransfer struct {
	r      BodyReader
	p      io.Writer
	blk    *Block
	done   <-chan struct{}
	finish chan struct{}
	errCh  chan error
}

func newBodyTransfer(
	r BodyReader, p io.Writer, blk *Block, done <-chan struct{}) *bodyTransfer {
	t := &bodyTransfer{r, p, blk, done, make(chan struct{}), make(chan error)}
	go t.start()
	return t
}

func (t *bodyTransfer) sendError(err error) {
	//log.Printf("W body transfer is sending error: %v", err)
	select {
	case <-t.done:
	case t.errCh <- err:
	}
}

func (t *bodyTransfer) start() {
	defer close(t.finish)

	t.r.Start()
	for {
		select {
		case b := <-t.r.BodyReceived():
			if len(b) == 0 {
				return
			}
			n, err := t.p.Write(b)

			//cache
			if t.blk != nil {
				c := make([]byte, len(t.blk.Content)+len(b))
				copy(c, t.blk.Content)
				copy(c, b)
				t.blk.Content = c
			}

			if n != len(b) || err != nil {
				//log.Println("W bodyTransfer write failed")
				t.r.Cancel()
				return
			}
		case err := <-t.r.ErrorOccurred():
			if err != io.EOF {
				//log.Printf("E bodyTransfer read error: %v", err)
			}
			// this allows to close |t.finish| before sending err
			go t.sendError(err)
			return
		case <-t.done:
			t.r.Cancel()
			return
		}
	}
}

func (t *bodyTransfer) errorOccurred() <-chan error {
	return t.errCh
}

func (t *bodyTransfer) waitFinish() {
	//<-t.errCh // discard error if exists
	<-t.finish
}

// Proxy handles an HTTP request and serves as proxy
type Proxy struct {
	clientConn         net.Conn
	serverConn         net.Conn
	clientReader       *bufio.Reader
	serverReader       *bufio.Reader
	clientBodyTransfer *bodyTransfer
	serverBodyTransfer *bodyTransfer
	req                *Request
	res                *Response
	blk                *Block
	done               chan struct{}
}

type stateFunc func(*Proxy) stateFunc

func NewProxy() *Proxy {
	return &Proxy{
		clientConn:         nil,
		serverConn:         nil,
		clientReader:       nil,
		serverReader:       nil,
		clientBodyTransfer: nil,
		serverBodyTransfer: nil,
		req:                nil,
		res:                nil,
		blk:                nil,
		done:               make(chan struct{}),
	}
}

func (p *Proxy) Start(conn net.Conn) {
	p.clientConn = conn
	p.clientReader = bufio.NewReader(conn)

	for state := waitForRequest; state != nil; {
		state = state(p)
	}
}

func (p *Proxy) Cancel() {
	p.done <- struct{}{}
}

func (p *Proxy) dialToServer() error {
	host, ok := p.req.Headers["host"]
	if !ok {
		return fmt.Errorf("Missing host")
	}
	addr := appendPortIfNeeded(host)
	conn, err := serverDialer(addr)
	if err == nil {
		p.serverConn = conn
		p.serverReader = bufio.NewReader(conn)
	}
	return err
}

func (p *Proxy) requestReceived(req *Request) stateFunc {
	p.req = req

	if req.Method != "GET" && req.Method != "HEAD" && req.Method != "POST" {
		//log.Printf("E %s is not supported", req.Method)
		p.res = ResponseBadRequest // Should be appropriate response
		return sendErrorResponse
	}

	flt := NewFilter()
	if flt.FilterUser(p.clientConn.LocalAddr().String()) {
		log.Printf("User %s can't Proxy", p.serverConn.LocalAddr().String())
		p.res = ResponseBadRequest
		return finishProxy
	}

	host, ok := p.req.Headers["host"]
	if !ok {
		//log.Printf("Missing Host")
		p.res = ResponseBadRequest
		return sendErrorResponse
	}
	addr := appendPortIfNeeded(host)
	if flt.FilterURL(addr) {
		log.Printf("Host %s can't Proxy", addr)
		p.res = ResponseBadRequest
		return finishProxy
	}
	// log.Println("#######", p.req.URI)
	if blk := cache.Find(p.req.URI); p.req.Method == "GET" && blk != nil {
		// fmt.Println("!!!!!!!")
		p.req.Headers["if-modified-since"] = blk.LastModified
		p.blk = blk
	}

	if err := p.dialToServer(); err != nil {
		//log.Println(err)
		p.res = ResponseBadRequest
		return sendErrorResponse
	}

	log.Printf("I %s -> %s",
		p.clientConn.RemoteAddr().String(),
		p.serverConn.RemoteAddr().String())
	log.Printf("I %s", p.req.Headers["host"])

	RemoveHopByHopHeaders(p.req.Headers)
	WriteRequest(p.serverConn, req)

	br := createBodyReader(p.clientReader, p.req.Headers)
	if br == nil {
		br = NewClientConnectionWatcher(p.clientReader)
	}
	p.clientBodyTransfer = newBodyTransfer(br, p.serverConn, nil, p.done)

	return waitForResponse
}

func (p *Proxy) responseReceived(res *Response) stateFunc {
	// TODO: call RemoveHopByHopHeaders()
	useCache := false
	var blk *Block
	if res.Status == 304 {
		if p.blk != nil {
			p.res = &Response{Headers: make(map[string]string)}
			p.res.Headers["date"] = time.Now().Format(time.RFC1123)
			p.blk.LastExtract = time.Now()
			cache.Insert(p.req.URI, *p.blk)
			useCache = true
		}
	} else if res.Status == 200 {
		p.res = res
		data, _ := Encode(res)
		blk = NewBlock(data, p.res.Headers["last-modified"])
	}
	if p.res == nil {
		p.res = res
	}
	WriteResponse(p.clientConn, p.res)
	var br BodyReader
	if useCache {
		br = createBodyReader(bytes.NewReader(p.blk.Content), p.res.Headers)
	} else {
		br = createBodyReader(p.serverReader, p.res.Headers)
	}

	if br == nil {
	} else {
		p.serverBodyTransfer = newBodyTransfer(br, p.clientConn, blk, p.done)
	}

	return receiveBody
}

// state funcs

func waitForRequest(p *Proxy) stateFunc {
	r := NewRequestReader(p.clientReader)
	r.Start()
	for {
		select {
		case req := <-r.RequestReceived():
			return p.requestReceived(req)
		case err := <-r.ErrorOccurred():
			err.Error()
			//log.Println(err)
			p.res = ResponseInternalError
			return sendErrorResponse
		case <-p.done:
			return finishProxy
		}
	}
	panic("not reached")
}

func waitForResponse(p *Proxy) stateFunc {
	r := NewResponseReader(p.serverReader)
	r.Start()
	for {
		select {
		case res := <-r.ResponseReceived():
			return p.responseReceived(res)
		case err := <-r.ErrorOccurred():
			err.Error()
			//log.Println(err)
			p.res = ResponseInternalError
			return sendErrorResponse
		case err := <-p.clientBodyTransfer.errorOccurred():
			err.Error()
			//log.Printf("E client connection has an error: %v", err)
			return finishProxy
		case <-p.done:
			return finishProxy
		}
	}
	panic("not reached")
}

func receiveBody(p *Proxy) stateFunc {
	// client body transfer must be always non-nil.
	p.clientBodyTransfer.waitFinish()
	if p.serverBodyTransfer != nil {
		p.serverBodyTransfer.waitFinish()
		if p.serverBodyTransfer.blk != nil {
			cache.Insert(p.req.URI, *p.serverBodyTransfer.blk)
		}
	}

	return finishProxy
}

func sendErrorResponse(p *Proxy) stateFunc {
	//log.Printf("E sending error response: %v", p.res)
	WriteResponse(p.clientConn, p.res)
	return finishProxy
}

func finishProxy(p *Proxy) stateFunc {
	if p.clientConn != nil {
		p.clientConn.Close()
	}
	if p.serverConn != nil {
		p.serverConn.Close()
	}
	close(p.done)
	cache.Write()
	return nil
}
