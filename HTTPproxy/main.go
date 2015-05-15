package main

import (
	"bytes"
	"encoding/gob"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"sync"
)

var port = flag.String("p", "8888", "port")
var cache *Cache
var cacheWrite sync.Mutex

func Handle(conn net.Conn) {
	proxyer := NewProxy()
	proxyer.Start(conn)
	// log.Println("Writing to Cache")
	// log.Println(cache)
	cache.Write()
}

func serve() {
	listener, err := net.Listen("tcp", ":"+*port)
	log.Println("Start To Listening 127.0.0.1:" + *port)
	if err != nil {
		panic(err)
	}
	defer func() {
		listener.Close()

	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Connect error: %v", err)
		}
		go Handle(conn)
	}
}

func main() {
	flag.Parse()
	data, err := ioutil.ReadFile("cache.bk")
	if err != nil {
		log.Printf("Read Cache Error: %v", err)
		return
	}
	cache = NewCache()
	if len(data) != 0 {
		if err := Decode(data, cache); err != nil {
			log.Printf("Cache Decode Error: %v", err)
			return
		}
	}
	cacheWrite = sync.Mutex{}
	serve()
}

func Encode(data interface{}) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(data)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func Decode(data []byte, to interface{}) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(to)
}
