package main

import (
	"flag"
	"github.com/pokerG/rdt"
)

var port = flag.String("p", ":8888", "port")

func main() {
	flag.Parse()
	server := rdt.NewServer(*port)
	server.Serve()
}
