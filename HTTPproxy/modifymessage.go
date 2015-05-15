package main

import (
	"fmt"
	"io"
	"unicode"
)

func capitalizeHeader(h string) string {
	ret := make([]rune, len(h))
	cap := true
	for i, c := range h {
		r := rune(c)
		if cap && unicode.IsLetter(r) {
			ret[i] = unicode.ToUpper(r)
			cap = false
		} else {
			ret[i] = r
		}
		if c == '-' {
			cap = true
		}
	}
	return string(ret)
}

func writeHeaders(w io.Writer, h HTTPHeader) {
	for k, v := range h {
		fmt.Fprintf(w, "%s: %s\r\n", capitalizeHeader(k), v)
	}
	fmt.Fprintf(w, "\r\n")
}

func WriteRequest(w io.Writer, req *Request) {
	fmt.Fprintf(w, "%s %s %s\r\n", req.Method, req.URI, req.Version)
	writeHeaders(w, req.Headers)
}

func WriteResponse(w io.Writer, res *Response) {
	fmt.Fprintf(w, "%s %d %s\r\n", res.Version, res.Status, res.Phrase)
	writeHeaders(w, res.Headers)
}
