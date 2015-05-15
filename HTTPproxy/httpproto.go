package main

type HTTPHeader map[string]string

type Request struct {
	Method  string
	URI     string
	Version string
	Headers HTTPHeader
}

type Response struct {
	Version string
	Status  int
	Phrase  string
	Headers HTTPHeader
}

var ResponseOK = &Response{
	Version: "HTTP/1.1",
	Status:  200,
	Phrase:  "OK",
}

var ResponseMP = &Response{
	Version: "HTTP/1.1",
	Status:  301,
	Phrase:  "Moved Permanently",
}

var ResponseBadRequest = &Response{
	Version: "HTTP/1.1",
	Status:  400,
	Phrase:  "Bad Request",
}

var ResponseNotFound = &Response{
	Version: "HTTP/1.1",
	Status:  404,
	Phrase:  "Not Found",
}

var ResponseInternalError = &Response{
	Version: "HTTP/1.1",
	Status:  500,
	Phrase:  "Internal Server Error",
}

var ResponseNotSupport = &Response{
	Version: "HTTP/1.1",
	Status:  505,
	Phrase:  "HTTP Version Not Supported",
}

func RemoveHopByHopHeaders(h HTTPHeader) {
	delete(h, "connection")
	delete(h, "keep-alive")
	delete(h, "proxy-authenticate")
	delete(h, "proxy-authorization")
	delete(h, "te")
	delete(h, "trailer")
	delete(h, "transfer-encoding")
	delete(h, "upgrade")

	delete(h, "proxy-connection")
}
