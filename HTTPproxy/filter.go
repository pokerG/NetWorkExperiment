package main

import (
	json "github.com/bitly/go-simplejson"
	"io/ioutil"
)

type filter struct {
	*json.Json
}

func NewFilter() *filter {
	content, _ := ioutil.ReadFile("filter.json")
	js, _ := json.NewJson(content)
	return &filter{
		js,
	}
}

func (f *filter) FilterURL(url string) bool {
	if list, err := f.Get("url_filter").StringArray(); err == nil {
		for _, v := range list {
			v = appendPortIfNeeded(v)
			if v == url {
				return true
			}
		}
		return false
	}
	return false
}

func (f *filter) FilterUser(user string) bool {
	if list, err := f.Get("user_filter").StringArray(); err != nil {
		for _, v := range list {

			if v == user {
				return true
			}
		}
		return false
	}
	return false
}
