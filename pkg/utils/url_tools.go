package utils

import (
	"log"
	"net/url"
)

func GetSchema(Url string) string {
	u, err := url.Parse(Url)
	if err != nil {
		log.Println(err)
		return ""
	}
	return u.Scheme
}
