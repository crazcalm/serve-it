package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

var root = flag.String("url", "", "Site you want to curl?")
var headers = flag.Bool("header", false, "Show headers")

func formatURL(site string) string {
	if !strings.HasPrefix(site, "http://") || !strings.HasPrefix(site, "https://") {
		return "http://" + site
	}
	return site
}

func main() {
	flag.Parse()
	site := formatURL(*root)
	fmt.Printf("site: %s\n", site)

	resp, err := http.Get(site)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if *headers {
		fmt.Printf("Headers: %v\n", resp.Header)
	}
	fmt.Println(string(body))

}
