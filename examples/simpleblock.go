package main

import (
	"fmt"
	"log"

	"github.com/rikatz/go-modsecurity"
)

func main() {

	modsec, err := modsecurity.NewModsecurity()
	if err != nil {
		panic(err)
	}

	modsec.SetServerLogCallback(func(msg string) {
		log.Println(msg)
	})

	ruleset := modsec.NewRuleSet()
	err = ruleset.AddFile("basic_rules.conf")
	if err != nil {
		panic(err)
	}
	transaction, err := ruleset.NewTransaction("127.0.0.1:12345", "10.10.10.0:80")
	if err != nil {
		panic(err)
	}

	err = transaction.ProcessUri("http://www.modsecurity.org/test?key1=value1&key2=value2&key3=value3", "GET", "1.!")
	if err != nil {
		panic(err)
	}

	err = transaction.AddRequestHeader([]byte("HEADER1"), []byte("XPTO123"))
	if err != nil {
		panic(err)
	}

	err = transaction.ProcessRequestHeaders()

	if err != nil {
		panic(err)
	}

	err = transaction.ProcessLogging()

	if err != nil {
		panic(err)
	}

	shouldintervene := transaction.ShouldIntervene()
	fmt.Printf("%t", shouldintervene)

	transaction.Cleanup()
}
