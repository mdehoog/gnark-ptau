package main

import (
	"log"
	"os"

	ptau "github.com/mdehoog/gnark-ptau"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("Usage: %s [input.ptau] [output.ph1]", os.Args[0])
	}
	pt, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		_ = pt.Close()
	}()
	k, err := ptau.ToSRS(pt)
	if err != nil {
		log.Fatal(err)
	}
	out, err := os.Create(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		_ = out.Close()
	}()
	_, err = k.WriteTo(out)
	if err != nil {
		log.Fatal(err)
	}
}
