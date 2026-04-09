package main

import (
	"archive/zip"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"
)

func getPayloadOffset(filename string) (int64, error) {
	zipReader, err := zip.OpenReader(filename)
	if err != nil {
		return 0, fmt.Errorf("not a valid zip archive: %s: %v", filename, err)
	}
	defer zipReader.Close()

	for _, file := range zipReader.Reader.File {
		if file.Name == "payload.bin" && file.UncompressedSize64 > 0 {
			offset, err := file.DataOffset()
			if err != nil {
				return 0, fmt.Errorf("failed to get data offset: %w", err)
			}
			return offset, nil
		}
	}

	return 0, fmt.Errorf("payload.bin not found inside archive")
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	var (
		list            bool
		partitions      string
		outputDirectory string
		concurrency     int
	)

	flag.IntVar(&concurrency, "c", 4, "Number of multiple workers to extract (shorthand)")
	flag.IntVar(&concurrency, "concurrency", 4, "Number of multiple workers to extract")
	flag.BoolVar(&list, "l", false, "Show list of partitions in payload.bin (shorthand)")
	flag.BoolVar(&list, "list", false, "Show list of partitions in payload.bin")
	flag.StringVar(&outputDirectory, "o", "", "Set output directory (shorthand)")
	flag.StringVar(&outputDirectory, "output", "", "Set output directory")
	flag.StringVar(&partitions, "p", "", "Dump only selected partitions (comma-separated) (shorthand)")
	flag.StringVar(&partitions, "partitions", "", "Dump only selected partitions (comma-separated)")
	flag.Parse()

	if flag.NArg() == 0 {
		usage()
	}
	filename := flag.Arg(0)

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		log.Fatalf("File does not exist: %s\n", filename)
	}

	payloadBin := filename
	var payloadOffset int64 = 0

	if strings.HasSuffix(filename, ".zip") {
		offset, err := getPayloadOffset(filename)
		if err != nil {
			log.Fatalf("Failed to map payload.bin from archive: %v\n", err)
		}
		payloadOffset = offset
		fmt.Printf("Mapped payload.bin from zip at data offset: %d\n", payloadOffset)
	} else {
		fmt.Printf("payload.bin: %s\n", payloadBin)
	}

	payload := NewPayload(payloadBin)
	payload.BaseOffset = payloadOffset
	if err := payload.Open(); err != nil {
		log.Fatal(err)
	}
	defer payload.Close()
	payload.Init()

	if list {
		return
	}

	now := time.Now()

	targetDirectory := outputDirectory
	if targetDirectory == "" {
		targetDirectory = fmt.Sprintf("extracted_%d%02d%02d_%02d%02d%02d", now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
	}
	if _, err := os.Stat(targetDirectory); os.IsNotExist(err) {
		if err := os.Mkdir(targetDirectory, 0o755); err != nil {
			log.Fatal("Failed to create target directory")
		}
	}

	payload.SetConcurrency(concurrency)
	fmt.Printf("Number of workers: %d\n", payload.GetConcurrency())

	if partitions != "" {
		if err := payload.ExtractSelected(targetDirectory, strings.Split(partitions, ",")); err != nil {
			log.Fatal(err)
		}
	} else {
		if err := payload.ExtractAll(targetDirectory); err != nil {
			log.Fatal(err)
		}
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options] [inputfile]\n", os.Args[0])
	flag.PrintDefaults()
	os.Exit(2)
}
