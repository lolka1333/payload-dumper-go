package main

import (
	"compress/bzip2"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	pathpkg "path/filepath"
	"sort"
	"sync"

	"github.com/klauspost/compress/zstd"

	humanize "github.com/dustin/go-humanize"
	"github.com/ulikunitz/xz"
	"github.com/vbauerster/mpb/v5"
	"github.com/vbauerster/mpb/v5/decor"
	"google.golang.org/protobuf/proto"

	"github.com/ssut/payload-dumper-go/chromeos_update_engine"
)

type request struct {
	partition       *chromeos_update_engine.PartitionUpdate
	targetDirectory string
}

// Payload is a new format for the Android OTA/Firmware update files since Android Oreo
type Payload struct {
	Filename   string
	BaseOffset int64

	file                 *os.File
	header               *payloadHeader
	deltaArchiveManifest *chromeos_update_engine.DeltaArchiveManifest
	signatures           *chromeos_update_engine.Signatures

	concurrency int

	metadataSize int64
	dataOffset   int64
	initialized  bool

	requests chan *request
	workerWG sync.WaitGroup
	progress *mpb.Progress
}

const (
	payloadHeaderMagic        = "CrAU"
	brilloMajorPayloadVersion = 2
	blockSize                 = 4096
)

type payloadHeader struct {
	Version              uint64
	ManifestLen          uint64
	MetadataSignatureLen uint32
	Size                 uint64

	payload *Payload
}

func (ph *payloadHeader) ReadFromPayload() error {
	if _, err := ph.payload.file.Seek(ph.payload.BaseOffset, 0); err != nil {
		return err
	}
	buf := make([]byte, 4)
	if _, err := ph.payload.file.Read(buf); err != nil {
		return err
	}
	if string(buf) != payloadHeaderMagic {
		return fmt.Errorf("Invalid payload magic: %s", buf)
	}

	// Read Version
	buf = make([]byte, 8)
	if _, err := ph.payload.file.Read(buf); err != nil {
		return err
	}
	ph.Version = binary.BigEndian.Uint64(buf)
	fmt.Printf("Payload Version: %d\n", ph.Version)

	if ph.Version != brilloMajorPayloadVersion {
		return fmt.Errorf("Unsupported payload version: %d", ph.Version)
	}

	// Read Manifest Len
	buf = make([]byte, 8)
	if _, err := ph.payload.file.Read(buf); err != nil {
		return err
	}
	ph.ManifestLen = binary.BigEndian.Uint64(buf)
	fmt.Printf("Payload Manifest Length: %d\n", ph.ManifestLen)

	ph.Size = 24

	// Read Manifest Signature Length
	buf = make([]byte, 4)
	if _, err := ph.payload.file.Read(buf); err != nil {
		return err
	}
	ph.MetadataSignatureLen = binary.BigEndian.Uint32(buf)
	fmt.Printf("Payload Manifest Signature Length: %d\n", ph.MetadataSignatureLen)

	return nil
}

// NewPayload creates a new Payload struct
func NewPayload(filename string) *Payload {
	payload := &Payload{
		Filename:    filename,
		concurrency: 4,
	}

	return payload
}

// SetConcurrency sets number of workers
func (p *Payload) SetConcurrency(concurrency int) {
	p.concurrency = concurrency
}

// GetConcurrency returns number of workers
func (p *Payload) GetConcurrency() int {
	return p.concurrency
}

// Open tries to open payload.bin file defined by Filename
func (p *Payload) Open() error {
	file, err := os.Open(p.Filename)
	if err != nil {
		return err
	}

	p.file = file
	return nil
}

// Close releases the payload file descriptor
func (p *Payload) Close() error {
	if p.file != nil {
		return p.file.Close()
	}
	return nil
}

func (p *Payload) readManifest() (*chromeos_update_engine.DeltaArchiveManifest, error) {
	buf := make([]byte, p.header.ManifestLen)
	if _, err := p.file.Read(buf); err != nil {
		return nil, err
	}
	deltaArchiveManifest := &chromeos_update_engine.DeltaArchiveManifest{}
	if err := proto.Unmarshal(buf, deltaArchiveManifest); err != nil {
		return nil, err
	}

	return deltaArchiveManifest, nil
}

func (p *Payload) readMetadataSignature() (*chromeos_update_engine.Signatures, error) {
	if _, err := p.file.Seek(p.BaseOffset+int64(p.header.Size+p.header.ManifestLen), 0); err != nil {
		return nil, err
	}

	buf := make([]byte, p.header.MetadataSignatureLen)
	if _, err := p.file.Read(buf); err != nil {
		return nil, err
	}
	signatures := &chromeos_update_engine.Signatures{}
	if err := proto.Unmarshal(buf, signatures); err != nil {
		return nil, err
	}

	return signatures, nil
}

func (p *Payload) Init() error {
	// Read Header
	p.header = &payloadHeader{
		payload: p,
	}
	if err := p.header.ReadFromPayload(); err != nil {
		return err
	}

	// Read Manifest
	deltaArchiveManifest, err := p.readManifest()
	if err != nil {
		return err
	}
	p.deltaArchiveManifest = deltaArchiveManifest

	// Read Signatures
	signatures, err := p.readMetadataSignature()
	if err != nil {
		return err
	}
	p.signatures = signatures

	// Update sizes
	p.metadataSize = int64(p.header.Size + p.header.ManifestLen)
	p.dataOffset = p.BaseOffset + p.metadataSize + int64(p.header.MetadataSignatureLen)

	fmt.Println("Found partitions:")
	for i, partition := range p.deltaArchiveManifest.Partitions {
		fmt.Printf("%s (%s)", partition.GetPartitionName(), humanize.Bytes(*partition.GetNewPartitionInfo().Size))

		if i < len(deltaArchiveManifest.Partitions)-1 {
			fmt.Printf(", ")
		} else {
			fmt.Printf("\n")
		}
	}
	p.initialized = true

	return nil
}

func (p *Payload) readDataBlob(offset int64, length int64) ([]byte, error) {
	buf := make([]byte, length)
	n, err := p.file.ReadAt(buf, p.dataOffset+offset)
	if err != nil {
		return nil, err
	}
	if int64(n) != length {
		return nil, fmt.Errorf("Read length mismatch: %d != %d", n, length)
	}

	return buf, nil
}

// zeroReader is a stateless reader that produces an infinite stream of zero bytes
// without allocating memory. Replaces the old pattern of make([]byte, hugeSize).
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// progressWriter is an io.Writer that updates an mpb.Bar
type progressWriter struct {
	w   io.Writer
	bar *mpb.Bar
}

func (pw *progressWriter) Write(p []byte) (n int, err error) {
	n, err = pw.w.Write(p)
	pw.bar.IncrBy(n)
	return n, err
}

// Extract decompresses and writes a single partition image to the output file.
// sourceFile must be an independently opened handle (not shared across goroutines)
// to avoid race conditions with concurrent ReadAt calls on Windows.
func (p *Payload) Extract(partition *chromeos_update_engine.PartitionUpdate, out *os.File, sourceFile *os.File) error {
	name := partition.GetPartitionName()
	info := partition.GetNewPartitionInfo()
	// totalOperations is no longer used for sizing since we scale by Bytes
	barName := fmt.Sprintf("%s", name)

	bar := p.progress.AddBar(
		int64(info.GetSize()),
		mpb.PrependDecorators(
			decor.Name(barName, decor.WCSyncSpaceR),
		),
		mpb.AppendDecorators(
			decor.CountersKibiByte("% .2f / % .2f"),
			decor.Name(" | "),
			decor.Percentage(),
		),
	)
	defer bar.SetTotal(0, true)

	writer := &progressWriter{w: out, bar: bar}

	for _, operation := range partition.Operations {
		if len(operation.DstExtents) == 0 {
			return fmt.Errorf("Invalid operation.DstExtents for the partition %s", name)
		}

		e := operation.DstExtents[0]
		dataOffset := p.dataOffset + int64(operation.GetDataOffset())
		dataLength := int64(operation.GetDataLength())
		_, err := out.Seek(int64(e.GetStartBlock())*blockSize, 0)
		if err != nil {
			return err
		}
		expectedUncompressedBlockSize := int64(e.GetNumBlocks() * blockSize)

		// Only compute SHA256 when we have an expected hash to compare against
		expectedHash := hex.EncodeToString(operation.GetDataSha256Hash())
		needVerify := expectedHash != ""

		sectionReader := io.NewSectionReader(sourceFile, dataOffset, dataLength)
		var dataReader io.Reader
		var bufSha hash.Hash

		if needVerify {
			bufSha = sha256.New()
			dataReader = io.TeeReader(sectionReader, bufSha)
		} else {
			dataReader = sectionReader
		}

		switch operation.GetType() {
		case chromeos_update_engine.InstallOperation_REPLACE:
			n, err := io.Copy(writer, dataReader)
			if err != nil {
				return err
			}

			if int64(n) != expectedUncompressedBlockSize {
				return fmt.Errorf("Verify failed (Unexpected bytes written): %s (%d != %d)", name, n, expectedUncompressedBlockSize)
			}

		case chromeos_update_engine.InstallOperation_REPLACE_XZ:
			reader, err := xz.NewReader(dataReader)
			if err != nil {
				return fmt.Errorf("Failed to create xz reader for %s: %v", name, err)
			}
			n, err := io.Copy(writer, reader)
			if err != nil {
				return err
			}
			if n != expectedUncompressedBlockSize {
				return fmt.Errorf("Verify failed (Unexpected bytes written): %s (%d != %d)", name, n, expectedUncompressedBlockSize)
			}

		case chromeos_update_engine.InstallOperation_REPLACE_BZ:
			reader := bzip2.NewReader(dataReader)
			n, err := io.Copy(writer, reader)
			if err != nil {
				return err
			}
			if n != expectedUncompressedBlockSize {
				return fmt.Errorf("Verify failed (Unexpected bytes written): %s (%d != %d)", name, n, expectedUncompressedBlockSize)
			}

		case chromeos_update_engine.InstallOperation_ZSTD:
			reader, err := zstd.NewReader(dataReader)
			if err != nil {
				return fmt.Errorf("Failed to create zstd reader for %s: %v", name, err)
			}
			n, err := io.Copy(writer, reader)
			reader.Close()
			if err != nil {
				return err
			}
			if n != expectedUncompressedBlockSize {
				return fmt.Errorf("Verify failed (Unexpected bytes written): %s (%d != %d)", name, n, expectedUncompressedBlockSize)
			}

		case chromeos_update_engine.InstallOperation_ZERO:
			// Use a zero reader instead of allocating a huge byte slice
			n, err := io.CopyN(writer, zeroReader{}, expectedUncompressedBlockSize)
			if err != nil {
				return err
			}

			if n != expectedUncompressedBlockSize {
				return fmt.Errorf("Verify failed (Unexpected bytes written): %s (%d != %d)", name, n, expectedUncompressedBlockSize)
			}

		default:
			return fmt.Errorf("Unhandled operation type: %s", operation.GetType().String())
		}

		// Verify hash only if expected hash exists
		if needVerify {
			hash := hex.EncodeToString(bufSha.Sum(nil))
			if hash != expectedHash {
				return fmt.Errorf("Verify failed (Checksum mismatch): %s (%s != %s)", name, hash, expectedHash)
			}
		}
	}

	return nil
}

func (p *Payload) worker() {
	// Each worker opens its own file handle to the payload to avoid
	// race conditions with concurrent ReadAt calls (especially on Windows
	// where ReadAt is implemented as non-atomic Seek+Read).
	sourceFile, err := os.Open(p.Filename)
	if err != nil {
		fmt.Printf("Worker failed to open payload file: %v\n", err)
		// Drain remaining requests to avoid deadlock
		for range p.requests {
			p.workerWG.Done()
		}
		return
	}
	defer sourceFile.Close()

	for req := range p.requests {
		partition := req.partition
		targetDirectory := req.targetDirectory

		name := fmt.Sprintf("%s.img", partition.GetPartitionName())
		outPath := pathpkg.Join(targetDirectory, name)
		outFile, err := os.OpenFile(outPath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0o755)
		if err != nil {
			fmt.Printf("Failed to create output file %s: %v\n", outPath, err)
			p.workerWG.Done()
			continue
		}
		if err := p.Extract(partition, outFile, sourceFile); err != nil {
			fmt.Printf("Extract error for %s: %v\n", name, err)
		}
		outFile.Close()

		p.workerWG.Done()
	}
}

func (p *Payload) spawnExtractWorkers(n int) {
	for i := 0; i < n; i++ {
		go p.worker()
	}
}

func (p *Payload) ExtractSelected(targetDirectory string, partitions []string) error {
	if !p.initialized {
		return errors.New("Payload has not been initialized")
	}
	p.progress = mpb.New()

	p.requests = make(chan *request, 100)
	p.spawnExtractWorkers(p.concurrency)

	sort.Strings(partitions)

	for _, partition := range p.deltaArchiveManifest.Partitions {
		if len(partitions) > 0 {
			idx := sort.SearchStrings(partitions, *partition.PartitionName)
			if idx == len(partitions) || partitions[idx] != *partition.PartitionName {
				continue
			}
		}

		p.workerWG.Add(1)
		p.requests <- &request{
			partition:       partition,
			targetDirectory: targetDirectory,
		}
	}

	// Close channel first so workers can exit their range loop,
	// then wait for all in-flight extractions to finish.
	close(p.requests)
	p.workerWG.Wait()

	return nil
}

func (p *Payload) ExtractAll(targetDirectory string) error {
	return p.ExtractSelected(targetDirectory, nil)
}
