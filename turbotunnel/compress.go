package turbotunnel

import (
	"io"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// CompressedReadWriteCloser wraps an io.ReadWriteCloser with zstd streaming compression.
type CompressedReadWriteCloser struct {
	rwc     io.ReadWriteCloser
	reader  *zstd.Decoder
	writer  *zstd.Encoder
	readMu  sync.Mutex
	writeMu sync.Mutex
	once    sync.Once
}

// NewCompressedReadWriteCloser wraps an io.ReadWriteCloser with zstd compression.
// Data written is compressed, data read is decompressed.
func NewCompressedReadWriteCloser(rwc io.ReadWriteCloser) (*CompressedReadWriteCloser, error) {
	// Create streaming decoder that reads from rwc
	decoder, err := zstd.NewReader(rwc,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderLowmem(true),
	)
	if err != nil {
		return nil, err
	}

	// Create streaming encoder that writes to rwc
	encoder, err := zstd.NewWriter(rwc,
		zstd.WithEncoderLevel(zstd.SpeedFastest),
		zstd.WithEncoderConcurrency(1),
		zstd.WithWindowSize(32*1024), // 32KB window
	)
	if err != nil {
		decoder.Close()
		return nil, err
	}

	return &CompressedReadWriteCloser{
		rwc:    rwc,
		reader: decoder,
		writer: encoder,
	}, nil
}

func (c *CompressedReadWriteCloser) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	return c.reader.Read(b)
}

func (c *CompressedReadWriteCloser) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	n, err := c.writer.Write(b)
	if err != nil {
		return n, err
	}
	// Flush to ensure data is sent immediately (important for low-latency)
	err = c.writer.Flush()
	return n, err
}

func (c *CompressedReadWriteCloser) Close() error {
	var err error
	c.once.Do(func() {
		c.writer.Close()
		c.reader.Close()
		err = c.rwc.Close()
	})
	return err
}
