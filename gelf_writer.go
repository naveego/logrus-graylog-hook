// Copyright 2012 SocialCode. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package graylog

import (
	"bytes"
	"compress/flate"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

// Writer implements io.Writer and is used to send both discrete
// messages to a graylog2 server, or data from a stream-oriented
// interface (like the functions in log).
type Writer struct {
	mu               sync.Mutex
	conn             net.Conn
	hostname         string
	Transport        Transport
	Facility         string // defaults to current process name
	CompressionLevel int    // one of the consts from compress/flate
	CompressionType  CompressType
}

// CompressType is the compression type the writer should use when sending messages
// to the graylog2 server over UDP.
type CompressType int

const (
	CompressGzip CompressType = iota
	CompressZlib
	NoCompress
)

// Message represents the contents of the GELF message.  It is gzipped
// before sending.
type Message struct {
	Version  string                 `json:"version"`
	Host     string                 `json:"host"`
	Short    string                 `json:"short_message"`
	Full     string                 `json:"full_message"`
	TimeUnix float64                `json:"timestamp"`
	Level    int32                  `json:"level"`
	Facility string                 `json:"facility"`
	File     string                 `json:"file"`
	Line     int                    `json:"line"`
	Extra    map[string]interface{} `json:"-"`
}

type innerMessage Message //against circular (Un)MarshalJSON

// Transport defines a contract to send messages to a GELF endpoint.
type Transport interface {
	WriteMessage(m *Message) (err error)
}

// NewWriter returns a new GELF Writer.  This writer can be used to send the
// output of the standard Go log functions to a central GELF server by
// passing it to log.SetOutput(). The addr parameter can include a schema,
// which must be "http", "https", or "udp" (like http://graylog.example.com/gelf),
// or can be a simple hostname (like 127.0.0.1:12201). If there is no schema
// the writer will use UDP.
func NewWriter(addr string) (*Writer, error) {
	var err error
	var t Transport
	var segs = strings.Split(addr, "://")
	w := &Writer{
		Facility:         path.Base(os.Args[0]),
		CompressionLevel: flate.BestSpeed,
	}

	if segs[0] == "http" || segs[0] == "https" {
		t = &httpTransport{
			client: &http.Client{},
			url:    addr,
		}
	} else {
		addr = segs[len(segs)-1]
		udp := udpTransport{
			compressionType:  func() CompressType { return w.CompressionType },
			compressionLevel: func() int { return w.CompressionLevel },
		}

		if udp.conn, err = net.Dial("udp", addr); err != nil {
			return nil, err
		}

		t = &udp
	}

	w.Transport = t

	if w.hostname, err = os.Hostname(); err != nil {
		return nil, err
	}

	return w, nil
}

// WriteMessage sends the specified message to the GELF server
// specified in the call to New().  It assumes all the fields are
// filled out appropriately.  In general, clients will want to use
// Write, rather than WriteMessage.
func (w *Writer) WriteMessage(m *Message) (err error) {

	return w.Transport.WriteMessage(m)
}

/*
func (w *Writer) Alert(m string) (err error)
func (w *Writer) Close() error
func (w *Writer) Crit(m string) (err error)
func (w *Writer) Debug(m string) (err error)
func (w *Writer) Emerg(m string) (err error)
func (w *Writer) Err(m string) (err error)
func (w *Writer) Info(m string) (err error)
func (w *Writer) Notice(m string) (err error)
func (w *Writer) Warning(m string) (err error)
*/

// Write encodes the given string in a GELF message and sends it to
// the server specified in New().
func (w *Writer) Write(p []byte) (n int, err error) {

	// 1 for the function that called us.
	file, line := getCallerIgnoringLogMulti(1)

	// remove trailing and leading whitespace
	p = bytes.TrimSpace(p)

	// If there are newlines in the message, use the first line
	// for the short message and set the full message to the
	// original input.  If the input has no newlines, stick the
	// whole thing in Short.
	short := p
	full := []byte("")
	if i := bytes.IndexRune(p, '\n'); i > 0 {
		short = p[:i]
		full = p
	}

	m := Message{
		Version:  "1.0",
		Host:     w.hostname,
		Short:    string(short),
		Full:     string(full),
		TimeUnix: float64(time.Now().UnixNano()/1000000) / 1000.,
		Level:    6, // info
		Facility: w.Facility,
		File:     file,
		Line:     line,
		Extra:    map[string]interface{}{},
	}

	if err = w.WriteMessage(&m); err != nil {
		return 0, err
	}

	return len(p), nil
}

// MarshalJSON converts a Message to JSON bytes.
func (m *Message) MarshalJSON() ([]byte, error) {
	var err error
	var b, eb []byte

	extra := m.Extra
	b, err = json.Marshal((*innerMessage)(m))
	m.Extra = extra
	if err != nil {
		return nil, err
	}

	if len(extra) == 0 {
		return b, nil
	}

	if eb, err = json.Marshal(extra); err != nil {
		return nil, err
	}

	// merge serialized message + serialized extra map
	b[len(b)-1] = ','
	return append(b, eb[1:len(eb)]...), nil
}

// UnmarshalJSON converts writes some bytes into a Message.
func (m *Message) UnmarshalJSON(data []byte) error {
	i := make(map[string]interface{}, 16)
	if err := json.Unmarshal(data, &i); err != nil {
		return err
	}
	for k, v := range i {
		if k[0] == '_' {
			if m.Extra == nil {
				m.Extra = make(map[string]interface{}, 1)
			}
			m.Extra[k] = v
			continue
		}
		switch k {
		case "version":
			m.Version = v.(string)
		case "host":
			m.Host = v.(string)
		case "short_message":
			m.Short = v.(string)
		case "full_message":
			m.Full = v.(string)
		case "timestamp":
			m.TimeUnix = v.(float64)
		case "level":
			m.Level = int32(v.(float64))
		case "facility":
			m.Facility = v.(string)
		case "file":
			m.File = v.(string)
		case "line":
			m.Line = int(v.(float64))
		}
	}
	return nil
}
