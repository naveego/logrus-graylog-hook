package graylog

import (
	"bytes"
	"encoding/json"
	"net/http"
)

type httpTransport struct {
	client *http.Client
	url    string
}

// WriteMessage sends the specified message to the GELF HTTP endpoint
// specified in the call to New().  It assumes all the fields are
// filled out appropriately.
func (w *httpTransport) WriteMessage(m *Message) (err error) {
	mBytes, err := json.Marshal(m)
	if err != nil {
		return
	}

	buf := bytes.NewBuffer(mBytes)

	_, err = w.client.Post(w.url, "application/json", buf)

	return err
}
