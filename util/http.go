package util

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

type Error struct {
	Message string `json:"status"`
}

func ReplyJSON(w http.ResponseWriter, code int, r interface{}) {
	b, err := json.Marshal(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(code)
	io.Copy(w, bytes.NewReader(b))
}
