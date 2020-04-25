package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/covidtrace/jwt"
	"github.com/covidtrace/operator/storage"
	"github.com/covidtrace/operator/util"
	"github.com/julienschmidt/httprouter"
)

type Handler interface {
	Issuer() *jwt.Issuer
	Refresher() *jwt.Issuer
	Bucket() storage.Bucket
	Meta(context.Context, *http.Request) (context.Context, *string, *tokenMeta, error)
	Dispatch(context.Context, *tokenMeta) error
}

type contextKey int

type tokenMeta struct {
	Code string `json:"code"`
	Hash string `json:"hash"`
}

type initRes struct {
	Token string `json:"token"`
}

type verifyReq struct {
	Token string `json:"token"`
	Code  string `json:"code"`
}

type verifyRes struct {
	Token   string `json:"token"`
	Refresh string `json:"refresh"`
}

func Init(h Handler) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		ctx, token, meta, err := h.Meta(context.Background(), r)
		if err != nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: err.Error()})
			return
		}

		if token == nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: "nil token"})
			return
		}

		if meta == nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: "nil meta"})
			return
		}

		if err := h.Bucket().Put(ctx, fmt.Sprintf("%s.json", *token), *meta); err != nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: "Error persisting token and code"})
			return
		}

		if err := h.Dispatch(ctx, meta); err != nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: err.Error()})
			return
		}

		util.ReplyJSON(w, http.StatusOK, initRes{Token: *token})
	}
}

func Verify(h Handler) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		ctx := context.Background()

		var req verifyReq
		if r.Body == nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: "Missing request body"})
			return
		}
		defer r.Body.Close()

		err := json.NewDecoder(r.Body).Decode(&req)
		if err == io.EOF {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: "Missing request body"})
			return
		}

		if err != nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: "Error parsing request body"})
			return
		}

		var tm tokenMeta
		done, err := h.Bucket().Get(ctx, fmt.Sprintf("%s.json", req.Token), &tm)
		if err != nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: "Error fetching token metadata"})
			return
		}

		if tm.Code != req.Code {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: "Invalid code"})
			return
		}

		token, err := h.Issuer().Token(tm.Hash, 0)
		if err != nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: err.Error()})
			return
		}

		refresh, err := h.Issuer().Token(tm.Hash, 0)
		if err != nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: err.Error()})
			return
		}

		if err := done(ctx); err != nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: "Error deleting metadata"})
			return
		}

		util.ReplyJSON(w, http.StatusOK, verifyRes{Token: token, Refresh: refresh})
	}
}

func Refresh(h Handler) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		query := r.URL.Query()
		code := query.Get("code")
		if code == "" {
			util.ReplyJSON(w, http.StatusUnauthorized, util.Error{Message: "Missing code parameter"})
			return
		}

		claims, err := h.Issuer().Validate(code)
		if err != nil {
			util.ReplyJSON(w, http.StatusUnauthorized, util.Error{Message: err.Error()})
			return
		}

		token, err := h.Issuer().Token(claims.Hash, claims.Refreshed+1)
		if err != nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: err.Error()})
			return
		}

		refresh, err := h.Refresher().Token(claims.Hash, claims.Refreshed+1)
		if err != nil {
			util.ReplyJSON(w, http.StatusBadRequest, util.Error{Message: err.Error()})
			return
		}

		util.ReplyJSON(w, http.StatusOK, verifyRes{Token: token, Refresh: refresh})
	}
}
