package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	twilio "github.com/kevinburke/twilio-go"
)

func getEnvVar(key string) string {
	value := os.Getenv(key)
	if value == "" {
		panic(fmt.Errorf("%s is required env var", key))
	}

	return value
}

var codeLength int = 6

var storageClient *storage.Client
var storageBucket *storage.BucketHandle

var twilioMessages *twilio.MessageService
var twilioLookup *twilio.LookupPhoneNumbersService
var twilioFromNumber string

func init() {
	mc := twilio.NewClient(getEnvVar("TWILIO_ACCOUNT_SID"), getEnvVar("TWILIO_AUTH_TOKEN"), nil)
	twilioMessages = mc.Messages

	lookupClient := twilio.NewLookupClient(getEnvVar("TWILIO_ACCOUNT_SID"), getEnvVar("TWILIO_AUTH_TOKEN"), nil)
	twilioLookup = lookupClient.LookupPhoneNumbers

	twilioFromNumber = getEnvVar("TWILIO_FROM_NUMBER")

	c, err := storage.NewClient(context.Background())
	if err != nil {
		panic(err)
	}

	storageClient = c
	storageBucket = storageClient.Bucket("covidtrace-operator")
}

type errMessage struct {
	Message string `json:"status"`
}

type initBody struct {
	PhoneNumber string `json:"phone"`
}

type initResp struct {
	Token string `json:"token"`
}

type tokenMetadata struct {
	Code string `json:"code"`
}

type verifyBody struct {
	Token string `json:"token"`
	Code  string `json:"code"`
}

type verifyResp struct {
	Token string `json:"token"`
}

func replyJSON(w http.ResponseWriter, code int, r interface{}) {
	b, err := json.Marshal(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(code)
	io.Copy(w, bytes.NewReader(b))
}

func main() {
	jwtSigningKey := []byte(getEnvVar("JWT_SIGNING_KEY"))

	router := httprouter.New()

	router.POST("/init", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		ctx := context.Background()

		var ib initBody
		if r.Body == nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Missing request body"})
			return
		}
		defer r.Body.Close()

		err := json.NewDecoder(r.Body).Decode(&ib)
		if err == io.EOF {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Missing request body"})
			return
		}

		if err != nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Error parsing request body"})
			return
		}

		if ib.PhoneNumber == "" {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Missing phone number"})
			return
		}

		qp := url.Values{}
		qp.Add("CountryCode", "US")
		qp.Add("Type", "carrier")
		lpn, err := twilioLookup.Get(ctx, ib.PhoneNumber, qp)
		if err != nil || lpn.CountryCode != "US" || lpn.Carrier.Type != "mobile" {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Error with phone number lookup"})
			return
		}

		token, err := uuid.NewRandom()
		if err != nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Error generating token"})
			return
		}

		digits := make([]string, codeLength)
		rand.Seed(int64(token.ID()))

		for i := 0; i < codeLength; i++ {
			digits[i] = fmt.Sprintf("%v", rand.Int()%10)
		}
		code := strings.Join(digits, "")

		ow := storageBucket.Object(fmt.Sprintf("%s.json", token)).NewWriter(ctx)
		if err := json.NewEncoder(ow).Encode(tokenMetadata{Code: code}); err != nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Error persisting token and code"})
			return
		}

		if err := ow.Close(); err != nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Error persisting token and code"})
			return
		}

		_, err = twilioMessages.SendMessage(
			twilioFromNumber,
			ib.PhoneNumber,
			fmt.Sprintf("Your code is %s", code),
			nil,
		)
		if err != nil {
			log.Println(err)
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Error sending SMS"})
			return
		}

		replyJSON(w, http.StatusOK, initResp{Token: token.String()})
	})

	router.POST("/verify", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		var vb verifyBody
		if r.Body == nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Missing request body"})
			return
		}
		defer r.Body.Close()

		err := json.NewDecoder(r.Body).Decode(&vb)
		if err == io.EOF {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Missing request body"})
			return
		}

		if err != nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Error parsing request body"})
			return
		}

		var tm tokenMetadata

		or, err := storageBucket.Object(fmt.Sprintf("%s.json", vb.Token)).NewReader(context.Background())
		if err != nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Error fetching token metadata"})
			return
		}

		if err := json.NewDecoder(or).Decode(&tm); err != nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Error fetching token metadata"})
			return
		}

		if err := or.Close(); err != nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Error fetching token metadata"})
			return
		}

		if tm.Code != vb.Code {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Invalid code"})
			return
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.StandardClaims{
			Issuer:   "covidtrace/operator",
			Audience: vb.Token,
		})
		ss, err := token.SignedString(jwtSigningKey)
		if err != nil {
			replyJSON(w, http.StatusBadRequest, errMessage{Message: "Error generating token"})
			return
		}

		replyJSON(w, http.StatusOK, verifyResp{Token: ss})
	})

	router.PanicHandler = func(w http.ResponseWriter, _ *http.Request, _ interface{}) {
		http.Error(w, "Unknown error", http.StatusBadRequest)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), router))
}
