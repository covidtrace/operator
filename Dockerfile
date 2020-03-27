FROM golang:1.14 AS builder

WORKDIR /go/src/github.com/covidtrace/operator

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .
RUN go install -v ./...

FROM golang:1.14
COPY --from=builder /go/bin/serve /go/bin/serve
CMD ["serve"]
