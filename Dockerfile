# Build Server
FROM golang:latest as builder
ENV GOBIN /go/bin
WORKDIR /go/src/github.com/QualiArts/cb-sample-server
COPY / .
RUN go test
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build

# COPY theserver file to image from builder
FROM alpine:latest
WORKDIR /usr/local/bin/
COPY --from=builder /go/src/github.com/QualiArts/cb-sample-server/cb-sample-server .

EXPOSE 8080

CMD ["/usr/local/bin/cb-sample-server"]
