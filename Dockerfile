FROM golang:1.13-buster as build

WORKDIR /go/src/app
ADD . /go/src/app

RUN GO111MODULE=on go build -o /go/bin/scanr cmd/scanr.go

FROM gcr.io/distroless/base-debian10
COPY --from=build /go/bin/scanr /
CMD ["/scanr"]
