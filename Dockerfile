# Copyright (c) 2026 Ggroup
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file.

FROM golang:1.26-alpine AS builder
WORKDIR /app


COPY go.mod ./

COPY go.sum ./


RUN go mod download


COPY . .


RUN CGO_ENABLED=0 GOOS=linux go build -o gr3m main.go


FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/
COPY --from=builder /app/gr3m .
COPY --from=builder /app/config.json .


EXPOSE 8080
EXPOSE 1080

ENTRYPOINT ["./gr3m", "-c", "config.json"]