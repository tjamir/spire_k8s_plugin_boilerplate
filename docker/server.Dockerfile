FROM --platform=linux/amd64 golang:1.18-alpine as builder
RUN apk add build-base git mercurial
ADD ./server /opt/nodeattestor-plugin/server
ADD ./go.mod /opt/nodeattestor-plugin/server/go.mod
RUN cd /opt/nodeattestor-plugin/server && go mod tidy
RUN cd /opt/nodeattestor-plugin/server && go mod download
WORKDIR /opt/nodeattestor-plugin/server
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -extldflags -static" -o /opt/nodeattestor-plugin/server/bin/psat_iid_server .
RUN chmod +x /opt/nodeattestor-plugin/server/bin/psat_iid_server

FROM gcr.io/spiffe-io/spire-server:1.3.3 AS spire-server-psat-iid
COPY --from=builder /opt/nodeattestor-plugin/server/bin/psat_iid_server /usr/local/bin/psat_iid_server
RUN chmod +x /usr/local/bin/psat_iid_server
