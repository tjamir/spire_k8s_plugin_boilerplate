FROM --platform=linux/amd64 golang:1.18-alpine as builder
RUN apk add build-base git mercurial
ADD ./agent /opt/nodeattestor-plugin/agent
ADD ./go.mod /opt/nodeattestor-plugin/agent/go.mod
RUN cd /opt/nodeattestor-plugin/agent && go mod tidy
RUN cd /opt/nodeattestor-plugin/agent && go mod download
WORKDIR /opt/nodeattestor-plugin/agent
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -extldflags -static" -o /opt/nodeattestor-plugin/agent/bin/psat_iid_agent .
RUN chmod +x /opt/nodeattestor-plugin/agent/bin/psat_iid_agent

FROM gcr.io/spiffe-io/spire-agent:1.3.3 AS spire-agent-psat-iid
COPY --from=builder /opt/nodeattestor-plugin/agent/bin/psat_iid_agent /usr/local/bin/psat_iid_agent
RUN chmod +x /usr/local/bin/psat_iid_agent
