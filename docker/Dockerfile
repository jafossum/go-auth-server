FROM golang:1.13-alpine as build-env

###########################################################################################
LABEL com.github.jafossum.maintainer="John A. Fossum <3495141+jafossum@users.noreply.github.com>"  \
      com.github.jafossum.description="Builder image for Golang Services"
###########################################################################################

# Install necessary
RUN apk add --update --no-cache \
    git \
    musl-dev \
    pkgconfig \
    alpine-sdk \
    libsodium-dev

# Create workdir
WORKDIR /app

# Config GO tu use goproxy.io
ENV go env -w GOPROXY=https://goproxy.io,direct

# Get dependancies - will also be cached if we won't change mod/sum
COPY go.mod .
COPY go.sum .
RUN go mod download

# COPY the source code as the last step
COPY . .

# Build the binary
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -installsuffix cgo -o /app/app

# Build the minimal runtime
FROM alpine:latest

###########################################################################################
LABEL com.github.jafossum.maintainer="John A. Fossum <3495141+jafossum@users.noreply.github.com>"  \
      com.github.jafossum.description="Runtime image for Golang Services"
###########################################################################################

# Install necessary
RUN apk add --update --no-cache \
    ca-certificates

# Create workdir
WORKDIR /app
RUN mkdir logs

# Copy from builder-env
COPY --from=build-env /app/app app

# Set entrypoint
ENTRYPOINT ["./app"]
