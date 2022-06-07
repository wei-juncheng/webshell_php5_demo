FROM golang:latest

WORKDIR /app

COPY go.mod ./
copy example.go ./
RUN go mod download

#編譯的檔案名=process name
RUN go build -o /go_webshell

EXPOSE 8080

CMD [ "/go_webshell" ]