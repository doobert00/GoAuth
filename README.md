## GoAuth
A simple authentication server written in Go :)

## Running
You will need to create SSL certificate and key called `server.crt` and `server.key`, respectively. We used `openssl` for this. To start the https server use:
```
cd server
go run main.go
```
To start the client (that does not work yet) use:
```
cd client
npm start
```
