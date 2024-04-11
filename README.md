# UID MFA Universal Go library

This SDK allows a web developer to quickly add UID's interactive, self-service, multi-factor authentication to any Golang web login form.


What's included:
* `universal_sdk` - The Golang UID SDK for interacting with the UID Universal Prompt
* `example` - An example Go application with UID integrated

## Tested Against Go Versions:
	- 1.19
	- 1.20

## Getting Started
To use the SDK in your existing development environment, install it using Go Modules
```
go mod init example
go get github.com/xin-li-ui/uid_mfa_universal_go/universal_sdk
```
Once it's installed, see our developer documentation at https://uid.com/docs/uidweb and `example/main.go` in this repo for guidance on integrating UID MFA into your web application.

## Contribute
To contribute, fork this repo and make a pull request with your changes when they are ready.

Install the SDK from source:
```
cd universal_sdk/
go build
```

## Tests
```
cd universal_sdk/
go test
```

## Format
To run formatter
```
go fmt
```