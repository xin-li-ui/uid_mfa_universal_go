# UID MFA Universal Golang SDK Demo

A simple Go web application that serves a logon page integrated with UID MFA.

## Setup
Change to the "example" directory
```
cd example
```

Install the demo requirements:
```
go mod tidy
```

Then, create a `Web SDK` application in the UID Manager Portal.

## Using the App

1. Copy the Client ID, Client Secret, and API Hostname values for your `Web SDK` application into the `config.json` file.
2. Start the app.
    ```
    go run main.go
    ```
3. Navigate to http://localhost:8080.
4. Log in with the user you would like to enroll in UID or with an already enrolled user (any password will work).

## (Optional) Run the demo using docker

A dockerfile is included to easily run the demo app with a known working Go configuration.

1. Copy the Client ID, Client Secret, and API Hostname values for your `Web SDK` application into the `config.json` file.
2. Build the docker image:
    ```
    docker build -t uid_golang_example -f Dockerfile ..
    ```
3. Run the docker container:
    ```
    docker run -it -p 8080:8080 uid_golang_example
    ```
4. Navigate to http://localhost:8080.
5. Log in with the user you would like to enroll in UID or with an already enrolled user (any password will work).