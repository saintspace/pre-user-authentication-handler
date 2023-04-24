package main

import (
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

func handler(event events.CognitoEventUserPoolsPreAuthentication) (events.CognitoEventUserPoolsPreAuthentication, error) {
	fmt.Printf("PreAuthentication of user: %s\n", event.UserName)
	return event, nil
}

func main() {
	lambda.Start(handler)
}
