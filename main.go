package main

import (
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
)

func handler(event events.CognitoEventUserPoolsPreAuthentication) (events.CognitoEventUserPoolsPreAuthentication, error) {
	fmt.Printf("PreAuthentication of user: %s\n", event.UserName)

	if event.Request.UserAttributes["email_verified"] == "false" {

		awsSession := session.Must(session.NewSessionWithOptions(session.Options{
			SharedConfigState: session.SharedConfigEnable,
		}))

		cognitoClient := cognitoidentityprovider.New(awsSession)

		params := &cognitoidentityprovider.ResendConfirmationCodeInput{
			ClientId: aws.String(event.CallerContext.ClientID),
			Username: aws.String(event.UserName),
		}

		_, err := cognitoClient.ResendConfirmationCode(params)
		if err != nil {
			fmt.Println("Error resending the verification email: ", err)
			return event, fmt.Errorf("Error resending the verification email: %v", err)
		}
		fmt.Println("Verification email resent. Please check your email and verify your account before signing in.")
		return event, fmt.Errorf("Verification email resent. Please check your email and verify your account before signing in.")
	} else {
		fmt.Println("User email already verified. Sign in successful.")
	}

	return event, nil
}

func main() {
	lambda.Start(handler)
}
