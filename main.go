package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

type ResendRecord struct {
	UserName       string `dynamodbav:"user_name"`
	LastResendTime int64  `dynamodbav:"last_resend_time"`
}

func handler(event events.CognitoEventUserPoolsPreAuthentication) (events.CognitoEventUserPoolsPreAuthentication, error) {

	if event.Request.UserAttributes["email_verified"] == "false" {

		awsSession := session.Must(session.NewSessionWithOptions(session.Options{
			SharedConfigState: session.SharedConfigEnable,
		}))
		dynamoDBClient := dynamodb.New(awsSession)
		resendTableName := os.Getenv("RESENDS_TABLE")
		noPreviousResendEvent := true

		// Get the last resend time for the user
		getItemInput := &dynamodb.GetItemInput{
			TableName: aws.String(resendTableName),
			Key: map[string]*dynamodb.AttributeValue{
				"user_name": {
					S: aws.String(event.UserName),
				},
			},
		}

		getItemOutput, err := dynamoDBClient.GetItem(getItemInput)
		if err != nil {
			fmt.Println("error getting item from DynamoDB:", err)
		}

		now := time.Now().Unix()
		resendRecord := ResendRecord{}

		if getItemOutput.Item != nil {
			err = dynamodbattribute.UnmarshalMap(getItemOutput.Item, &resendRecord)
			if err != nil {
				fmt.Println("error unmarshalling DynamoDB item:", err)
			} else {
				noPreviousResendEvent = false // We have successfully retrieved a record of a previous send
			}
		}

		// Get the resend interval from the environment variable and convert it to an integer
		resendIntervalStr := os.Getenv("RESEND_INTERVAL_SECONDS")
		resendInterval, err := strconv.Atoi(resendIntervalStr)
		if err != nil {
			fmt.Println("Error converting RESEND_INTERVAL_SECONDS to integer:", err)
			resendInterval = 86400 // Default to 24 hours if there is an issue parsing the environment variable
		}

		if noPreviousResendEvent || now-resendRecord.LastResendTime > int64(resendInterval) {

			cognitoClient := cognitoidentityprovider.New(awsSession)
			clientID := os.Getenv("CLIENT_ID")
			clientSecret := os.Getenv("CLIENT_SECRET")

			secretHash := createSecretHash(event.UserName, clientID, clientSecret)

			params := &cognitoidentityprovider.ResendConfirmationCodeInput{
				ClientId:   aws.String(clientID),
				Username:   aws.String(event.UserName),
				SecretHash: aws.String(secretHash),
			}

			_, err := cognitoClient.ResendConfirmationCode(params)
			if err != nil {
				fmt.Println("error resending account verification email: ", err)
				return event, accountVerificationError()
			}
			fmt.Println("resent account verification email")
			resendRecord.UserName = event.UserName
			resendRecord.LastResendTime = now

			av, err := dynamodbattribute.MarshalMap(resendRecord)
			if err != nil {
				fmt.Println("error marshalling DynamoDB item:", err)
				return event, accountVerificationError()
			}

			putItemInput := &dynamodb.PutItemInput{
				TableName: aws.String(resendTableName),
				Item:      av,
			}

			_, err = dynamoDBClient.PutItem(putItemInput)
			if err != nil {
				fmt.Println("error updating item in DynamoDB:", err)
				return event, accountVerificationError()
			}

			return event, accountVerificationError()
		} else {
			fmt.Println("Preventing resend confirmation for user", event.UserName)
			return event, accountVerificationError()
		}
	}

	return event, nil
}

func accountVerificationError() error {
	return fmt.Errorf("--- Looks like you have not verified your email yet. Please check your email and verify your account before signing in")
}

func createSecretHash(username, clientID, clientSecret string) string {
	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(username + clientID))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func main() {
	lambda.Start(handler)
}
