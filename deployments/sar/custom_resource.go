package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecs"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/pkg/lambdalogger"
)

var awsSession = session.Must(session.NewSession())

// Returns physicalResourceID and outputs
func customResource(ctx context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	_, logger := lambdalogger.ConfigureGlobal(ctx, nil)
	logger.Info("received request", zap.Any("event", event))

	switch event.ResourceType {
	case "Custom::ECS-Cluster":
		switch event.RequestType {
		case cfn.RequestCreate:
			// TODO: struct validation
			name := event.ResourceProperties["ClusterName"].(string)
			client := ecs.New(awsSession)
			_, err := client.CreateCluster(&ecs.CreateClusterInput{
				ClusterName: &name,
				Tags: []*ecs.Tag{
					{
						Key:   aws.String("Application"),
						Value: aws.String("Panther"),
					},
					// TODO - stack name tag?
				},
			})
			if err != nil {
				return "", nil, fmt.Errorf("failed to create ECS cluster: %v", err)
			}

			physicalID := arn.ARN{
				Partition: "aws",
				Service:   "ecs",
				Region:    *awsSession.Config.Region,
				AccountID: os.Getenv("AWS_ACCOUNT_ID"),
				Resource:  "cluster/" + name,
			}
			return physicalID.String(), nil, nil
		case cfn.RequestUpdate:
			// TODO - destroy and recreate?
			return "", nil, nil
		case cfn.RequestDelete:
			clusterArn, err := arn.Parse(event.PhysicalResourceID)
			if err != nil {
				return "", nil, fmt.Errorf("invalid arn: %s: %v", event.PhysicalResourceID, err)
			}
			name := strings.TrimPrefix(clusterArn.Resource, "cluster/")
			client := ecs.New(awsSession)
			_, err = client.DeleteCluster(&ecs.DeleteClusterInput{Cluster: &name})
			if err != nil {
				return "", nil, fmt.Errorf("failed to delete ECS cluster: %v", err)
			}

			return event.PhysicalResourceID, nil, nil
		default:
			return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
		}
	default:
		return "", nil, fmt.Errorf("unknown custom resource type %s", event.ResourceType)
	}
}

func main() {
	lambda.Start(cfn.LambdaWrap(customResource))
}
