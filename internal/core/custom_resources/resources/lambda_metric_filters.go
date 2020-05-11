package resources

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"go.uber.org/zap"
)

const (
	memoryFilter      = `[ report_label="REPORT", ..., label="Used:", max_memory_used_value, unit="MB" ]`
	warnFilterGo      = `{ $.level = "warn" }`
	warnFilterPython  = `[ level="[WARN]" ]`
	errorFilterGo     = `{ $.level = "error" }`
	errorFilterPython = `[ level="[ERROR]" ]`
)

type LambdaMetricFiltersProperties struct {
	LambdaRuntime string `validate:"required,oneof=Go Python"`
	LogGroupName  string `validate:"required"`
}

// Add metric filters to a Lambda function's CloudWatch log group
func customLambdaMetricFilters(_ context.Context, event cfn.Event) (physicalID string, outputs map[string]interface{}, err error) {
	var props LambdaMetricFiltersProperties
	if err = parseProperties(event.ResourceProperties, &props); err != nil {
		return
	}

	switch event.RequestType {
	case cfn.RequestCreate:
		lambdaName := lambdaNameFromLogGroup(props.LogGroupName)

		// Track max memory usage
		err = putMetricFilter(props.LogGroupName, memoryFilter, lambdaName+"-memory", "$max_memory_used_value")
		if err != nil {
			return
		}

		// We store successful filter name suffixes at the end of the physicalID.
		// If the create fails halfway through, CFN will rollback and request deletion for the resource.
		// This way, we can delete whichever filters have been added so far.
		physicalID = fmt.Sprintf("custom:metric-filters:%s:memory", props.LogGroupName)

		// Logged warnings
		warnFilter := warnFilterGo
		if props.LambdaRuntime == "Python" {
			warnFilter = warnFilterPython
		}
		err = putMetricFilter(props.LogGroupName, warnFilter, lambdaName+"-warns", "1")
		if err != nil {
			return
		}
		physicalID += "/warns"

		// Logged errors
		errorFilter := errorFilterGo
		if props.LambdaRuntime == "Python" {
			errorFilter = errorFilterPython
		}
		err = putMetricFilter(props.LogGroupName, errorFilter, lambdaName+"-errors", "1")
		if err != nil {
			return
		}
		physicalID += "/errors"

		return

	case cfn.RequestUpdate:
		// TODO - replace existing event filters
		return event.PhysicalResourceID, nil, nil

	case cfn.RequestDelete:
		physicalID = event.PhysicalResourceID
		split := strings.Split(physicalID, ":")
		if len(split) != 4 {
			// If creation fails before any filters were created, the resourceID will be "error"
			zap.L().Warn("invalid physicalResourceId - skipping delete")
			return event.PhysicalResourceID, nil, nil
		}

		logGroupName := split[2]
		lambdaName := lambdaNameFromLogGroup(logGroupName)

		for _, filterSuffix := range strings.Split(split[3], "/") {
			filterName := lambdaName + "-" + filterSuffix
			zap.L().Info("deleting metric filter", zap.String("name", filterName))
			_, err = getCloudWatchLogsClient().DeleteMetricFilter(&cloudwatchlogs.DeleteMetricFilterInput{
				FilterName:   &filterName,
				LogGroupName: &logGroupName,
			})

			if err != nil {
				if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == cloudwatchlogs.ErrCodeResourceNotFoundException {
					zap.L().Info("metric filter has already been deleted")
					err = nil
				} else {
					err = fmt.Errorf("failed to delete %s metric filter %s: %v", logGroupName, filterName, err)
					return
				}
			}
		}
		return

	default:
		err = fmt.Errorf("unknown request type %s", event.RequestType)
		return
	}
}

// For metric/filter names, use the Lambda function name as a prefix
// "/aws/lambda/panther-alert-delivery" => "panther-alert-delivery"
func lambdaNameFromLogGroup(logGroupName string) string {
	split := strings.Split(logGroupName, "/")
	return split[len(split)-1]
}

func putMetricFilter(logGroupName, filterPattern, metricName, metricValue string) error {
	zap.L().Info("creating metric filter", zap.String("metricName", metricName))
	_, err := getCloudWatchLogsClient().PutMetricFilter(&cloudwatchlogs.PutMetricFilterInput{
		FilterName:    &metricName,
		FilterPattern: &filterPattern,
		LogGroupName:  &logGroupName,
		MetricTransformations: []*cloudwatchlogs.MetricTransformation{
			{
				DefaultValue:    aws.Float64(0),
				MetricName:      &metricName,
				MetricNamespace: aws.String("Panther"),
				MetricValue:     &metricValue,
			},
		},
	})

	if err != nil {
		return fmt.Errorf("failed to put %s metric filter: %v", metricName, err)
	}
	return nil
}
