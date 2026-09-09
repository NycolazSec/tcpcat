package target

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func stringPtr(s string) *string {
	return &s
}

func LoadFromAWSTags(region, tagsStr string) ([]string, error) {
	if region == "" {
		return nil, fmt.Errorf("AWS region is required (--aws-region)")
	}

	filters, err := parseTagsToFilters(tagsStr)
	if err != nil {
		return nil, fmt.Errorf("invalid tag format: %w", err)
	}

	filters = append(filters, types.Filter{
		Name:   stringPtr("instance-state-name"),
		Values: []string{"running"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS configuration (check your credentials): %w", err)
	}

	client := ec2.NewFromConfig(cfg)

	input := &ec2.DescribeInstancesInput{
		Filters: filters,
	}

	paginator := ec2.NewDescribeInstancesPaginator(client, input)

	var ips []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve EC2 instances: %w", err)
		}

		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				if instance.PublicIpAddress != nil {
					ips = append(ips, *instance.PublicIpAddress)
				}
			}
		}
	}

	return ips, nil
}

func parseTagsToFilters(tagsStr string) ([]types.Filter, error) {
	if tagsStr == "" {
		return nil, fmt.Errorf("tag string cannot be empty")
	}

	var filters []types.Filter
	pairs := strings.Split(tagsStr, ",")

	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("malformed tag pair: '%s'", pair)
		}
		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		filters = append(filters, types.Filter{
			Name:   stringPtr("tag:" + key),
			Values: []string{value},
		})
	}

	return filters, nil
}
