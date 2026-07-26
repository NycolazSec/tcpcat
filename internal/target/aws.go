package target

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// stringPtr est un utilitaire pour obtenir un pointeur vers une chaîne de caractères.
func stringPtr(s string) *string {
	return &s
}

// LoadFromAWSTags récupère les adresses IP publiques des instances EC2 correspondant aux tags donnés.
func LoadFromAWSTags(region, tagsStr string) ([]string, error) {
	if region == "" {
		return nil, fmt.Errorf("la région AWS est requise (--aws-region)")
	}

	filters, err := parseTagsToFilters(tagsStr)
	if err != nil {
		return nil, fmt.Errorf("format de tags invalide: %w", err)
	}

	// Ajoute un filtre pour ne récupérer que les instances en cours d'exécution.
	filters = append(filters, types.Filter{
		Name:   stringPtr("instance-state-name"),
		Values: []string{"running"},
	})

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("impossible de charger la configuration AWS (vérifiez vos credentials): %w", err)
	}

	client := ec2.NewFromConfig(cfg)

	input := &ec2.DescribeInstancesInput{
		Filters: filters,
	}

	paginator := ec2.NewDescribeInstancesPaginator(client, input)

	var ips []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			return nil, fmt.Errorf("échec de la récupération des instances EC2: %w", err)
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

// parseTagsToFilters convertit une chaîne de tags (ex: "Key=Env,Value=Prod") en filtres pour l'API EC2.
func parseTagsToFilters(tagsStr string) ([]types.Filter, error) {
	if tagsStr == "" {
		return nil, fmt.Errorf("la chaîne de tags ne peut pas être vide")
	}

	var filters []types.Filter
	pairs := strings.Split(tagsStr, ",")

	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("paire de tags malformée: '%s'", pair)
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
