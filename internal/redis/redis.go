package redis

import (
	"context"

	"github.com/redis/go-redis/v9"
)

func NewClient(addr, password string, db int) redis.UniversalClient {
	return redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})
}

func Ping(ctx context.Context, client redis.UniversalClient) error {
	return client.Ping(ctx).Err()
}
