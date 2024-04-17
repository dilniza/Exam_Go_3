package redis

import (
	"context"
	"fmt"
	"user/config"
	"user/storage"

	"time"

	"github.com/redis/go-redis/v9"
)

type Store struct {
	db *redis.Client
}

func New(cfg config.Config) storage.IRedisStorage {
	redisClient := redis.NewClient(&redis.Options{
		Addr: cfg.RedisHost + ":" + cfg.RedisPort,
	})

	return Store{
		db: redisClient,
	}
}

func (s Store) Set(ctx context.Context, key string, value interface{}, duration time.Duration) error {
	statusCmd := s.db.SetEx(ctx, key, value, duration)
	if statusCmd.Err() != nil {
		return statusCmd.Err()
	}
	fmt.Println("Saved in redis cache")
	return nil
}

func (s Store) Get(ctx context.Context, key string) (interface{}, error) {
	resp := s.db.Get(ctx, key)

	if resp.Err() != nil {
		return nil, resp.Err()
	}
	fmt.Println("Gotten in redis cache")
	return resp.Val(), nil
}

// 127.0.0.1:6379> GET user_id:610fd550-427c-4fec-81c1-1549f2f4f88d
// (nil)

func (s Store) Del(ctx context.Context, key string) error {
	statusCmd := s.db.Del(ctx, key)
	if statusCmd.Err() != nil {
		return statusCmd.Err()
	}
	fmt.Println("Deleted from redis cache")
	return nil
}
