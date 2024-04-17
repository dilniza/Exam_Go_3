package postgres

import (
	"context"
	"exam3/storage"
	"fmt"
	"time"
	"user/config"
	"user/pkg/logger"
	postgres "user/storage"
	"user/storage/redis"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/lib/pq"
)

type Store struct {
	Pool   *pgxpool.Pool
	logger logger.ILogger
	cfg    config.Config
	redis  storage.IRedisStorage
}

func New(ctx context.Context, cfg config.Config, logger logger.ILogger, redis storage.IRedisStorage) (postgres.IStorage, error) {
	url := fmt.Sprintf(`host=%s port=%v user=%s password=%s database=%s sslmode=disable`,
		cfg.PostgresHost, cfg.PostgresPort, cfg.PostgresUser, cfg.PostgresPassword, cfg.PostgresDatabase)

	pgPoolConfig, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}

	pgPoolConfig.MaxConns = 100
	pgPoolConfig.MaxConnLifetime = time.Hour

	newPool, err := pgxpool.NewWithConfig(context.Background(), pgPoolConfig)
	if err != nil {
		fmt.Println("error while connecting to db", err.Error())
		return nil, err
	}

	return Store{
		Pool:   newPool,
		logger: logger,
		cfg:    cfg,
		redis:  redis,
	}, nil
}

func (s Store) CloseDB() {
	s.Pool.Close()
}

func (s Store) User() storage.IUserStorage {
	newUser := NewUserRepo(s.Pool, s.logger, s.redis)

	return &newUser
}

func (s Store) Redis() storage.IRedisStorage {
	return redis.New(s.cfg)
}
