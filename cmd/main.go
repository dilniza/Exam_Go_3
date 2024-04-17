package main

import (
	"context"
	"fmt"
	"user/api"
	"user/config"
	"user/pkg/logger"
	"user/service"
	"user/storage/postgres"
	"user/storage/redis"

	_ "github.com/joho/godotenv"
)

func main() {
	cfg := config.Load()

	log := logger.New(cfg.ServiceName)

	newRedis := redis.New(cfg)

	store, err := postgres.New(context.Background(), cfg, log, newRedis)
	if err != nil {
		fmt.Println("error while connecting db, err: ", err)
		return
	}
	defer store.CloseDB()

	services := service.New(store, log, newRedis)
	server := api.New(services, log)

	fmt.Println("programm is running on localhost:8080...")
	server.Run(":8080")

}
