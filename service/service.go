package service

import (
	"user/pkg/logger"
	"user/storage"
)

type IServiceManager interface {
	User() userService
	Auth() authService
}

type Service struct {
	userService userService
	auth        authService

	logger logger.ILogger
}

func New(storage storage.IStorage, log logger.ILogger, redis storage.IRedisStorage) Service {
	return Service{
		userService: NewUserService(storage, log, redis),
		auth:        NewAuthService(storage, log, redis),
		logger:      log,
	}
}

func (s Service) User() userService {
	return s.userService
}

func (s Service) Auth() authService {
	return s.auth
}
