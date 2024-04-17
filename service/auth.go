package service

import (
	"context"
	"user/api/models"
	"user/pkg/logger"
	"user/storage"

	"golang.org/x/crypto/bcrypt"
)

type authService struct {
	storage storage.IStorage
	logger  logger.ILogger
	redis   storage.IRedisStorage
}

func NewAuthService(storage storage.IStorage, log logger.ILogger, redis storage.IRedisStorage) authService {
	return authService{
		storage: storage,
		logger:  log,
		redis:   redis,
	}
}

func (a authService) ChangePassword(ctx context.Context, pass models.ChangePassword) (string, error) {
	result, err := a.storage.User().ChangePassword(ctx, pass)
	if err != nil {
		a.logger.Error("failed to change password", logger.Error(err))
		return "", err
	}
	return result, nil
}

func (a authService) ForgetPassword(ctx context.Context, forget models.ForgetPassword) (string, error) {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(forget.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		a.logger.Error("failed to generate user new password", logger.Error(err))
		return "", err
	}
	forget.NewPassword = string(hashedPass)

	result, err := a.storage.User().ForgetPassword(ctx, forget)
	if err != nil {
		a.logger.Error("failed to reset password", logger.Error(err))
		return "", err
	}
	return result, nil
}

func (a authService) ChangeStatus(ctx context.Context, status models.ChangeStatus) (string, error) {
	result, err := a.storage.User().ChangeStatus(ctx, status)
	if err != nil {
		a.logger.Error("failed to change user status", logger.Error(err))
		return "", err
	}
	return result, nil
}
