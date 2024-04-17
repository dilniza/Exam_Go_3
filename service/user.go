package service

import (
	"context"
	"encoding/json"
	"user/api/models"
	"user/pkg/logger"
	"user/storage"
)

type userService struct {
	storage storage.IStorage
	logger  logger.ILogger
	redis   storage.IRedisStorage
}

func NewUserService(storage storage.IStorage, logger logger.ILogger, redis storage.IRedisStorage) userService {
	return userService{
		storage: storage,
		logger:  logger,
		redis:   redis,
	}
}

func (s userService) Create(ctx context.Context, user models.CreateUser) (string, error) {
	pKey, err := s.storage.User().Create(ctx, user)
	if err != nil {
		s.logger.Error("failed to create user", logger.Error(err))
		return "", err
	}

	return pKey, nil
}

func (s userService) Update(ctx context.Context, user models.UpdateUser, id string) (string, error) {
	id, err := s.storage.User().Update(ctx, user, id)
	if err != nil {
		s.logger.Error("failed to update user", logger.Error(err))
		return "", err
	}

	err = s.redis.Del(ctx, "user_id:"+id)
	if err != nil {
		s.logger.Error("failed to delete user data from Redis", logger.Error(err))
	}

	return id, nil
}

func (s userService) GetByID(ctx context.Context, id string) (models.User, error) {
	var user models.User
	userData, err := s.redis.Get(ctx, "user_id:"+id)
	if err == nil {
		err := json.Unmarshal([]byte(userData.(string)), &user)
		if err != nil {
			s.logger.Error("failed to unmarshal user data from Redis", logger.Error(err))
		} else {
			return user, nil
		}
	}

	user, err = s.storage.User().GetByID(ctx, id)
	if err != nil {
		s.logger.Error("failed to get user by ID", logger.Error(err))
		return models.User{}, err
	}
	return user, nil
}

func (s userService) GetAll(ctx context.Context, req models.GetAllUsersRequest) (models.GetAllUsersResponse, error) {
	users, err := s.storage.User().GetAll(ctx, req)
	if err != nil {
		s.logger.Error("failed to get all users", logger.Error(err))
		return models.GetAllUsersResponse{}, err
	}
	return users, nil
}

func (s userService) Delete(ctx context.Context, id string) error {
	err := s.storage.User().Delete(ctx, id)
	if err != nil {
		s.logger.Error("failed to delete user", logger.Error(err))
		return err
	}

	err = s.redis.Del(ctx, "user_id:"+id)
	if err != nil {
		s.logger.Error("failed to delete user data from Redis", logger.Error(err))
	}
	return nil
}
