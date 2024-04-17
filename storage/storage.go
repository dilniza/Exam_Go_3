package storage

import (
	"context"
	"user/api/models"

	"time"
)

type IStorage interface {
	CloseDB()
	User() IUserStorage
	Redis() IRedisStorage
}

type IUserStorage interface {
	Create(ctx context.Context, User models.CreateUser) (string, error)
	Update(ctx context.Context, User models.UpdateUser, id string) (string, error)
	GetByID(ctx context.Context, id string) (models.User, error)
	GetAll(ctx context.Context, req models.GetAllUsersRequest) (models.GetAllUsersResponse, error)
	Delete(ctx context.Context, id string) error
	ChangePassword(ctx context.Context, pass models.ChangePassword) (string, error)
	CheckMailExists(ctx context.Context, mail string) (bool, error)
	ForgetPassword(ctx context.Context, forget models.ForgetPassword) (string, error)
	ChangeStatus(ctx context.Context, status models.ChangeStatus) (string, error)
	LoginByMail(ctx context.Context, login string) (string, error)
}

type IRedisStorage interface {
	Set(ctx context.Context, key string, value interface{}, duration time.Duration) error
	Get(ctx context.Context, key string) (interface{}, error)
	Del(ctx context.Context, key string) error
}
