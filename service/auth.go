package service

import (
	"context"
	"errors"
	"fmt"
	"time"
	"user/api/models"
	"user/config"
	"user/pkg"
	"user/pkg/jwt"
	"user/pkg/logger"
	"user/smtp"
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

func (a authService) UserLogin(ctx context.Context, loginRequest models.UserLoginRequest) (models.UserLoginResponse, error) {
	fmt.Println(" loginRequest.Mail: ", loginRequest.Mail)
	_, err := a.storage.User().LoginByMail(ctx, loginRequest.Mail)
	if err != nil {
		a.logger.Error("error while getting user credentials by login", logger.Error(err))
		return models.UserLoginResponse{}, err
	}

	m := make(map[interface{}]interface{})

	m["user_role"] = config.USER_ROLE

	accessToken, refreshToken, err := jwt.GenJWT(m)
	if err != nil {
		a.logger.Error("error while generating tokens for user login", logger.Error(err))
		return models.UserLoginResponse{}, err
	}

	return models.UserLoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (a authService) UserLoginOtp(ctx context.Context, mail models.UserMail) error {

	_, err := a.storage.User().CheckMailExists(ctx, mail.Mail)
	if err == nil {
		a.logger.Error("gmail address isn't registered", logger.Error(err))
		return errors.New("gmail address isn't registered")
	}

	otpCode := pkg.GenerateOTP()

	msg := fmt.Sprintf("Your OTP code is: %v, for registering RENT_CAR. Don't give it to anyone", otpCode)

	err = a.redis.Set(ctx, mail.Mail, otpCode, time.Minute*2)
	if err != nil {
		a.logger.Error("error while setting otpCode to redis User register", logger.Error(err))
		return err
	}

	err = smtp.SendMail(mail.Mail, msg)
	if err != nil {
		a.logger.Error("error while sending otp code to User register", logger.Error(err))
		return err
	}

	return nil
}
