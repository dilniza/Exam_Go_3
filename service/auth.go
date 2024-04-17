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
	"user/pkg/smtp"
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

func (a authService) ForgetPasswordReset(ctx context.Context, forget models.ForgetPassword) (string, error) {
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

func (a authService) UserLoginMailPassword(ctx context.Context, user models.UserLoginRequest) (models.UserLoginResponse, error) {

	_, err := a.storage.User().LoginByMailAndPassword(ctx, user)
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
	if err != nil {
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

func (a authService) UserRegister(ctx context.Context, loginRequest models.UserMail) error {
	_, err := a.storage.User().CheckMailExists(ctx, loginRequest.Mail)
	if err != nil {
		a.logger.Error("error while checking email existence", logger.Error(err))
		return err
	}

	fmt.Println(" loginRequest.Login: ", loginRequest.Mail)
	otpCode := pkg.GenerateOTP()

	msg := fmt.Sprintf("Your OTP code is: %v, for registering RENT_CAR. Don't give it to anyone", otpCode)

	err = a.redis.Set(ctx, loginRequest.Mail, otpCode, time.Minute*2)
	if err != nil {
		a.logger.Error("error while setting otpCode to redis user register", logger.Error(err))
		return err
	}

	err = smtp.SendMail(loginRequest.Mail, msg)
	if err != nil {
		a.logger.Error("error while sending otp code to user register", logger.Error(err))
		return err
	}

	return nil
}

func (a authService) UserRegisterConfirm(ctx context.Context, req models.UserLoginMailOtp) (models.UserLoginResponse, error) {
	resp := models.UserLoginResponse{}

	otp, err := a.redis.Get(ctx, req.Mail)
	if err != nil {
		a.logger.Error("error while getting otp code for customer register confirm", logger.Error(err))
		return resp, err
	}
	
	if req.Otp != otp {
		a.logger.Error("incorrect otp code for customer register confirm", logger.Error(err))
		return resp, errors.New("incorrect otp code")
	}

	req.User.Mail = req.Mail
	id, err := a.storage.User().Create(ctx, req.User)
	if err != nil {
		a.logger.Error("error while creating customer", logger.Error(err))
		return resp, err
	}
	var m = make(map[interface{}]interface{})

	m["user_id"] = id
	m["user_role"] = config.USER_ROLE

	accessToken, refreshToken, err := jwt.GenJWT(m)
	if err != nil {
		a.logger.Error("error while generating tokens for customer register confirm", logger.Error(err))
		return resp, err
	}
	resp.AccessToken = accessToken
	resp.RefreshToken = refreshToken

	return resp, nil
}