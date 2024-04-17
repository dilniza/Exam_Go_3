package models

type UserLoginRequest struct {
	Mail     string `json:"mail"`
	Password string `json:"password"`
}

type UserLoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type AuthInfo struct {
	UserID   string `json:"user_id"`
	UserRole string `json:"user_role"`
}

type ChangePassword struct {
	Mail        string `json:"mail"`
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type UserMail struct {
	Mail string `json:"mail"`
}

type UserLoginMailOtp struct {
	Mail string     `json:"mail"`
	Otp  string     `json:"otp"`
	User CreateUser `json:"user"`
}

type ForgetPassword struct {
	Mail        string `json:"mail"`
	Otp         string `json:"otp"`
	NewPassword string `json:"new_password"`
}
