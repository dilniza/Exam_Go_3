package handler

import (
	"fmt"
	"net/http"
	"user/api/models"
	"user/pkg/check"

	"github.com/gin-gonic/gin"
)

// ChangePassword godoc
// @Security     ApiKeyAuth
// @Router       /user/password/change [PATCH]
// @Summary      Change user password
// @Description  Updates a user password with the provided old and new passwords.
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        user body models.ChangePassword true "user"
// @Success      200  {object}  string
// @Failure      400  {object}  models.Response
// @Failure      500  {object}  models.Response
func (h *Handler) ChangePassword(c *gin.Context) {
	var pass models.ChangePassword
	if err := c.ShouldBindJSON(&pass); err != nil {
		handleResponseLog(c, h.Log, "error while decoding request body", http.StatusBadRequest, err.Error())
		return
	}
	if err := check.ValidatePassword(pass.OldPassword); err != nil {
		handleResponseLog(c, h.Log, "error while validating old password", http.StatusBadRequest, err.Error())
		return
	}
	if err := check.ValidatePassword(pass.NewPassword); err != nil {
		handleResponseLog(c, h.Log, "error while validating new password", http.StatusBadRequest, err.Error())
		return
	}

	msg, err := h.Services.Auth().ChangePassword(c.Request.Context(), pass)
	if err != nil {
		handleResponseLog(c, h.Log, "error while changing password", http.StatusInternalServerError, err.Error())
		return
	}

	handleResponseLog(c, h.Log, "Password changed successfully", http.StatusOK, msg)
}

// ForgetPassword godoc
// @Router       /user/password [POST]
// @Summary      User Forgetpassword
// @Description  User Forgetpassword
// @Tags         Forgetpassword
// @Accept       json
// @Produce      json
// @Param        register body models.UserMail true "register"
// @Success      201  {object}  models.Response
// @Failure      400  {object}  models.Response
// @Failure      404  {object}  models.Response
// @Failure      500  {object}  models.Response
func (h *Handler) ForgetPassword(c *gin.Context) {
	loginReq := models.UserMail{}

	if err := c.ShouldBindJSON(&loginReq); err != nil {
		handleResponseLog(c, h.Log, "error while binding body", http.StatusBadRequest, err.Error())
		return
	}

	if _, err := check.ValidateEmail(loginReq.Mail); err != nil {
		handleResponseLog(c, h.Log, "Email address is incorrect"+loginReq.Mail, http.StatusBadRequest, err.Error())
		return
	}
	err := h.Services.Auth().UserLoginOtp(c.Request.Context(), loginReq)
	if err != nil {
		handleResponseLog(c, h.Log, "error", http.StatusBadRequest, err)
		return
	}

	handleResponseLog(c, h.Log, "Otp sent successfully", http.StatusOK, "Success. Check your email")
}


// ForgetPasswordReset godoc
// @Router       /user/password/reset [POST]
// @Summary      Reset forgotten password
// @Description  Resets a user password using a one-time password for verification.
// @Tags         Forgetpassword
// @Accept       json
// @Produce      json
// @Param        user body models.ForgetPassword true "user"
// @Success      200  {object}  string
// @Failure      400  {object}  models.Response
// @Failure      500  {object}  models.Response
func (h *Handler) ForgetPasswordReset(c *gin.Context) {
	var forget models.ForgetPassword
	if err := c.ShouldBindJSON(&forget); err != nil {
		handleResponseLog(c, h.Log, "error while decoding request body", http.StatusBadRequest, err.Error())
		return
	}

	if err := check.ValidatePassword(forget.NewPassword); err != nil {
		handleResponseLog(c, h.Log, "error while validating new password", http.StatusBadRequest, err.Error())
		return
	}

	msg, err := h.Services.Auth().ForgetPasswordReset(c.Request.Context(), forget)
	if err != nil {
		handleResponseLog(c, h.Log, "error while resetting password", http.StatusInternalServerError, err.Error())
		return
	}

	handleResponseLog(c, h.Log, "Password reset successfully", http.StatusOK, msg)
}

// ChangeStatus godoc
// @Security     ApiKeyAuth
// @Router       /user/status [PATCH]
// @Summary      Change user status
// @Description  Updates the active status of a user.
// @Tags         ChangeStatus
// @Accept       json
// @Produce      json
// @Param        status body models.ChangeStatus true "status"
// @Success      200  {object}  string
// @Failure      400  {object}  models.Response
// @Failure      500  {object}  models.Response
func (h *Handler) ChangeStatus(c *gin.Context) {
	var status models.ChangeStatus
	if err := c.ShouldBindJSON(&status); err != nil {
		handleResponseLog(c, h.Log, "error while decoding request body", http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.Services.Auth().ChangeStatus(c.Request.Context(), status)
	if err != nil {
		handleResponseLog(c, h.Log, "error while changing user status", http.StatusInternalServerError, err.Error())
		return
	}

	handleResponseLog(c, h.Log, "User status updated successfully", http.StatusOK, "Status changed for: "+userID)
}

// UserLoginMailPassword godoc
// @Router       /user/login [POST]
// @Summary      User login
// @Description  User login
// @Tags         Login
// @Accept       json
// @Produce      json
// @Param        login body models.UserLoginRequest true "login"
// @Success      201  {object}  models.UserLoginResponse
// @Failure      400  {object}  models.Response
// @Failure      404  {object}  models.Response
// @Failure      500  {object}  models.Response
func (h *Handler) UserLoginMailPassword(c *gin.Context) {
	loginReq := models.UserLoginRequest{}

	if err := c.ShouldBindJSON(&loginReq); err != nil {
		handleResponseLog(c, h.Log, "error while binding body", http.StatusBadRequest, err)
		return
	}
	fmt.Println("loginReq: ", loginReq)

	if err := check.ValidatePassword(loginReq.Password); err != nil {
		handleResponseLog(c, h.Log, "error while validating password", http.StatusBadRequest, err.Error())
		return
	}

	loginResp, err := h.Services.Auth().UserLoginMailPassword(c.Request.Context(), loginReq)
	if err != nil {
		handleResponseLog(c, h.Log, "unauthorized", http.StatusUnauthorized, err)
		return
	}

	handleResponseLog(c, h.Log, "Logged in successfully", http.StatusOK, loginResp)

}

// UserRegister godoc
// @Router       /user/register [POST]
// @Summary      User register
// @Description  User register
// @Tags         Register
// @Accept       json
// @Produce      json
// @Param        register body models.UserMail true "register"
// @Success      201  {object}  models.Response
// @Failure      400  {object}  models.Response
// @Failure      404  {object}  models.Response
// @Failure      500  {object}  models.Response
func (h *Handler) UserRegister(c *gin.Context) {
	loginReq := models.UserMail{}

	if err := c.ShouldBindJSON(&loginReq); err != nil {
		handleResponseLog(c, h.Log, "error while binding body", http.StatusBadRequest, err)
		return
	}
	fmt.Println("loginReq: ", loginReq)

	if _, err := check.ValidateEmail(loginReq.Mail); err != nil {
		handleResponseLog(c, h.Log, "error while validating email"+loginReq.Mail, http.StatusBadRequest, err.Error())
		return
	}

	err := h.Services.Auth().UserRegister(c.Request.Context(), loginReq)
	if err != nil {
		handleResponseLog(c, h.Log, "", http.StatusInternalServerError, err)
		return
	}

	handleResponseLog(c, h.Log, "Otp sent successfully", http.StatusOK, "Success")
}

// UserRegisterConfirm godoc
// @Router       /user/register-confirm [POST]
// @Summary      User register
// @Description  User register
// @Tags         Register
// @Accept       json
// @Produce      json
// @Param        register body models.UserLoginMailOtp true "register"
// @Success      201  {object}  models.UserLoginResponse
// @Failure      400  {object}  models.Response
// @Failure      404  {object}  models.Response
// @Failure      500  {object}  models.Response
func (h *Handler) UserRegisterConfirm(c *gin.Context) {
	req := models.UserLoginMailOtp{}

	if err := c.ShouldBindJSON(&req); err != nil {
		handleResponseLog(c, h.Log, "error while binding body", http.StatusBadRequest, err)
		return
	}
	fmt.Println("req: ", req)

	if _, err := check.ValidateEmail(req.Mail); err != nil {
		handleResponseLog(c, h.Log, "error while validating email"+req.Mail, http.StatusBadRequest, err.Error())
		return
	}

	if err := check.ValidatePassword(req.User.Password); err != nil {
		handleResponseLog(c, h.Log, "error while validating password", http.StatusBadRequest, err.Error())
		return
	}

	confResp, err := h.Services.Auth().UserRegisterConfirm(c.Request.Context(), req)
	if err != nil {
		handleResponseLog(c, h.Log, "error while confirming", http.StatusUnauthorized, err.Error())
		return
	}

	handleResponseLog(c, h.Log, "Registered successfully", http.StatusOK, confResp)

}

// UserLoginWithEmail godoc
// @Router       /user/login/email [POST]
// @Summary      User login with mail
// @Description  User logins with mail, otp is sent to user mail
// @Tags         Login
// @Accept       json
// @Produce      json
// @Param        login body models.UserMail true "login"
// @Success      201  {object}  models.Response
// @Failure      400  {object}  models.Response
// @Failure      404  {object}  models.Response
// @Failure      500  {object}  models.Response
func (h *Handler) UserLoginWithEmail(c *gin.Context) {
	req := models.UserMail{}

	if err := c.ShouldBindJSON(&req); err != nil {
		handleResponseLog(c, h.Log, "error while binding body", http.StatusBadRequest, err)
		return
	}

	if _, err := check.ValidateEmail(req.Mail); err != nil {
		handleResponseLog(c, h.Log, "error while validating email"+req.Mail, http.StatusBadRequest, err.Error())
		return
	}

	err := h.Services.Auth().UserLoginOtp(c.Request.Context(), req)
	if err != nil {
		handleResponseLog(c, h.Log, "error while sending otp to mail", http.StatusUnauthorized, err.Error())
		return
	}

	handleResponseLog(c, h.Log, "Logged in successfully", http.StatusOK, "Success")

}

// UserLoginWithOtp godoc
// @Router       /user/login/otp [POST]
// @Summary      User logins with otp
// @Description  User inputs otp and mail
// @Tags         Login
// @Accept       json
// @Produce      json
// @Param        login body models.UserLoginMailOtp true "login"
// @Success      201  {object}  models.UserLoginResponse
// @Failure      400  {object}  models.Response
// @Failure      404  {object}  models.Response
// @Failure      500  {object}  models.Response
func (h *Handler) UserLoginWithOtp(c *gin.Context) {
	req := models.UserLoginMailOtp{}

	if err := c.ShouldBindJSON(&req); err != nil {
		handleResponseLog(c, h.Log, "error while binding body", http.StatusBadRequest, err)
		return
	}
	fmt.Println("req: ", req)

	if _, err := check.ValidateEmail(req.Mail); err != nil {
		handleResponseLog(c, h.Log, "error while validating email"+req.Mail, http.StatusBadRequest, err.Error())
		return
	}

	if err := check.ValidatePassword(req.User.Password); err != nil {
		handleResponseLog(c, h.Log, "error while validating password", http.StatusBadRequest, err.Error())
		return
	}

	confResp, err := h.Services.Auth().UserRegisterConfirm(c.Request.Context(), req)
	if err != nil {
		handleResponseLog(c, h.Log, "error while confirming", http.StatusUnauthorized, err.Error())
		return
	}

	handleResponseLog(c, h.Log, "Succes", http.StatusOK, confResp)

}