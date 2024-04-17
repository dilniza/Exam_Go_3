package handler

import (
	"net/http"
	"user/api/models"
	"user/pkg/check"

	"github.com/gin-gonic/gin"
)

// ChangePasswordHandler godoc
// @Security     ApiKeyAuth
// @Router       /user/password [PATCH]
// @Summary      Change user password
// @Description  Updates a user password with the provided old and new passwords.
// @Tags         user
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

// ForgetPasswordHandler godoc
// @Router       /user/password/reset [POST]
// @Summary      Reset forgotten password
// @Description  Resets a user password using a one-time password for verification.
// @Tags         user
// @Accept       json
// @Produce      json
// @Param        user body models.ForgetPassword true "user"
// @Success      200  {object}  string
// @Failure      400  {object}  models.Response 
// @Failure      500  {object}  models.Response 
func (h *Handler) ForgetPassword(c *gin.Context) {
	var forget models.ForgetPassword
	if err := c.ShouldBindJSON(&forget); err != nil {
		handleResponseLog(c, h.Log, "error while decoding request body", http.StatusBadRequest, err.Error())
		return
	}

	// Validate OTP

	if err := check.ValidatePassword(forget.NewPassword); err != nil {
		handleResponseLog(c, h.Log, "error while validating new password", http.StatusBadRequest, err.Error())
		return
	}

	msg, err := h.Services.Auth().ForgetPassword(c.Request.Context(), forget)
	if err != nil {
		handleResponseLog(c, h.Log, "error while resetting password", http.StatusInternalServerError, err.Error())
		return
	}

	handleResponseLog(c, h.Log, "Password reset successfully", http.StatusOK, msg)
}

// ChangeStatusHandler godoc
// @Security     ApiKeyAuth
// @Router       /user/status [PATCH]
// @Summary      Change user status
// @Description  Updates the active status (enabled/disabled) of a user.
// @Tags         user
// @Accept       json
// @Produce      json
// @Param        status body models.ChangeStatus true "user"
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

	handleResponseLog(c, h.Log, "User status updated successfully", http.StatusOK, userID)
}
