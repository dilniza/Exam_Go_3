package api

import (
	"errors"
	"fmt"
	"net/http"
	"user/api/handler"
	"user/pkg/logger"
	"user/service"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	_ "user/api/docs"
)

// New ...
// @title           Swagger Example API
// @version         1.0
// @description     This is a sample server celler server.
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
func New(services service.IServiceManager, log logger.ILogger) *gin.Engine {
	h := handler.NewStrg(services, log)

	r := gin.Default()
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	r.POST("/user", h.CreateUser)
	
	//2
	r.POST("/user/register", h.UserRegister)
	r.POST("/user/register-confirm", h.UserRegisterConfirm)
	//3
	r.POST("/user/login", h.UserLoginMailPassword)
	//4
	r.POST("/user/login/email", h.UserLoginWithEmail)
	r.POST("/user/login/otp", h.UserLoginWithOtp)
	//5
	r.PATCH("/user/password/change", h.ChangePassword)
	//6
	r.POST("/user/password", h.ForgetPassword)
	r.POST("/user/password/reset", h.ForgetPasswordReset)
	//7
	r.PATCH("/user/status", h.ChangeStatus)

	r.Use(authMiddleware)
	r.Use(logMiddleware)
	//1
	r.PUT("/user/:id", h.UpdateUser)
	r.GET("/user/:id", h.GetUserByID)
	r.GET("/user", h.GetAllUsers)
	r.DELETE("/user/:id", h.DeleteUser)

	return r
}

func authMiddleware(c *gin.Context) {
	auth := c.GetHeader("Authorization")
	if auth == "" {
		c.AbortWithError(http.StatusUnauthorized, errors.New("unauthorized"))
	}
	c.Next()
}

func logMiddleware(c *gin.Context) {
	headers := c.Request.Header

	for key, values := range headers {
		for _, v := range values {
			fmt.Printf("Header: %v, Value: %v\n", key, v)
		}
	}

	c.Next()
}
