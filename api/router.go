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
	
	r.POST("user/password", h.ForgetPasswordOtp)
	r.POST("user/password/reset", h.ForgetPassword)
	r.POST("user/login", h.LoginUser)
	r.POST("user/register", h.UserRegister)
	r.POST("user/register-confirm", h.UserRegisterConfirm)

	r.Use(authMiddleware)
	r.Use(logMiddleware)
	
	r.PATCH("/user", h.ChangePassword)
	r.PATCH("/user/status", h.ChangeStatus)

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
