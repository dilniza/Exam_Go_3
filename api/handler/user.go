package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"user/api/models"
	"user/pkg/check"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// CreateUser godoc
// @Router      /user [POST]
// @Summary     Create a user
// @Description This api creates a new user.
// @Tags        user
// @Accept      json
// @Produce 	json
// @Param 		user body models.CreateUser true "user"
// @Success 	200  {object}  string
// @Failure		400  {object}  models.Response
// @Failure		404  {object}  models.Response
// @Failure		500  {object}  models.Response
func (h Handler) CreateUser(c *gin.Context) {
	user := models.CreateUser{}

	if err := c.ShouldBindJSON(&user); err != nil {
		handleResponseLog(c, h.Log, "error while decoding request body", http.StatusBadRequest, err.Error())
		return
	}

	if _, err := check.ValidateEmail(user.Mail); err != nil {
		handleResponseLog(c, h.Log, "error while validating email"+user.Mail, http.StatusBadRequest, err.Error())
		return
	}

	if _, err := check.ValidatePhone(user.Phone); err != nil {
		handleResponseLog(c, h.Log, "error while validating phone", http.StatusBadRequest, err.Error())
		return
	}

	if err := check.ValidatePassword(user.Password); err != nil {
		handleResponseLog(c, h.Log, "error while validating password", http.StatusBadRequest, err.Error())
		return
	}

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(
		user.Password,
	), bcrypt.DefaultCost)
	if err != nil {
		handleResponseLog(c, h.Log, "error while generating user password", http.StatusInternalServerError, err.Error())
		return
	}
	user.Password = string(hashedPass)

	id, err := h.Services.User().Create(c.Request.Context(), user)
	if err != nil {
		handleResponseLog(c, h.Log, "error while creating user", http.StatusInternalServerError, err.Error())
		return
	}

	handleResponseLog(c, h.Log, "User was successfully created", http.StatusOK, id)
}

// UpdateUser godoc
// @Security ApiKeyAuth
// @Router		/user/{id} [PUT]
// @Summary		update a user
// @Description This api updates a user by its id and returns id.
// @Tags		user
// @Accept		json
// @Produce		json
// @Param 		id path string true "User ID"
// @Param		user body models.UpdateUser true "user"
// @Success		200  {object}  string
// @Failure		400  {object}  models.Response
// @Failure		404  {object}  models.Response
// @Failure		500  {object}  models.Response
func (h Handler) UpdateUser(c *gin.Context) {
	user := models.UpdateUser{}

	if err := c.ShouldBindJSON(&user); err != nil {
		handleResponseLog(c, h.Log, "error while decoding request body", http.StatusBadRequest, err.Error())
		return
	}

	id := c.Param("id")

	err := uuid.Validate(id)
	if err != nil {
		handleResponseLog(c, h.Log, "error while validating id"+id, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := check.ValidateEmail(user.Mail); err != nil {
		handleResponseLog(c, h.Log, "error while validating email"+user.Mail, http.StatusBadRequest, err.Error())
		return
	}

	if _, err := check.ValidatePhone(user.Phone); err != nil {
		handleResponseLog(c, h.Log, "error while validating phone", http.StatusBadRequest, err.Error())
		return
	}

	ID, err := h.Services.User().Update(c.Request.Context(), user, id)
	if err != nil {
		handleResponseLog(c, h.Log, "error while updating user", http.StatusInternalServerError, err.Error())
		return
	}

	handleResponseLog(c, h.Log, "User was successfully updated", http.StatusOK, ID)
}

// GetUserById godoc
// @Security ApiKeyAuth
// @Router		/user/{id} [GET]
// @Summary		get a user by its id
// @Description This api gets a user by its id and returns its information.
// @Tags		user
// @Accept		json
// @Produce		json
// @Param		id path string true "user"
// @Success		200  {object}  models.User
// @Failure		400  {object}  models.Response
// @Failure		404  {object}  models.Response
// @Failure		500  {object}  models.Response
func (h Handler) GetUserByID(c *gin.Context) {
	id := c.Param("id")

	if id == "" {
		handleResponseLog(c, h.Log, "missing user ID", http.StatusBadRequest, id)
		return
	}

	user, err := h.Services.User().GetByID(c.Request.Context(), id)
	if err != nil {
		handleResponseLog(c, h.Log, "error while getting user by ID", http.StatusBadRequest, err.Error())
		return
	}

	handleResponseLog(c, h.Log, "User was successfully gotten by Id", http.StatusOK, user)
}

// GetAllUsers godoc
// @Security ApiKeyAuth
// @Router 			/user [GET]
// @Summary 		Get all users
// @Description		Retrieves information about all users.
// @Tags 			user
// @Accept 			json
// @Produce 		json
// @Param 			search query string true "users"
// @Param 			page query uint64 false "page"
// @Param 			limit query uint64 false "limit"
// @Success 		200 {object} models.GetAllUsersResponse
// @Failure 		400 {object} models.Response
// @Failure 		500 {object} models.Response
func (h Handler) GetAllUsers(c *gin.Context) {
	var (
		req = models.GetAllUsersRequest{}
	)

	req.Search = c.Query("search")

	page, err := strconv.ParseUint(c.DefaultQuery("page", "1"), 10, 64)
	if err != nil {
		handleResponseLog(c, h.Log, "error while parsing page", http.StatusBadRequest, err.Error())
		return
	}

	limit, err := strconv.ParseUint(c.DefaultQuery("limit", "10"), 10, 64)
	if err != nil {
		handleResponseLog(c, h.Log, "error while parsing limit", http.StatusBadRequest, err.Error())
		return
	}

	req.Page = page
	req.Limit = limit

	users, err := h.Services.User().GetAll(c.Request.Context(), req)
	if err != nil {
		handleResponseLog(c, h.Log, "error while getting users", http.StatusInternalServerError, err.Error())
		return
	}

	handleResponseLog(c, h.Log, "Users were successfully gotten by Id", http.StatusOK, users)
}

// DeleteUser godoc
// @Security ApiKeyAuth
// @Router		/user/{id} [DELETE]
// @Summary		delete a user by its id
// @Description This api deletes a user by its id and returns success message.
// @Tags		user
// @Accept		json
// @Produce		json
// @Param		id path string true "user ID"
// @Success		200  {object}  nil
// @Failure		400  {object}  models.Response
// @Failure		404  {object}  models.Response
// @Failure		500  {object}  models.Response
func (h Handler) DeleteUser(c *gin.Context) {
	id := c.Param("id")
	fmt.Println("id: ", id)

	if id == "" {
		handleResponseLog(c, h.Log, "missing car ID", http.StatusBadRequest, id)
		return
	}

	err := uuid.Validate(id)
	if err != nil {
		handleResponseLog(c, h.Log, "error while validating id", http.StatusBadRequest, err.Error())
		return
	}

	err = h.Services.User().Delete(c.Request.Context(), id)
	if err != nil {
		handleResponseLog(c, h.Log, "error while deleting user", http.StatusInternalServerError, err.Error())
		return
	}

	handleResponseLog(c, h.Log, "User was successfully deleted", http.StatusOK, id)
}
