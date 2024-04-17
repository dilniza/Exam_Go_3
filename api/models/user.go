package models

type GetUser struct {
	ID        string `json:"id"`
	Mail      string `json:"mail"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Phone     string `json:"phone"`
	Sex       string `json:"sex"`
	Active    bool   `json:"active"`
}

type User struct {
	ID        string `json:"id"`
	Mail      string `json:"mail"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Password  string `json:"password"`
	Phone     string `json:"phone"`
	Sex       string `json:"sex"`
	Active    bool   `json:"active"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at"`
}

type CreateUser struct {
	Mail      string `json:"mail"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Password  string `json:"password"`
	Phone     string `json:"phone"`
	Sex       string `json:"sex"`
}

type UpdateUser struct {
	Mail      string `json:"mail"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Phone     string `json:"phone"`
}

type GetAllUsersRequest struct {
	Search string `json:"search"`
	Page   uint64 `json:"page"`
	Limit  uint64 `json:"limit"`
}

type GetAllUsersResponse struct {
	Users []User `json:"users"`
	Count int64  `json:"count"`
}

type ChangeStatus struct {
	ID     string `json:"id"`
	Active bool   `json:"active"`
}
