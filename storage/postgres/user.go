package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"user/api/models"
	"user/pkg/logger"
	"user/storage"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type UserRepo struct {
	db     *pgxpool.Pool
	logger logger.ILogger
	redis  storage.IRedisStorage
}

func NewUserRepo(db *pgxpool.Pool, log logger.ILogger, redis storage.IRedisStorage) UserRepo {
	return UserRepo{
		db:     db,
		logger: log,
		redis:  redis,
	}
}

func (c *UserRepo) Create(ctx context.Context, user models.CreateUser) (string, error) {
	id := uuid.New().String()
	query := `INSERT INTO "Users" (
        id,
		mail,
        first_name,
        last_name,
		password,
        phone,
        sex,
        created_at,
        updated_at
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`

	_, err := c.db.Exec(ctx, query,
		id,
		user.Mail,
		user.FirstName,
		user.LastName,
		user.Password,
		user.Phone,
		user.Sex,
	)
	if err != nil {
		c.logger.Error("failed to create user in database", logger.Error(err))
		return "", err
	}

	UserJSON, err := json.Marshal(user)
	if err != nil {
		c.logger.Error("failed to marshal User data for Redis", logger.Error(err))
	} else {
		err = c.redis.Set(ctx, "User_id:"+id, string(UserJSON), time.Minute*2)
		if err != nil {
			c.logger.Error("failed to save create User data in Redis", logger.Error(err))
		}
	}

	return id, nil
}

func (c *UserRepo) Update(ctx context.Context, user models.UpdateUser, id string) (string, error) {
	query := `UPDATE "Users" SET
		first_name = $1,
		last_name = $2,
		mail = $3,
		phone = $4,
		updated_at = $5
	WHERE id = $6`

	_, err := c.db.Exec(ctx, query,
		user.FirstName,
		user.LastName,
		user.Mail,
		user.Phone,
		time.Now(),
		id,
	)

	if err != nil {
		c.logger.Error("failed to update user in database", logger.Error(err))
		return "", err
	}

	return id, nil
}

func (c *UserRepo) GetByID(ctx context.Context, id string) (models.User, error) {
	var (
		user      models.User
		firstname sql.NullString
		lastname  sql.NullString
		phone     sql.NullString
		mail      sql.NullString
		password  sql.NullString
		sex       sql.NullString
		active    sql.NullBool
		createdat sql.NullString
		updatedat sql.NullString
	)

	query := `SELECT 
		id,
		mail,
		first_name,
		last_name,
		password,
		phone,
		sex,
		active,
		created_at,
		updated_at
	FROM "Users" 
	WHERE id = $1`

	row := c.db.QueryRow(ctx, query, id)

	err := row.Scan(
		&user.ID,
		&mail,
		&firstname,
		&lastname,
		&password,
		&phone,
		&sex,
		&active,
		&createdat,
		&updatedat,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return models.User{}, err
		}
		c.logger.Error("failed to scan user by ID from database", logger.Error(err))
		return models.User{}, err
	}

	user.Mail = mail.String
	user.FirstName = firstname.String
	user.LastName = lastname.String
	user.Password = password.String
	user.Phone = phone.String
	user.Sex = sex.String
	user.Active = active.Bool
	user.CreatedAt = createdat.String
	user.UpdatedAt = updatedat.String

	return user, nil
}

func (c *UserRepo) GetAll(ctx context.Context, req models.GetAllUsersRequest) (models.GetAllUsersResponse, error) {
	var (
		resp      = models.GetAllUsersResponse{}
		filter    string
		firstname sql.NullString
		lastname  sql.NullString
		phone     sql.NullString
		mail      sql.NullString
		password  sql.NullString
		sex       sql.NullString
		active    sql.NullBool
		createdat sql.NullString
		updatedat sql.NullString
		count     sql.NullInt64
	)
	offset := (req.Page - 1) * req.Limit

	if req.Search != "" {
		filter = fmt.Sprintf(` WHERE (first_name ILIKE '%%%v%%' OR last_name ILIKE '%%%v%%')`, req.Search, req.Search)
	} else {
		filter = ""
	}

	filter += fmt.Sprintf(" OFFSET %v LIMIT %v", offset, req.Limit)

	query := `SELECT 
		id,
		mail,
		first_name,
		last_name,
		password,
		phone,
		sex,
		active,
		created_at,
		updated_at
	FROM "Users"` + filter

	rows, err := c.db.Query(ctx, query)
	if err != nil {
		c.logger.Error("failed to get all users from database", logger.Error(err))
		return resp, err
	}
	defer rows.Close()

	for rows.Next() {
		var user models.User

		err := rows.Scan(
			&user.ID,
			&mail,
			&firstname,
			&lastname,
			&password,
			&phone,
			&sex,
			&active,
			&createdat,
			&updatedat,
		)
		if err != nil {
			c.logger.Error("failed to scan users from database", logger.Error(err))
			return models.GetAllUsersResponse{}, err
		}

		user.Mail = mail.String
		user.FirstName = firstname.String
		user.LastName = lastname.String
		user.Password = password.String
		user.Phone = phone.String
		user.Sex = sex.String
		user.Active = active.Bool
		user.CreatedAt = createdat.String
		user.UpdatedAt = updatedat.String

		resp.Users = append(resp.Users, user)
	}

	countQuery := `SELECT COUNT(id) FROM "Users"`
	err = c.db.QueryRow(ctx, countQuery).Scan(&count)
	resp.Count = count.Int64
	if err != nil {
		c.logger.Error("failed to get users count from database", logger.Error(err))
		return models.GetAllUsersResponse{}, err
	}

	return resp, nil
}

func (c *UserRepo) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM "Users" WHERE id = $1`

	_, err := c.db.Exec(ctx, query, id)
	if err != nil {
		c.logger.Error("failed to delete user from database", logger.Error(err))
		return err
	}

	return nil
}

func (c *UserRepo) ChangePassword(ctx context.Context, pass models.ChangePassword) (string, error) {
	var hashedPass string

	query := `SELECT password
	FROM "Users"
	WHERE mail = $1`

	err := c.db.QueryRow(ctx, query,
		pass.Mail,
	).Scan(&hashedPass)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.New("incorrect mail")
		}
		c.logger.Error("failed to get user password from database", logger.Error(err))
		return "", err
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPass), []byte(pass.OldPassword))
	if err != nil {
		return "", errors.New("password mismatch")
	}

	newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(pass.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.logger.Error("failed to generate User new password", logger.Error(err))
		return "", err
	}

	query = `UPDATE "Users" SET 
		password = $1, 
		updated_at = CURRENT_TIMESTAMP 
	WHERE mail = $2`

	_, err = c.db.Exec(ctx, query, newHashedPassword, pass.Mail)
	if err != nil {
		c.logger.Error("failed to change user password in database", logger.Error(err))
		return "", err
	}

	return "Password changed successfully", nil
}

func (c *UserRepo) CheckMailExists(ctx context.Context, mail string) (string, error) {
	var exists string
	query := `SELECT mail FROM "Users" WHERE mail = $1`
	err := c.db.QueryRow(ctx, query, mail).Scan(&exists)
	if err != nil {
		c.logger.Error("failed to check if email exists", logger.Error(err))
		return "", err
	}
	return exists, nil
}

func (c *UserRepo) ForgetPassword(ctx context.Context, forget models.ForgetPassword) (string, error) {

	query := `UPDATE "Users" SET 
		password = $1, 
		updated_at = CURRENT_TIMESTAMP 
	WHERE mail = $2`

	_, err := c.db.Exec(ctx, query, forget.NewPassword, forget.Mail)

	if err != nil {
		c.logger.Error("failed to update user password in database", logger.Error(err))
		return "", err
	}

	return "Password changed successfully", nil
}

func (c *UserRepo) ChangeStatus(ctx context.Context, status models.ChangeStatus) (string, error) {
	query := `UPDATE "Users" SET 
		active = $1, 
		updated_at = CURRENT_TIMESTAMP 
	WHERE id = $2`

	_, err := c.db.Exec(ctx, query, status.Active, status.ID)
	if err != nil {
		c.logger.Error("failed to change user status in database", logger.Error(err))
		return "", err
	}

	return status.ID, nil
}

func (c *UserRepo) LoginByMailAndPassword(ctx context.Context, login models.UserLoginRequest) (string, error) {
	var (
		password string
	)

	query := `SELECT
        password
    FROM "Users" 
    WHERE mail = $1`

	row := c.db.QueryRow(ctx, query, login.Mail)
	err := row.Scan(
		&password,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", err
		}
		c.logger.Error("failed to scan user by email from database", logger.Error(err))
		return "", err
	}

	err = bcrypt.CompareHashAndPassword([]byte(password), []byte(login.Password))
	if err != nil {
		return "", errors.New("password mismatch")
	}

	return login.Mail, nil
}
