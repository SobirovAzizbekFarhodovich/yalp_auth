package postgres

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	pb "auth/genprotos"

	"golang.org/x/crypto/bcrypt"
)

type UserStorage struct {
	db *sql.DB
}

func NewUserStorage(db *sql.DB) *UserStorage {
	return &UserStorage{db: db}
}

const emailRegex = `^[a-zA-Z0-9._]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`

func isValidEmail(email string) bool {
	re := regexp.MustCompile(emailRegex)
	return re.MatchString(email)
}
func (u *UserStorage) RegisterUser(user *pb.RegisterUserRequest) (*pb.RegisterUserResponse, error) {
    if !isValidEmail(user.Email) {
        return nil, errors.New("invalid email format")
    }

    var exists bool
    queryCheck := `SELECT EXISTS (SELECT 1 FROM users WHERE email=$1)`
    err := u.db.QueryRow(queryCheck, user.Email).Scan(&exists)
    if err != nil {
        return nil, err
    }

    if exists {
        return nil, errors.New("email already registered")
    }

    query := `INSERT INTO users (email, password, full_name, profile_picture, bio) VALUES ($1, $2, $3, $4, $5)`
    _, err = u.db.Exec(query, user.Email, user.Password, user.FullName, user.ProfilePicture, user.Bio)
    if err != nil {
        return nil, err
    }

    return &pb.RegisterUserResponse{}, nil
}


func (u *UserStorage) LoginUser(user *pb.LoginUserRequest) (*pb.LoginUserResponse, error) {
	query := `
	SELECT id, email, password, full_name, role FROM users WHERE email = $1 AND deleted_at = 0
	`
	row := u.db.QueryRow(query, user.Email)
	res := pb.LoginUserResponse{}
	err := row.Scan(
		&res.Id,
		&res.Email,
		&res.Password,
		&res.FullName,
		&res.Role,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invalid email or password")
		}
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(res.Password), []byte(user.Password))
	if err != nil {
		return nil, fmt.Errorf("invalid email or password")
	}
	return &res, nil
}

func (u *UserStorage) GetByIdUser(id *pb.GetByIdUserRequest) (*pb.GetByIdUserResponse, error) {
	query := `
		SELECT id, email, full_name, profile_picture, bio FROM users 
		WHERE id = $1 AND deleted_at = 0
	`
	row := u.db.QueryRow(query, id.Id)

	user := pb.GetByIdUserResponse{}
	err := row.Scan(
		&user.Id,
		&user.Email,
		&user.FullName,
		&user.ProfilePicture,
		&user.Bio,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return &user, nil
}

func (u *UserStorage) UpdateUser(req *pb.UpdateUserRequest) (*pb.UpdateUserResponse, error) {
	query := `UPDATE users SET `
	var condition []string
	var args []interface{}

	if req.Email != "" && req.Email != "string" {
		condition = append(condition, fmt.Sprintf("email = $%d", len(args)+1))
		args = append(args, req.Email)
	}
	if req.FullName != "" && req.FullName != "string" {
		condition = append(condition, fmt.Sprintf("full_name = $%d", len(args)+1))
		args = append(args, req.FullName)
	}

	if req.ProfilePicture != "" && req.ProfilePicture != "string" {
		condition = append(condition, fmt.Sprintf("profile_picture = $%d", len(args)+1))
		args = append(args, req.ProfilePicture)
	}
	if req.Bio != "" && req.Bio != "string" {
		condition = append(condition, fmt.Sprintf("bio = $%d", len(args)+1))
		args = append(args, req.Bio)
	}

	if len(condition) == 0 {
		return nil, errors.New("nothing to update")
	}

	query += strings.Join(condition, ", ")
	query += fmt.Sprintf(" WHERE id = $%d RETURNING id, email, full_name, profile_picture, bio", len(args)+1)
	args = append(args, req.Id)

	res := pb.UpdateUserResponse{}
	row := u.db.QueryRow(query, args...)

	err := row.Scan(&res.Id, &res.Email, &res.FullName, &res.ProfilePicture, &res.Bio)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (u *UserStorage) DeleteUser(id *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error) {
	query := `
		UPDATE users
		SET deleted_at = $2
		WHERE id = $1 AND deleted_at = 0
	`
	_, err := u.db.Exec(query, id.Id, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	return &pb.DeleteUserResponse{}, nil
}

func (u *UserStorage) ChangePassword(password *pb.ChangePasswordRequest) (*pb.ChangePasswordResponse, error) {
	var currentHashedPassword string
	query := `
		SELECT password
		FROM users
		WHERE id = $1 AND deleted_at = 0
	`
	err := u.db.QueryRow(query, password.Id).Scan(&currentHashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(currentHashedPassword), []byte(password.CurrentPassword))
	if err != nil {
		return nil, fmt.Errorf("invalid current password")
	}

	hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(password.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash new password")
	}

	updateQuery := `
		UPDATE users
		SET password = $2
		WHERE id = $1 AND deleted_at = 0
	`
	_, err = u.db.Exec(updateQuery, password.Id, hashedNewPassword)
	if err != nil {
		return nil, err
	}

	return &pb.ChangePasswordResponse{}, nil
}

func (p *UserStorage) ForgotPassword(forgotPass *pb.ForgotPasswordRequest) (*pb.ForgotPasswordResponse, error) {
	return &pb.ForgotPasswordResponse{}, nil
}

func (s *UserStorage) GetUserByEmail(email string) (*pb.UpdateUserResponse, error) {
	var user pb.UpdateUserResponse
	query := "SELECT id, email, full_name, profile_picture, bio FROM users WHERE email = $1 AND deleted_at = 0"
	row := s.db.QueryRow(query, email)
	err := row.Scan(&user.Id, &user.Email, &user.FullName, &user.ProfilePicture, &user.Bio)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (p *UserStorage) ResetPassword(resetPass *pb.ResetPasswordRequest) (*pb.ResetPasswordResponse, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(resetPass.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	query := `
		UPDATE users
		SET password = $2
		WHERE id = $1 AND deleted_at = 0
	`
	_, err = p.db.Exec(query, resetPass.Id, string(hashedPassword))
	if err != nil {
		return nil, err
	}

	return &pb.ResetPasswordResponse{}, nil
}

func (p *UserStorage) GetAllUsers(req *pb.GetAllUsersRequest) (*pb.GetAllUsersResponse, error) {
	query := `
		SELECT id, email, full_name, profile_picture, bio, role 
		FROM users 
		WHERE deleted_at IS NULL 
		LIMIT $1 OFFSET $2
	`
	
	rows, err := p.db.Query(query, req.Limit, req.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var users []*pb.GetByIdUserResponse
	
	for rows.Next() {
		var user pb.GetByIdUserResponse
		err := rows.Scan(
			&user.Id,
			&user.Email,
			&user.FullName,
			&user.ProfilePicture,
			&user.Bio,
			&user.Role,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, &user)
	}
	
	if err := rows.Err(); err != nil {
		return nil, err
	}
		return &pb.GetAllUsersResponse{
		Users: users,
	}, nil
}
