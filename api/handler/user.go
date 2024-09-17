package handler

import (
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"time"

	token "auth/api/token"
	"auth/config"
	pb "auth/genprotos"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type changePass struct {
	CurrentPassword string
	NewPassword     string
}

type resetPass struct {
	ResetToken  string
	NewPassword string
}

// RegisterUser handles the creation of a new user
// @Summary Register User
// @Description Register a new user
// @Tags Auth
// @Accept json
// @Produce json
// @Param Create body pb.RegisterUserRequest true "Create"
// @Success 201 {object} string "Create Successfully"
// @Failure 400 {string} string "Error while creating user"
// @Router /auth/register [post]
func (h *Handler) RegisterUser(ctx *gin.Context) {
	user := pb.RegisterUserRequest{}
	err := ctx.BindJSON(&user)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	emailRegex := `^[a-zA-Z0-9._]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(emailRegex)
	if !re.MatchString(user.Email) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	user.Password = string(hashedPassword)

	_, err = h.UserStorage.User().RegisterUser(&user)
	if err != nil {
		if status.Code(err) == codes.AlreadyExists {
			ctx.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
		} else {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		}
		return
	}

	ctx.JSON(http.StatusCreated, gin.H{"message": "User created successfully"})
}

// UpdateUser handles updating an existing user
// @Summary Update User
// @Description Update an existing user
// @Tags Admin
// @Accept json
// @Security BearerAuth
// @Produce json
// @Param Update body pb.UpdateUserRequest true "Update"
// @Success 200 {object} string "Update Successful"
// @Failure 400 {string} string "Error while updating user"
// @Router /admin/{id} [put]
func (h *Handler) UpdateUser(ctx *gin.Context) {
	user := pb.UpdateUserRequest{}
	err := ctx.BindJSON(&user)
	if err != nil {
		ctx.JSON(400, err.Error())
		return
	}

	res, err := h.UserStorage.User().UpdateUser(&user)
	if err != nil {
		ctx.JSON(400, err.Error())
		return
	}

	ctx.JSON(200, res)
}

// DeleteUser handles the deletion of a user
// @Summary Delete User
// @Description Delete an existing user
// @Tags Admin
// @Accept json
// @Security BearerAuth
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} string "Delete Successfully"
// @Failure 400 {string} string "Error while deleting user"
// @Router /admin/{id} [delete]
func (h *Handler) DeleteUser(ctx *gin.Context) {
	id := pb.DeleteUserRequest{Id: ctx.Param("id")}

	_, err := h.UserStorage.User().DeleteUser(&id)
	if err != nil {
		ctx.JSON(400, err.Error())
		return
	}

	ctx.JSON(200, gin.H{"message": "User deleted successfully"})
}

// GetByIdUser handles retrieving a user by ID
// @Summary Get User By ID
// @Description Get a user by ID
// @Tags Admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} pb.GetByIdUserResponse "Get By ID Successful"
// @Failure 400 {string} string "Error while retrieving user"
// @Failure 404 {string} string "User Not Found"
// @Router /admin/{id} [get]
func (h *Handler) GetbyIdUser(ctx *gin.Context) {
	id := pb.GetByIdUserRequest{Id: ctx.Param("id")}

	res, err := h.UserStorage.User().GetByIdUser(&id)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			ctx.JSON(404, "User Not Found")
			return
		}
		ctx.JSON(400, "Error while retrieving user")
		return
	}

	ctx.JSON(200, res)
}

// LoginUser handles user login
// @Summary Login User
// @Description Login a user
// @Tags Auth
// @Accept json
// @Produce json
// @Param Create body pb.LoginUserRequest true "Create"
// @Success 200 {object} string "Login Successfully"
// @Failure 400 {string} string "Error while logging in"
// @Failure 404 {string} string "User Not Found"
// @Router /auth/login [post]
func (h *Handler) LoginUser(ctx *gin.Context) {
	user := pb.LoginUserRequest{}
	err := ctx.ShouldBindJSON(&user)
	if err != nil {
		ctx.JSON(400, err.Error())
		return
	}

	res, err := h.UserStorage.User().LoginUser(&user)
	if err != nil {
		if err.Error() == "invalid email or password" {
			ctx.JSON(404, "User Not Found or Invalid Password")
			return
		}
		ctx.JSON(400, err.Error())
		return
	}

	t := token.GenereteJWTToken(res)
	ctx.JSON(200, t)
}

// ChangePassword handles changing user password
// @Summary Change Password
// @Description Change user password
// @Tags User
// @Accept json
// @Security BearerAuth
// @Produce json
// @Param ChangePass body changePass true "Change Password"
// @Success 200 {body} string "Password Changed Successfully"
// @Failure 400 {string} string "Error while changing password"
// @Router /user/change-password [post]
func (h *Handler) ChangePassword(ctx *gin.Context) {
	changePas := changePass{}
	err := ctx.BindJSON(&changePas)
	if err != nil {
		ctx.JSON(400, err.Error())
		return
	}
	changePass := pb.ChangePasswordRequest{CurrentPassword: changePas.CurrentPassword, NewPassword: changePas.NewPassword}
	cnf := config.Load()
	id, _ := token.GetIdFromToken(ctx.Request, &cnf)
	changePass.Id = id

	_, err = h.UserStorage.User().ChangePassword(&changePass)
	if err != nil {
		ctx.JSON(400, err.Error())
		return
	}

	ctx.JSON(200, gin.H{"message": "Password Changed Successfully"})
}

// ForgotPassword handles initiating the forgot password process
// @Summary Forgot Password
// @Description Initiate forgot password process
// @Tags User
// @Accept json
// @Security BearerAuth
// @Produce json
// @Success 200 {body} string "Forgot Password Initiated Successfully"
// @Failure 400 {string} string "Error while initiating forgot password"
// @Router /user/forgot-password [post]
func (h *Handler) ForgotPassword(ctx *gin.Context) {
	cnf := config.Load()

	email, _ := token.GetEmailFromToken(ctx.Request, &cnf)
	if !isValidEmail(email) {
		ctx.JSON(400, gin.H{"error": "Noto'g'ri email manzili"})
		return
	}

	f := rand.Intn(899999) + 100000

	err := h.redis.SaveToken(email, fmt.Sprintf("%d", f), time.Minute*2)
	if err != nil {
		ctx.JSON(400, gin.H{"error": "Tokenni saqlashda xatolik"})
		return
	}

	ctx.JSON(200, gin.H{"message": "Email orqali xabar yuborildi"})
}

func isValidEmail(email string) bool {
	regex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(regex)
	return re.MatchString(email)
}

// ResetPassword handles resetting the user password
// @Summary Reset Password
// @Description Reset user password
// @Tags User
// @Accept json
// @Security BearerAuth
// @Produce json
// @Param ResetPass body resetPass true "Reset Password"
// @Success 200 {string} string "Password Reset Successfully"
// @Failure 400 {string} string "Error while resetting password"
// @Router /user/reset-password [post]
func (h *Handler) ResetPassword(ctx *gin.Context) {
	resetPas := resetPass{}
	err := ctx.BindJSON(&resetPas)
	if err != nil {
		ctx.JSON(400, err.Error())
		return
	}
	resetPass := pb.ResetPasswordRequest{ResetToken: resetPas.ResetToken, Password: resetPas.NewPassword}
	cnf := config.Load()
	id, _ := token.GetIdFromToken(ctx.Request, &cnf)
	resetPass.Id = id

	email, _ := token.GetEmailFromToken(ctx.Request, &cnf)
	e, err := h.redis.Get(email)
	if err != nil {
		ctx.JSON(400, err.Error())
		return
	}

	if e != resetPass.ResetToken {
		ctx.JSON(400, "Invalid reset-password")
		return
	}

	_, err = h.UserStorage.User().ResetPassword(&resetPass)
	if err != nil {
		ctx.JSON(400, err.Error())
		return
	}

	ctx.JSON(200, "Password Reset Successfully")
}

// GetProfil handles retrieving a user Profil
// @Summary Get User Profile
// @Description Get a user Profil
// @Tags User
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} pb.GetByIdUserResponse "Get Profil Successful"
// @Failure 400 {string} string "Error while retrieving user"
// @Router /user [get]
func (h *Handler) GetProfil(ctx *gin.Context) {
	cnf := config.Load()
	id, _ := token.GetIdFromToken(ctx.Request, &cnf)

	res, err := h.UserStorage.User().GetByIdUser(&pb.GetByIdUserRequest{Id: id})
	if err != nil {
		ctx.JSON(400, err.Error())
		return
	}

	ctx.JSON(200, res)
}

// UpdateProfil handles updating an existing user
// @Summary Update Profile
// @Description Update an existing user
// @Tags User
// @Accept json
// @Security BearerAuth
// @Produce json
// @Param Update body pb.UpdateUserForUser true "Update"
// @Success 200 {object} pb.UpdateUserResponse "Update Successful"
// @Failure 400 {string} string "Error while updating user"
// @Router /user [put]
func (h *Handler) UpdateProfil(ctx *gin.Context) {
	updateUserRequest := pb.UpdateUserForUser{}
	err := ctx.BindJSON(&updateUserRequest)
	if err != nil {
		ctx.JSON(400, err.Error())
		return
	}

	cnf := config.Load()
	userId, _ := token.GetIdFromToken(ctx.Request, &cnf)

	updateRequest := pb.UpdateUserRequest{
		Id:             userId,
		FullName:       updateUserRequest.FullName,
		ProfilePicture: updateUserRequest.ProfilePicture,
		Bio:            updateUserRequest.Bio,
	}

	res, err := h.UserStorage.User().UpdateUser(&updateRequest)
	if err != nil {
		ctx.JSON(400, err.Error())
		return
	}
	ctx.JSON(200, res)
}

// DeleteProfil handles the deletion of a Profil
// @Summary Delete Profile
// @Description Delete an existing Profil
// @Tags User
// @Accept json
// @Security BearerAuth
// @Produce json
// @Success 200 {string} string "Delete Successful"
// @Failure 400 {string} string "Error while deleting user"
// @Router /user [delete]
func (h *Handler) DeleteProfil(ctx *gin.Context) {
	cnf := config.Load()
	id, _ := token.GetIdFromToken(ctx.Request, &cnf)

	_, err := h.UserStorage.User().DeleteUser(&pb.DeleteUserRequest{Id: id})
	if err != nil {
		ctx.JSON(400, err.Error())
		return
	}

	ctx.JSON(200, "User deleted successfully")
}

// GetAllUsers handles the retrieval of all users
// @Summary Get All Users
// @Description Retrieve a list of all users with pagination
// @Tags Admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param limit query int false "Limit" default(10)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} pb.GetAllUsersResponse "List of Users"
// @Failure 400 {string} string "Error while retrieving users"
// @Router /admin/all [get]
func (h *Handler) GetAllUsers(ctx *gin.Context) {
	limit := ctx.DefaultQuery("limit", "10")
	offset := ctx.DefaultQuery("offset", "0")

	limitInt, err := strconv.Atoi(limit)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, "Invalid limit parameter")
		return
	}

	offsetInt, err := strconv.Atoi(offset)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, "Invalid offset parameter")
		return
	}

	req := &pb.GetAllUsersRequest{
		Limit:  int32(limitInt),
		Offset: int32(offsetInt),
	}

	res, err := h.UserStorage.User().GetAllUsers(req)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	ctx.JSON(http.StatusOK, res)
}
