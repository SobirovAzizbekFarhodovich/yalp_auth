package api

import (
	"log"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
	files "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"auth/api/handler"
	middleware "auth/api/middleware"
	_ "auth/docs"
)

// @title auth service API
// @version 1.0
// @description auth service API
// @BasePath /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func NewGin(h *handler.Handler) *gin.Engine {
	e, err := casbin.NewEnforcer("config/model.conf", "config/policy.csv")
	if err != nil {
		panic(err)
	}

	err = e.LoadPolicy()
	if err != nil {
		log.Fatal("casbin error load policy: ", err)
		panic(err)
	}

	r := gin.Default()

	r.Use(middleware.NewAuth(e))
	auth := r.Group("/auth")
	auth.POST("/register", h.RegisterUser)
	auth.POST("/login", h.LoginUser)

	u := r.Group("/user")
	u.POST("/change-password", h.ChangePassword)
	u.POST("/forgot-password", h.ForgotPassword)
	u.POST("/reset-password", h.ResetPassword)
	u.GET("", h.GetProfil)
	u.PUT("", h.UpdateProfil)
	u.DELETE("", h.DeleteProfil)

	a := r.Group("/admin")
	a.PUT("/:id", h.UpdateUser)
	a.DELETE("/:id", h.DeleteUser)
	a.GET("/:id", h.GetbyIdUser)
	a.GET("/all", h.GetAllUsers)


	url := ginSwagger.URL("/swagger/doc.json")
	r.GET("/swagger/*any", ginSwagger.WrapHandler(files.Handler, url))

	return r
}
