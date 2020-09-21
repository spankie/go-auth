package server

import (
	"bytes"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/globalsign/mgo/bson"
	"github.com/spankie/go-auth/db"
	"github.com/spankie/go-auth/models"
	"github.com/spankie/go-auth/server/response"
	"github.com/spankie/go-auth/servererrors"
	"github.com/spankie/go-auth/services"
	"golang.org/x/crypto/bcrypt"
)

func (s *Server) handleSignup() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := &models.User{Status: "active"}

		if errs := s.decode(c, user); errs != nil {
			response.JSON(c, "", http.StatusBadRequest, nil, errs)
			return
		}
		var err error
		user.Password, err = bcrypt.GenerateFromPassword([]byte(user.PasswordString), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("hash password err: %v\n", err)
			response.JSON(c, "", http.StatusInternalServerError, nil, []string{"internal server error"})
			return
		}
		user, err = s.DB.CreateUser(user)
		if err != nil {
			log.Printf("create user err: %v\n", err)
			if err, ok := err.(db.ValidationError); ok {
				response.JSON(c, "", http.StatusBadRequest, nil, []string{err.Error()})
				return
			}
			response.JSON(c, "", http.StatusInternalServerError, nil, []string{"internal server error"})
			return
		}
		response.JSON(c, "signup successful", http.StatusCreated, nil, nil)
	}
}

func (s *Server) handleLogin() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := &models.User{}
		loginRequest := &struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
		}{}

		if errs := s.decode(c, loginRequest); errs != nil {
			response.JSON(c, "", http.StatusBadRequest, nil, errs)
			return
		}
		// Check if the user with that username exists
		user, err := s.DB.FindUserByUsername(loginRequest.Username)
		if err != nil {
			if inactiveErr, ok := err.(servererrors.InActiveUserError); ok {
				response.JSON(c, "", http.StatusBadRequest, nil, []string{inactiveErr.Error()})
				return
			}
			log.Printf("No user: %v\n", err)
			response.JSON(c, "", http.StatusUnauthorized, nil, []string{"user not found"})
			return
		}
		log.Printf("%v\n%s\n", user.Password, string(user.Password))
		err = bcrypt.CompareHashAndPassword(user.Password, []byte(loginRequest.Password))
		if err != nil {
			log.Printf("passwords do not match %v\n", err)
			response.JSON(c, "", http.StatusUnauthorized, nil, []string{"username or password incorrect"})
			return
		}

		accessClaims := jwt.MapClaims{
			"user_email": user.Email,
			"exp":        time.Now().Add(services.AccessTokenValidity).Unix(),
		}
		refreshClaims := jwt.MapClaims{
			"exp": time.Now().Add(services.RefreshTokenValidity).Unix(),
			"sub": 1,
		}

		secret := os.Getenv("JWT_SECRET")
		accToken, err := services.GenerateToken(jwt.SigningMethodHS256, accessClaims, &secret)
		if err != nil {
			log.Printf("token generation error err: %v\n", err)
			response.JSON(c, "", http.StatusInternalServerError, nil, []string{"internal server error"})
			return
		}

		refreshToken, err := services.GenerateToken(jwt.SigningMethodHS256, refreshClaims, &secret)
		if err != nil {
			log.Printf("token generation error err: %v\n", err)
			response.JSON(c, "", http.StatusInternalServerError, nil, []string{"internal server error"})
			return
		}

		response.JSON(c, "login successful", http.StatusOK, gin.H{
			"user":          user,
			"access_token":  *accToken,
			"refresh_token": *refreshToken,
		}, nil)
	}
}

func (s *Server) handleLogout() gin.HandlerFunc {
	return func(c *gin.Context) {

		if tokenI, exists := c.Get("access_token"); exists {
			if userI, exists := c.Get("user"); exists {
				if user, ok := userI.(*models.User); ok {
					if accessToken, ok := tokenI.(string); ok {

						rt := &struct {
							RefreshToken string `json:"refresh_token,omitempty" binding:"required"`
						}{}

						if err := c.ShouldBindJSON(rt); err != nil {
							log.Printf("no refresh token in request body: %v\n", err)
							response.JSON(c, "", http.StatusBadRequest, nil, []string{"unauthorized"})
							return
						}

						accBlacklist := &models.Blacklist{
							Email:     user.Email,
							CreatedAt: time.Now(),
							Token:     accessToken,
						}

						err := s.DB.AddToBlackList(accBlacklist)
						if err != nil {
							log.Printf("can't add access token to blacklist: %v\n", err)
							response.JSON(c, "logout failed", http.StatusInternalServerError, nil, []string{"couldn't revoke access token"})
							return
						}

						refreshBlacklist := &models.Blacklist{
							Email:     user.Email,
							CreatedAt: time.Now(),
							Token:     rt.RefreshToken,
						}

						err = s.DB.AddToBlackList(refreshBlacklist)
						if err != nil {
							log.Printf("can't add refresh token to blacklist: %v\n", err)
							response.JSON(c, "logout failed", http.StatusInternalServerError, nil, []string{"couldn't revoke refresh token"})
							return
						}
						response.JSON(c, "logout successful", http.StatusOK, nil, nil)
						return
					}
				}
			}
		}
		log.Printf("can't get info from context\n")
		response.JSON(c, "", http.StatusInternalServerError, nil, []string{"internal server error"})
		return
	}
}

// handleShowProfile returns user's details
func (s *Server) handleShowProfile() gin.HandlerFunc {
	return func(c *gin.Context) {
		if userI, exists := c.Get("user"); exists {
			if user, ok := userI.(*models.User); ok {
				response.JSON(c, "user details retrieved correctly", http.StatusOK, gin.H{
					"email":      user.Email,
					"phone":      user.Phone,
					"first_name": user.FirstName,
					"last_name":  user.LastName,
					"image":      user.Image,
					"username":   user.Username,
				}, nil)
				return
			}
		}
		log.Printf("can't get user from context\n")
		response.JSON(c, "", http.StatusInternalServerError, nil, []string{"internal server error"})
	}
}

func (s *Server) handleUpdateUserDetails() gin.HandlerFunc {
	return func(c *gin.Context) {
		if userI, exists := c.Get("user"); exists {
			if user, ok := userI.(*models.User); ok {

				username, email := user.Username, user.Email
				if errs := s.decode(c, user); errs != nil {
					response.JSON(c, "", http.StatusBadRequest, nil, errs)
					return
				}

				//TODO try to eliminate this
				user.Username, user.Email = username, email
				user.UpdatedAt = time.Now()
				if err := s.DB.UpdateUser(user); err != nil {
					log.Printf("update user error : %v\n", err)
					response.JSON(c, "", http.StatusInternalServerError, nil, []string{"internal server error"})
					return
				}
				response.JSON(c, "user updated successfuly", http.StatusOK, nil, nil)
				return
			}
		}
		log.Printf("can't get user from context\n")
		response.JSON(c, "", http.StatusInternalServerError, nil, []string{"internal server error"})
	}
}

func (s *Server) handleGetUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		if userI, exists := c.Get("user"); exists {
			if user, ok := userI.(*models.User); ok {
				users, err := s.DB.FindAllUsersExcept(user.Email)
				if err != nil {
					log.Printf("find users error : %v\n", err)
					response.JSON(c, "", http.StatusInternalServerError, nil, []string{"internal server error"})
					return
				}
				response.JSON(c, "retrieved users sucessfully", http.StatusOK, gin.H{"users": users}, nil)
				return
			}
		}
		log.Printf("can't get user from context\n")
		response.JSON(c, "", http.StatusInternalServerError, nil, []string{"internal server error"})
		return
	}
}

func (s *Server) handleGetUserByUsername() gin.HandlerFunc {
	return func(c *gin.Context) {
		name := &struct {
			Username string `json:"username" binding:"required"`
		}{}

		if errs := s.decode(c, name); errs != nil {
			response.JSON(c, "", http.StatusBadRequest, nil, errs)
			return
		}

		user, err := s.DB.FindUserByUsername(name.Username)
		if err != nil {
			if inactiveErr, ok := err.(servererrors.InActiveUserError); ok {
				response.JSON(c, "", http.StatusBadRequest, nil, []string{inactiveErr.Error()})
				return
			}
			log.Printf("find user error : %v\n", err)
			response.JSON(c, "user not found", http.StatusNotFound, nil, []string{"user not found"})
			return
		}

		response.JSON(c, "user retrieved successfully", http.StatusOK, gin.H{
			"email":      user.Email,
			"phone":      user.Phone,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
			"image":      user.Image,
			"username":   user.Username,
		}, nil)
	}
}

// handleUploadProfilePic uploads a user's profile picture
func (s *Server) handleUploadProfilePic() gin.HandlerFunc {
	return func(c *gin.Context) {

		if userI, exists := c.Get("user"); exists {
			if user, ok := userI.(*models.User); ok {

				const maxSize = int64(2048000) // allow only 2MB of file size

				r := c.Request
				err := r.ParseMultipartForm(maxSize)
				if err != nil {
					log.Printf("parse image error: %v\n", err)
					response.JSON(c, "", http.StatusBadRequest, nil, []string{"image too large"})
					return
				}

				file, fileHeader, err := r.FormFile("profile_picture")
				if err != nil {
					log.Println(err)
					response.JSON(c, "", http.StatusBadRequest, nil, []string{"image not supplied"})
					return
				}
				defer file.Close()

				supportedFileTypes := map[string]bool{
					".png":  true,
					".jpeg": true,
					".jpg":  true,
				}
				fileExtension := filepath.Ext(fileHeader.Filename)
				if !supportedFileTypes[fileExtension] {
					log.Println(fileExtension)
					response.JSON(c, "", http.StatusBadRequest, nil, []string{fileExtension + " image file type is not supported"})
					return
				}
				tempFileName := "profile_pics/" + bson.NewObjectId().Hex() + fileExtension

				session, err := session.NewSession(&aws.Config{
					Region: aws.String(os.Getenv("AWS_REGION")),
					Credentials: credentials.NewStaticCredentials(
						os.Getenv("AWS_SECRET_ID"),
						os.Getenv("AWS_SECRET_KEY"),
						os.Getenv("AWS_TOKEN"),
					),
				})
				if err != nil {
					log.Printf("could not upload file: %v\n", err)
				}

				err = uploadFileToS3(session, file, tempFileName, fileHeader.Size)
				if err != nil {
					log.Println(err)
					response.JSON(c, "", http.StatusInternalServerError, nil, []string{"an error occured while uploading the image"})
					return
				}

				user.Image = os.Getenv("S3_BUCKET") + tempFileName
				if err = s.DB.UpdateUser(user); err != nil {
					log.Println(err)
					response.JSON(c, "", http.StatusInternalServerError, nil, []string{"unable to update user's profile pic"})
					return
				}

				response.JSON(c, "successfully created file", http.StatusOK, gin.H{
					"imageurl": user.Image,
				}, nil)
				return
			}
		}
		response.JSON(c, "", http.StatusUnauthorized, nil, []string{"unable to retrieve authenticated user"})
		return
	}
}

func uploadFileToS3(s *session.Session, file multipart.File, fileName string, size int64) error {
	// get the file size and read
	// the file content into a buffer
	buffer := make([]byte, size)
	file.Read(buffer)

	// config settings: this is where you choose the bucket,
	// filename, content-type and storage class of the file
	// you're uploading
	_, err := s3.New(s).PutObject(&s3.PutObjectInput{
		Bucket:               aws.String(os.Getenv("S3_BUCKET_NAME")),
		Key:                  aws.String(fileName),
		ACL:                  aws.String("public-read"),
		Body:                 bytes.NewReader(buffer),
		ContentLength:        aws.Int64(int64(size)),
		ContentType:          aws.String(http.DetectContentType(buffer)),
		ContentDisposition:   aws.String("attachment"),
		ServerSideEncryption: aws.String("AES256"),
		StorageClass:         aws.String("INTELLIGENT_TIERING"),
	})
	return err
}
