package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/spankie/go-auth/db"
	"github.com/spankie/go-auth/models"
	"github.com/spankie/go-auth/router"
	"github.com/stretchr/testify/assert"
)

func TestSignupWithCorrectDetails(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := db.NewMockDB(ctrl)

	s := &Server{
		DB:     m,
		Router: router.NewRouter(),
	}
	router := s.setupRouter()

	user := models.User{
		FirstName:      "Spankie",
		LastName:       "Dee",
		PasswordString: "password",
		Username:       "spankie",
		Email:          "spankie_signup@gmail.com",
		Phone:          "08909876787",
	}

	m.EXPECT().CreateUser(gomock.Any()).Return(&user, nil)

	jsonuser, err := json.Marshal(user)
	if err != nil {
		t.Fail()
		return
	}
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/auth/signup", strings.NewReader(string(jsonuser)))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), "signup successful")
}

func TestSignupWithInCorrectDetails(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := db.NewMockDB(ctrl)

	s := &Server{
		DB:     m,
		Router: router.NewRouter(),
	}
	router := s.setupRouter()

	user := models.User{
		FirstName:      "Spankie",
		LastName:       "Dee",
		PasswordString: "password",
		// Username:       "spankie",
		Email: "spankie_signup",
		Phone: "08909876787",
	}

	jsonuser, err := json.Marshal(user)
	if err != nil {
		t.Fail()
		return
	}
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/auth/signup", strings.NewReader(string(jsonuser)))
	router.ServeHTTP(w, req)

	bodyString := w.Body.String()
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, bodyString, fmt.Sprintf("validation failed on field 'Email', condition: email, actual: %s", user.Email))
	assert.Contains(t, bodyString, "validation failed on field 'Username', condition: required")
}
