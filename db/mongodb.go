package db

import (
	"time"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/pkg/errors"
	"github.com/spankie/go-auth/models"
	"github.com/spankie/go-auth/servererrors"
)

// MongoDB implements the DB interface
type MongoDB struct {
	DB *mgo.Database
}

// Init sets up the mongodb instance
func (mdb *MongoDB) Init() {
	dburl := "mongodb://localhost:27017/go-auth"
	dbname := "go-auth"
	DBSession, err := mgo.Dial(dburl)
	if err != nil {
		panic(errors.Wrap(err, "Unable to connect to Mongo database"))
	}
	mdb.DB = DBSession.DB(dbname)
}

// CreateUser creates a new user in the DB
func (mdb *MongoDB) CreateUser(user *models.User) (*models.User, error) {
	_, err := mdb.FindUserByEmail(user.Email)
	if err == nil {
		return user, ValidationError{Field: "email", Message: "already in use"}
	}
	_, err = mdb.FindUserByUsername(user.Username)
	if err == nil {
		return user, ValidationError{Field: "username", Message: "already in use"}
	}
	_, err = mdb.FindUserByPhone(user.Phone)
	if err == nil {
		return user, ValidationError{Field: "phone", Message: "already in use"}
	}
	user.CreatedAt = time.Now()
	err = mdb.DB.C("user").Insert(user)
	return user, err
}

// FindUserByUsername finds a user by the username
func (mdb *MongoDB) FindUserByUsername(username string) (*models.User, error) {
	user := &models.User{}
	err := mdb.DB.C("user").Find(bson.M{"username": username}).One(user)
	if user.Status != "active" {
		return nil, servererrors.NewInActiveUserError("user is inactive")
	}
	return user, err
}

// FindUserByEmail finds a user by email
func (mdb *MongoDB) FindUserByEmail(email string) (*models.User, error) {
	user := &models.User{}
	err := mdb.DB.C("user").Find(bson.M{"email": email}).One(user)
	if user.Status != "active" {
		return nil, servererrors.NewInActiveUserError("user is inactive")
	}
	return user, err
}

// FindUserByPhone finds a user by the phone
func (mdb MongoDB) FindUserByPhone(phone string) (*models.User, error) {
	user := &models.User{}
	err := mdb.DB.C("user").Find(bson.M{"phone": phone}).One(user)
	return user, err
}

// UpdateUser updates user in the collection
func (mdb *MongoDB) UpdateUser(user *models.User) error {
	return mdb.DB.C("user").Update(bson.M{"email": user.Email}, user)
}

// AddToBlackList puts blacklist into the blacklist collection
func (mdb *MongoDB) AddToBlackList(blacklist *models.Blacklist) error {
	return mdb.DB.C("blacklist").Insert(blacklist)
}

// TokenInBlacklist checks if token is already in the blacklist collection
func (mdb *MongoDB) TokenInBlacklist(token *string) bool {
	blacklist := &struct {
		Token string //we could remove this though....
	}{} //Did this so as to allow middleware Authorize use this
	if err := mdb.DB.C("blacklist").Find(bson.M{"token": *token}).One(blacklist); err != nil {
		return false
	}
	return true
}

// FindAllUsersExcept returns all the users expcept the one specified in the except parameter
func (mdb *MongoDB) FindAllUsersExcept(except string) ([]models.User, error) {
	var users []models.User
	err := mdb.DB.C("user").Find(bson.M{"email": bson.M{"$ne": except}}).All(&users)
	return users, err
}
