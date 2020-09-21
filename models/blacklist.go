package models

import "time"

//Blacklist helps us blacklist tokens
type Blacklist struct {
	Email     string
	Token     string
	CreatedAt time.Time
}
