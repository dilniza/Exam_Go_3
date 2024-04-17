package check

import (
	"errors"
	"fmt"
	"regexp"
	"unicode"
)

func ValidateEmail(email string) (bool, error) {
	mail := regexp.MustCompile(`(?i)\w+@\w+(\.[a-z]{2,})+`).MatchString(email) // `\w+\@w\.(com|ru|org|edu)]`
	if !mail {
		fmt.Println(mail)

		err := errors.New("error in validate email")
		return mail, err
	}
	return mail, nil
}

// func ValidatePhone(phone string) bool {
// 	phone = strings.ReplaceAll(phone, " ", "")
// 	phone = strings.ReplaceAll(phone, "-", "")
// 	phone = strings.ReplaceAll(phone, "(", "")
// 	phone = strings.ReplaceAll(phone, ")", "")

// 	if !strings.HasPrefix(phone, "998") {
// 		return false
// 	}

// 	return len(phone) == 12
// }

func ValidatePhone(phone string) (bool, error) {
	ret := regexp.MustCompile(`\+?|\s?998\s?|-?\(?\d{2}\)?\s?|-?\d{3}\s?|-?\d{2}\s?|-?\d{2}`).MatchString(phone)

	if !ret {
		err := errors.New("error in validate phone")
		return false, err
	}

	digitCount := 0
	for _, char := range phone {
		if unicode.IsDigit(char) {
			digitCount++
		}
	}

	if digitCount < 7 {
		err := errors.New("phone number must have at least 7 digits")
		return false, err
	}

	return true, nil
}

func ValidatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	if !regexp.MustCompile(`[a-z]`).MatchString(password) {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !regexp.MustCompile(`[0-9]`).MatchString(password) {
		return errors.New("password must contain at least one digit")
	}
	if !regexp.MustCompile(`[^a-zA-Z0-9\s]`).MatchString(password) {
		return errors.New("password must contain at least one special character")
	}
	return nil
}
