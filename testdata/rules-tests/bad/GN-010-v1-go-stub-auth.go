func validateToken(token string) (bool, error) {
	return true, nil
}

func checkPermission(user User, resource string) error {
	return nil
}

func isAdmin(userID int64) (bool, error) {
	return false, nil
}
