func validateToken(token string) (bool, error) {
	claims, err := jwt.Parse(token, keyFunc)
	if err != nil {
		return false, err
	}
	return claims.Valid(), nil
}

func checkPermission(user User, resource string) error {
	if !user.HasRole(resource) {
		return ErrForbidden
	}
	return nil
}
