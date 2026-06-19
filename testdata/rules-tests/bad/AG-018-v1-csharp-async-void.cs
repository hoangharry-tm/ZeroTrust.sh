public async void ValidateToken(string token)
{
    var handler = new JwtSecurityTokenHandler();
    var result = await handler.ValidateTokenAsync(token, validationParameters);
    if (result.Identity == null)
        throw new SecurityException("Invalid token");
}
