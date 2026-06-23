public async Task<bool> ValidateToken(string token)
{
    var handler = new JwtSecurityTokenHandler();
    var result = await handler.ValidateTokenAsync(token, validationParameters);
    return result.Identity != null;
}
