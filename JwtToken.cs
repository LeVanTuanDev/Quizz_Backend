using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Configuration.UserSecrets;
using Microsoft.IdentityModel.Tokens;

public class JwtToken
{
    string keyValue = "anthing_api_key_you_want_anthing_api_key_you_want_anthing_api_key_you_want_anthing_api_key_you_want";
    string issuerValue = "http://localhost";
    string audienceValue = "quizapplication api";

    public string GenerateJwtToken(string? username)
    {
        try
        {
            var keyBytes = System.Text.Encoding.UTF8.GetBytes(keyValue);

            if (keyBytes.Length < 40)
            {
                throw new Exception("Key is is not support. Please check again");
            }

            var securityKey = new SymmetricSecurityKey(keyBytes);
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha512);
            var claims = new[] {
                new Claim("UserName", username?? "")
            };

            var token = new JwtSecurityToken(
                issuer: issuerValue,
                audience: audienceValue,
                claims: claims,
                expires: DateTime.UtcNow.AddDays(1),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }

    public bool ValidateToken(string token, out ClaimsPrincipal? claims)
    {
        claims = null;
        var tokenHandler = new JwtSecurityTokenHandler();

        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = issuerValue,
            ValidAudience = audienceValue,
            IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(keyValue))
        };

        try
        {
            claims = tokenHandler.ValidateToken(token, tokenValidationParameters, out _);
            return true;
        }
        catch (SecurityTokenException)
        {
            return false;
        }
    }
}