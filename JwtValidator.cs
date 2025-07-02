using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

public class JwtValidator
{
    private static readonly ConcurrentDictionary<string, (SecurityKey key, DateTime expiry)> KeyCache = new();

    public static async Task<ClaimsPrincipal?> ValidateTokenAsync(string accessToken)
    {
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(accessToken);
        var jku = jwt.Header["jku"]?.ToString();
        var kid = jwt.Header["kid"]?.ToString();

        if (string.IsNullOrEmpty(jku) || string.IsNullOrEmpty(kid))
            return null;

        var signingKey = await GetSecurityKeyWithCache(jku, kid);
        var issuer = jku.Replace("/token_keys", "/oauth/token");

        var validationParams = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = signingKey,
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = false,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(2)
        };

        return handler.ValidateToken(accessToken, validationParams, out _);
    }

    private static async Task<SecurityKey> GetSecurityKeyWithCache(string jku, string kid)
    {
        if (KeyCache.TryGetValue(kid, out var cached) && cached.expiry > DateTime.UtcNow)
            return cached.key;

        using var client = new HttpClient();
        var jwks = JObject.Parse(await client.GetStringAsync(jku));
        var key = jwks["keys"]?.FirstOrDefault(k => k["kid"]?.ToString() == kid)
            ?? throw new Exception("Key not found");

        var rsa = new RSACryptoServiceProvider();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus = Base64UrlEncoder.DecodeBytes(key["n"]?.ToString()),
            Exponent = Base64UrlEncoder.DecodeBytes(key["e"]?.ToString())
        });

        var securityKey = new RsaSecurityKey(rsa) { KeyId = kid };
        KeyCache[kid] = (securityKey, DateTime.UtcNow.AddMinutes(45));
        return securityKey;
    }
}
