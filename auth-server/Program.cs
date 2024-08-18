using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = "https://localhost:5111"; // Replace with the actual Identity App URL
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKeyResolver = (token, securityToken, kid, validationParameters) =>
            {
                var client = new HttpClient();
                var jwksUri = new Uri($"{options.Authority}/.well-known/jwks");
                var response = client.GetAsync(jwksUri).Result;
                response.EnsureSuccessStatusCode();

                var jwks = JsonSerializer.Deserialize<JsonWebKeySet>(response.Content.ReadAsStringAsync().Result);
                var signingKey = jwks.Keys.FirstOrDefault(key => key.Kid == kid);
                if (signingKey == null)
                {
                    throw new SecurityTokenException("Invalid signing key");
                }

                var rsa = RSA.Create();
                rsa.ImportParameters(
                    new RSAParameters
                    {
                        Modulus = Base64UrlEncoder.DecodeBytes(signingKey.N),
                        Exponent = Base64UrlEncoder.DecodeBytes(signingKey.E)
                    }
                );

                return new[] { new RsaSecurityKey(rsa) };
            },
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidIssuer = "https://localhost:5111", // Replace with the actual Identity App URL
            ValidAudience = "https://localhost:5222" // Replace with the actual Service App URL
        };
    });

var app = builder.Build();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

// Private RSA key
var rsa = RSA.Create();
// Load your private key here (from a file, certificate, etc.)

app.MapGet("/.well-known/jwks", () =>
{
    var parameters = rsa.ExportParameters(false);

    var jwk = new JsonWebKey
    {
        Kty = "RSA",
        Use = "sig",
        Kid = Guid.NewGuid().ToString(),
        E = Base64UrlEncoder.Encode(parameters.Exponent),
        N = Base64UrlEncoder.Encode(parameters.Modulus)
    };

    var jwks = new JsonWebKeySet();
    jwks.Keys.Add(jwk); // Add the JWK to the Keys collection

    return jwks;
});

app.MapPost("/token", () =>
{
    var claims = new[]
    {
        new Claim(JwtRegisteredClaimNames.Sub, "user1"),
        new Claim(JwtRegisteredClaimNames.Name, "User One")
    };

    var credentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);
    var token = new JwtSecurityToken(
        issuer: "http://localhost:5111", // Replace with the actual Identity App URL
        audience: "http://localhost:5222", // Replace with the actual Service App URL
        claims: claims,
        expires: DateTime.Now.AddMinutes(30),
        signingCredentials: credentials
    );

    var tokenHandler = new JwtSecurityTokenHandler();
    return tokenHandler.WriteToken(token);
});

app.Run();
