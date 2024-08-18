using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
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

                Console.WriteLine("Fetched Signing key From Identity Server: " + JsonSerializer.Serialize(signingKey));

                var rsa = RSA.Create();
                rsa.ImportParameters(
                    new RSAParameters
                    {
                        Modulus = Base64UrlEncoder.DecodeBytes(signingKey.N),
                        Exponent = Base64UrlEncoder.DecodeBytes(signingKey.E)
                    }
                );

                return [new RsaSecurityKey(rsa)];
            },
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidIssuer = "http://localhost:5111", // Replace with the actual Identity App URL
            ValidAudience = "http://localhost:5222" // Replace with the actual Service App URL
        };
    });

var app = builder.Build();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.MapGet("/protected", [Authorize] () =>
{
    return "This is a protected resource";
});

app.Run();
