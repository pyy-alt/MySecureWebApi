using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using System.Linq; // 确保有这个 using

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

// 强制设置控制台日志的最低级别为 Debug
builder.Logging.ClearProviders();
builder.Logging.AddConsole(options => options.LogToStandardErrorThreshold = LogLevel.Debug);
builder.Logging.SetMinimumLevel(LogLevel.Debug);

builder.Services.AddCors(options =>
{
    options.AddPolicy(name: "MyAllowSpecificOrigins",
        builder =>
        {
            builder.WithOrigins("http://localhost:8080")
                .AllowAnyHeader()
                .AllowAnyMethod();
        });
});

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// ****** 添加 JWT Bearer 认证配置 ******
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = "http://localhost:5233/";
        options.RequireHttpsMetadata = false;
        options.Audience = "api1";

        // *** 禁用默认的 Claims 映射 ***
        options.MapInboundClaims = false;

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = true,
            ValidAudience = "api1",
            ValidateIssuer = true,
            ValidIssuer = "http://localhost:5233/",
            ValidateLifetime = true,  // 确保这里是 true
            ClockSkew = TimeSpan.Zero, // 严格校验令牌过期时间

            // ****** 临时添加：自定义令牌生命周期验证 ******
            // 这会强制 Access Token 在签发后 X 秒内过期
            LifetimeValidator = (notBefore, expires, securityToken, validationParameters) =>
            {
                // 定义一个短的有效时间，例如 60 秒 (1分钟)
                var shortLifetime = TimeSpan.FromSeconds(10);

                // 计算令牌的实际生命周期
                if (expires.HasValue && notBefore.HasValue)
                {
                    // 令牌的实际有效时间
                    var actualLifetime = expires.Value - notBefore.Value;

                    // 如果实际生命周期大于我们想要的短生命周期，则按短生命周期计算过期
                    // 这将导致令牌在短生命周期后被认为是过期的
                    if (actualLifetime > shortLifetime)
                    {
                        // 强制令牌在 notBefore + shortLifetime 时过期
                        return DateTime.UtcNow <= notBefore.Value.Add(shortLifetime);
                    }
                }

                // 否则，使用原始的过期时间进行验证
                return expires.HasValue && expires.Value > DateTime.UtcNow;
            }
        };

        // ****** 移除或注释掉 OnTokenValidated 事件中的临时响应代码 ******
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<JwtBearerHandler>>();
                logger.LogInformation("Token validated successfully. Claims in principal:");
                foreach (var claim in context.Principal.Claims)
                {
                    logger.LogInformation($"- Type: {claim.Type}, Value: {claim.Value}");
                }
                var scopeClaims = context.Principal.Claims.Where(c => c.Type == "scope").ToList();
                if (scopeClaims.Any())
                {
                    logger.LogInformation($"Found 'scope' claims: {string.Join(", ", scopeClaims.Select(c => c.Value))}");
                    if (scopeClaims.Any(c => c.Value.Contains("api1")))
                    {
                        logger.LogInformation("'api1' scope found in claims. Authorization policy should now succeed.");
                    }
                    else
                    {
                        logger.LogWarning("'api1' scope NOT found among claims, even though 'scope' claims exist. Policy might still fail.");
                    }
                }
                else
                {
                    logger.LogWarning("No 'scope' claims found for the authenticated user. Policy will fail.");
                }
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<JwtBearerHandler>>();
                logger.LogError(context.Exception, "Authentication failed during token validation. Exception: {Message}", context.Exception.Message);
                return Task.CompletedTask;
            },
            OnForbidden = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<JwtBearerHandler>>();
                logger.LogWarning("Access forbidden after authentication due to authorization policy failure.");
                return Task.CompletedTask;
            }
        };
    });

// ****** 添加授权配置 ******
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ApiScope", policy =>
    {
        policy.RequireAuthenticatedUser();
        // 修改为 RequireAssertion
        policy.RequireAssertion(context =>
        {
            var scopeClaims = context.User.FindAll("scope");
            return scopeClaims.Any(c => c.Value.Contains("api1"));
        });
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors("MyAllowSpecificOrigins");
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();