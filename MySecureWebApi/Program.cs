using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims; // 用于 ClaimTypes

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

// 添加对控制器的支持
builder.Services.AddControllers(); 

// 配置 Swagger/OpenAPI 支持
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// ****** 添加 JWT Bearer 认证配置 ******
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // 认证服务器的地址（Orchard CoreAuthServer 的实际 URL）
        // 确保这里是 http://localhost:5233，与您的认证服务器实际运行的协议和端口一致
        options.Authority = "http://localhost:5233"; 

        // 既然 Authority 是 HTTP，这里就必须设置为 false，不依赖于 IsDevelopment() 判断
        options.RequireHttpsMetadata = false; 

        // 你的 API 的 Audience (受众)，与在 Orchard Core 中配置的 Resource Scope 名称一致
        options.Audience = "api1"; 

        // 配置令牌验证参数
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = true,  // 验证令牌的受众
            ValidAudience = "api1",   // 再次强调受众，必须与 Orchard Core 中配置的 Resource Scope 名称一致
            ValidateIssuer = true,    // 验证令牌的颁发者
            ValidIssuer = "http://localhost:5233", // 必须与 Authority 一致
            ValidateLifetime = true,  // 验证令牌的有效期
            ClockSkew = TimeSpan.Zero // 严格校验令牌过期时间，没有时间偏差
        };
    });

// ****** 添加授权配置 ******
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ApiScope", policy =>
    {
        // 要求必须通过认证
        policy.RequireAuthenticatedUser();
        // 要求令牌中包含 'scope' 声明，且值为 'api1'
        policy.RequireClaim("scope", "api1");
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// !!! 临时注释掉 HTTPS 重定向，因为您当前使用 HTTP 访问 !!!
// app.UseHttpsRedirection(); 

app.UseAuthentication(); // 启用认证中间件，它会处理 JWT 令牌
app.UseAuthorization();  // 启用授权中间件，它会根据策略检查权限

app.MapControllers(); // 映射控制器路由，使 API 端点可以被访问

app.Run(); // 启动应用程序