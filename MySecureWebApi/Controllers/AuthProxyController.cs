// File: MySecureWebApi/Controllers/AuthProxyController.cs
using Microsoft.AspNetCore.Mvc;
using Duende.IdentityModel.Client; // 确保是 Duende.IdentityModel.Client
using System.Net.Http; // For IHttpClientFactory
using System.Threading.Tasks; // For async/await
using Microsoft.Extensions.Configuration; // For IConfiguration to read from appsettings.json
using System; // For Console.WriteLine and Exception

[ApiController]
[Route("api/[controller]")] // 路由是 /api/AuthProxy
public class AuthProxyController : ControllerBase
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _configuration; // 注入 IConfiguration

    public AuthProxyController(IHttpClientFactory httpClientFactory, IConfiguration configuration)
    {
        _httpClientFactory = httpClientFactory;
        _configuration = configuration;
    }

    [HttpPost("login")] // 登录端点：POST /api/AuthProxy/login
    public async Task<IActionResult> Login([FromBody] LoginRequestModel model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        // 从 appsettings.json 读取配置
        var orchardAuthServerUrl = _configuration["IdentityServer:Authority"];
        var clientId = _configuration["IdentityServer:ClientId"];
        var clientSecret = _configuration["IdentityServer:ClientSecret"];
        var scopes = _configuration["IdentityServer:Scopes"];

        if (string.IsNullOrEmpty(orchardAuthServerUrl) || string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret) || string.IsNullOrEmpty(scopes))
        {
            return StatusCode(500, new { message = "Server configuration for IdentityServer (Authority, ClientId, ClientSecret, Scopes) is missing." });
        }

        var client = _httpClientFactory.CreateClient();

        try
        {
            // 1. 发现 IdentityServer4 的配置端点 (Discovery Document)
            var disco = await client.GetDiscoveryDocumentAsync(orchardAuthServerUrl);
            if (disco.IsError)
            {
                Console.WriteLine($"Discovery error during login: {disco.Error}");
                return StatusCode(500, new { message = $"Failed to discover IdentityServer: {disco.Error}" });
            }

            if (string.IsNullOrEmpty(disco.TokenEndpoint))
            {
                return StatusCode(500, new { message = "IdentityServer Token Endpoint not found in discovery document." });
            }

            // 2. 构建并发送 ROPC 请求 (RequestPasswordTokenAsync)
            var tokenResponse = await client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = disco.TokenEndpoint, // 使用发现的 Token Endpoint
                ClientId = clientId,
                ClientSecret = clientSecret, // <-- 提供 Client Secret
                Scope = scopes,
                UserName = model.Username,
                Password = model.Password
            });

            // 3. 处理 IdentityServer 的响应
            if (tokenResponse.IsError)
            {
                // 使用 ?? 运算符确保 ErrorDescription 为 null 时有默认值
                Console.WriteLine($"Token request error: {tokenResponse.Error} - {tokenResponse.ErrorDescription ?? "No description available."}");
                
                // 如果是 invalid_grant (凭据错误) 或 invalid_client (客户端认证失败)，返回 400
                if (tokenResponse.Error == "invalid_grant" || tokenResponse.Error == "invalid_client")
                {
                     return BadRequest(new { message = tokenResponse.ErrorDescription ?? tokenResponse.Error });
                }
                // 其他服务器端错误，返回 500
                return StatusCode(500, new { message = tokenResponse.ErrorDescription ?? tokenResponse.Error });
            }

            // 4. 成功获取 Token，将 Token 返回给前端
            return Ok(new
            {
                accessToken = tokenResponse.AccessToken,
                idToken = tokenResponse.IdentityToken,
                refreshToken = tokenResponse.RefreshToken,
                expiresIn = tokenResponse.ExpiresIn
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An unexpected error occurred during login: {ex.Message}");
            return StatusCode(500, new { message = "An unexpected error occurred during login." });
        }
    }

    // ====== 新增的登出端点：POST /api/AuthProxy/logout ======
    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody] LogoutRequestModel model)
    {
        // 确保客户端ID和Secret是从配置中读取的
        var orchardAuthServerUrl = _configuration["IdentityServer:Authority"];
        var clientId = _configuration["IdentityServer:ClientId"];
        var clientSecret = _configuration["IdentityServer:ClientSecret"];

        if (string.IsNullOrEmpty(orchardAuthServerUrl) || string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
        {
            return StatusCode(500, new { message = "Server configuration for IdentityServer (Authority, ClientId, ClientSecret) is missing for logout." });
        }

        var client = _httpClientFactory.CreateClient();

        try
        {
            // 1. 发现 IdentityServer4 的配置端点 (Discovery Document)
            var disco = await client.GetDiscoveryDocumentAsync(orchardAuthServerUrl);
            if (disco.IsError)
            {
                Console.WriteLine($"Discovery error during logout: {disco.Error}");
                return StatusCode(500, new { message = $"Failed to discover IdentityServer during logout: {disco.Error}" });
            }

            if (string.IsNullOrEmpty(disco.RevocationEndpoint))
            {
                return StatusCode(500, new { message = "IdentityServer Revocation Endpoint not found in discovery document. Please ensure it is enabled in Orchard Core OIDC settings." });
            }

            // 2. 调用 IdentityServer 的 Token 撤销端点
            // 我们将优先尝试撤销 Refresh Token，因为它通常有效期更长，且是刷新 Access Token 的凭证。
            // 之后再尝试撤销 Access Token。
            
            // Flag to track if any token was successfully revoked or attempted
            bool revocationAttempted = false;

            // --- 尝试撤销 Refresh Token ---
            if (!string.IsNullOrEmpty(model.RefreshToken))
            {
                revocationAttempted = true;
                var refreshTokenRevocationResponse = await client.RevokeTokenAsync(new TokenRevocationRequest
                {
                    Address = disco.RevocationEndpoint, // 从发现文档获取撤销端点
                    ClientId = clientId,
                    ClientSecret = clientSecret, // Confidential Client 需要提供 Client Secret
                    Token = model.RefreshToken,
                    TokenTypeHint = "refresh_token" // 明确指定是 refresh_token
                });

                // 检查响应对象本身是否为 null 或是否有错误
                if (refreshTokenRevocationResponse == null)
                {
                    Console.WriteLine("Refresh Token revocation response was null, this indicates an issue with the HTTP call itself.");
                }
                else if (refreshTokenRevocationResponse.IsError)
                {
                    // 使用 ?? 运算符确保 ErrorDescription 为 null 时有默认值
                    Console.WriteLine($"Refresh Token revocation error: {refreshTokenRevocationResponse.Error}");
                    // 尽管有错误，但我们允许请求继续，因为前端会清除本地token。
                    // 实际项目中，您可能需要更复杂的错误处理或重试逻辑。
                }
                else
                {
                    Console.WriteLine("Refresh Token successfully revoked at IdentityServer.");
                }
            }
            
            // --- 尝试撤销 Access Token (如果 Refresh Token 不存在或已处理) ---
            if (!string.IsNullOrEmpty(model.AccessToken)) // 即使 refresh token 存在，也可以尝试撤销 access token
            {
                revocationAttempted = true;
                var accessTokenRevocationResponse = await client.RevokeTokenAsync(new TokenRevocationRequest
                {
                    Address = disco.RevocationEndpoint,
                    ClientId = clientId,
                    ClientSecret = clientSecret,
                    Token = model.AccessToken,
                    TokenTypeHint = "access_token"
                });

                // 检查响应对象本身是否为 null 或是否有错误
                if (accessTokenRevocationResponse == null)
                {
                    Console.WriteLine("Access Token revocation response was null, this indicates an issue with the HTTP call itself.");
                }
                else if (accessTokenRevocationResponse.IsError)
                {
                    // 使用 ?? 运算符确保 ErrorDescription 为 null 时有默认值
                    Console.WriteLine($"Access Token revocation error: {accessTokenRevocationResponse.Error}");
                }
                else
                {
                    Console.WriteLine("Access Token successfully revoked at IdentityServer.");
                }
            }
            
            if (!revocationAttempted)
            {
                Console.WriteLine("No tokens (Access Token or Refresh Token) provided by the client for revocation.");
            }

            // 3. 返回成功响应给前端
            // 即使Token撤销过程中有警告或错误，只要不导致服务崩溃，我们通常也返回成功给前端，
            // 因为前端会清除本地token并认为自己已登出。
            return Ok(new { message = "Logout processed by MySecureWebApi, tokens revoked if provided and successful." });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An unexpected error occurred during logout: {ex.Message}");
            // 如果发生意外异常，返回 500
            return StatusCode(500, new { message = "An unexpected error occurred during logout." });
        }
    }
    
     // ====== 新增的注册端点：POST /api/AuthProxy/register ======
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequestProxyModel model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var orchardAuthServerUrl = _configuration["IdentityServer:Authority"]; // 同样使用 Auth Server 的 URL
        if (string.IsNullOrEmpty(orchardAuthServerUrl))
        {
            return StatusCode(500, new { message = "Orchard Core Auth Server URL is missing in configuration." });
        }

        var client = _httpClientFactory.CreateClient();

        try
        {
            // 构建转发到 Orchard Core 注册 API 的请求 URL
            // 假设 Orchard Core 的注册 API 是 /api/Registration/register
            var registrationApiUrl = $"{orchardAuthServerUrl}/api/Registration/register";

            // 创建 JSON 内容
            var jsonContent = new StringContent(
                System.Text.Json.JsonSerializer.Serialize(new 
                { 
                    model.Username, 
                    model.Email, 
                    model.Password, 
                    model.ConfirmPassword 
                }),
                System.Text.Encoding.UTF8,
                "application/json"
            );

            // 发送 POST 请求到 Orchard Core 的注册 API
            var response = await client.PostAsync(registrationApiUrl, jsonContent);

            // 处理 Orchard Core 注册 API 的响应
            if (response.IsSuccessStatusCode)
            {
                return Ok(new { message = "User registration request sent successfully to Orchard Core." });
            }
            else
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"Error from Orchard Core registration API: {response.StatusCode} - {errorContent}");
                return StatusCode((int)response.StatusCode, new { message = "Failed to register user at Orchard Core.", details = errorContent });
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An unexpected error occurred during user registration proxy: {ex.Message}");
            return StatusCode(500, new { message = "An unexpected error occurred during registration." });
        }
    }
}
    
// 登录请求 DTO
public class LoginRequestModel
{
    public string Username { get; set; } = string.Empty; // 初始化，避免 null 警告
    public string Password { get; set; } = string.Empty; // 初始化，避免 null 警告
}

// 登出请求 DTO
public class LogoutRequestModel
{
    public string? AccessToken { get; set; } // 可以为 null，使用 ? 标记可空类型
    public string? RefreshToken { get; set; } // 可以为 null，使用 ? 标记可空类型
}
// MySecureWebApi 用于接收前端注册请求的 DTO
// 名称与 Orchard Core 中的 RegisterRequestModel 不同，避免混淆
public class RegisterRequestProxyModel
{
    [System.ComponentModel.DataAnnotations.Required]
    public string Username { get; set; } = string.Empty;

    [System.ComponentModel.DataAnnotations.Required]
    [System.ComponentModel.DataAnnotations.EmailAddress]
    public string Email { get; set; } = string.Empty;

    [System.ComponentModel.DataAnnotations.Required]
    public string Password { get; set; } = string.Empty;

    [System.ComponentModel.DataAnnotations.Compare("Password")]
    public string ConfirmPassword { get; set; } = string.Empty;
}