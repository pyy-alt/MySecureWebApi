using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Linq; // for .Any() and .Where()
using System.Security.Claims; // for ClaimTypes

namespace MySecureWebApi.Controllers;

[ApiController]
[Route("[controller]")]
[Authorize(Policy = "ApiScope")] // 确保这一行已启用，并且是 "ApiScope"
public class WeatherForecastController : ControllerBase
{
    private static readonly string[] Summaries = new[]
    {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };

    private readonly ILogger<WeatherForecastController> _logger;

    public WeatherForecastController(ILogger<WeatherForecastController> logger)
    {
        _logger = logger;
    }

    [HttpGet(Name = "GetWeatherForecast")]
    public IEnumerable<WeatherForecast> Get()
    {
        // --- 请确保这些调试代码在这里 ---
        var userClaims = User.Claims.Select(c => new { c.Type, c.Value }).ToList();
        _logger.LogInformation("Current User Claims for WeatherForecast:");
        foreach (var claim in userClaims)
        {
            _logger.LogInformation($"- Type: {claim.Type}, Value: {claim.Value}");
        }

        // 检查 'scope' claim
        var scopeClaims = User.Claims.Where(c => c.Type == "scope").ToList();
        if (scopeClaims.Any())
        {
            _logger.LogInformation($"Found 'scope' claims: {string.Join(", ", scopeClaims.Select(c => c.Value))}");
            if (scopeClaims.Any(c => c.Value == "api1"))
            {
                _logger.LogInformation("'api1' scope found in claims. Policy 'ApiScope' should succeed.");
            }
            else
            {
                _logger.LogWarning("'api1' scope NOT found in claims, but other scopes might be present. 'ApiScope' policy would fail.");
            }
        }
        else
        {
            _logger.LogWarning("No 'scope' claims found for the authenticated user. 'ApiScope' policy would fail.");
        }
        // --- 调试代码结束 ---

        return Enumerable.Range(1, 5).Select(index => new WeatherForecast
        {
            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            TemperatureC = Random.Shared.Next(-20, 55),
            Summary = Summaries[Random.Shared.Next(Summaries.Length)]
        })
        .ToArray();
    }
}