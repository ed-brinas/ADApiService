using ADApiService.Models;
using ADApiService.Services;
using Microsoft.AspNetCore.Authentication.Negotiate;

public class CorsSettings
{
    public bool RestrictOrigins { get; set; }
    public string[] AllowedOrigins { get; set; }
}

var builder = WebApplication.CreateBuilder(args);
var corsSettings = builder.Configuration.GetSection("CorsSettings").Get<CorsSettings>();

// --- Service Configuration ---
builder.Services.Configure<AdSettings>(builder.Configuration.GetSection("AdSettings"));

builder.Services.AddCors(options =>
{
    options.AddPolicy(name: "DefaultCorsPolicy",
                      policy =>
                      {
                          // Check the setting from appsettings.json
                          if (corsSettings.RestrictOrigins && corsSettings.AllowedOrigins?.Length > 0)
                          {
                              // If true, apply the specific origins
                              policy.WithOrigins(corsSettings.AllowedOrigins)
                                    .AllowAnyHeader()
                                    .AllowAnyMethod()
                                    .AllowCredentials(); // Credentials can be allowed with specific origins
                          }
                          else
                          {
                              // If false, allow any origin (less secure, for development)
                              policy.AllowAnyOrigin()
                                    .AllowAnyHeader()
                                    .AllowAnyMethod();
                              // NOTE: .AllowCredentials() cannot be used with .AllowAnyOrigin()
                          }
                      });
});

builder.Services.AddControllers();
builder.Services.AddScoped<IAdService, AdService>();

// --- Authentication & Authorization ---
builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();
builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

// --- Swagger for API Documentation ---
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "AD User Management API", Version = "v1" });
    var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    c.IncludeXmlComments(xmlPath);
});

var app = builder.Build();

// --- HTTP Request Pipeline ---
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// ** NEW: Middleware to log the incoming request origin **
app.Use((context, next) =>
{
    var origin = context.Request.Headers["Origin"].FirstOrDefault();
    if (!string.IsNullOrEmpty(origin))
    {
        // Use the application's logger to print the origin to the console
        app.Logger.LogInformation("--> Incoming request from Origin: {Origin}", origin);
    }
    else
    {
        app.Logger.LogInformation("--> Incoming request with no Origin header.");
    }
    return next();
});


app.UseRouting();

app.UseCors(DefaultCorsPolicy);

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

