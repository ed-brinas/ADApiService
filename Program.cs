using ADApiService.Models;
using ADApiService.Services;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.OpenApi.Models;
using System.Reflection;

var builder = WebApplication.CreateBuilder(args);

// --- 1. Service Configuration ---

// Bind appsettings.json to the AdSettings class for strongly-typed configuration
builder.Services.Configure<AdSettings>(builder.Configuration.GetSection("AdSettings"));

builder.Services.AddControllers();

// Register the AdService for dependency injection
builder.Services.AddScoped<IAdService, AdService>();

// --- 2. Authentication & Authorization ---

// Set up Windows Authentication (Kerberos/NTLM)
builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();

builder.Services.AddAuthorization(options =>
{
    // Require an authenticated user for all endpoints by default
    options.FallbackPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

// --- 3. API Documentation (Swagger) ---

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Version = "v1",
        Title = "Active Directory Management API",
        Description = "A secure API for managing users in a multi-domain Active Directory forest."
    });

    // Include XML comments in Swagger UI
    var xmlFilename = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    options.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory, xmlFilename));
});


// --- 4. CORS Configuration ---

var corsSettings = builder.Configuration.GetSection("Cors").Get<CorsSettings>() ?? new CorsSettings();
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins(corsSettings.AllowedOrigins.ToArray())
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials(); // Required for Windows Authentication
    });
});


// --- 5. Build the Application ---

var app = builder.Build();

// --- 6. Middleware Pipeline ---

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "AD Management API v1"));
    // Add developer exception page for detailed errors in development
    app.UseDeveloperExceptionPage();
}

app.UseCors();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

// Helper class for CORS settings
public class CorsSettings
{
    public List<string> AllowedOrigins { get; set; } = new();
}

