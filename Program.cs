using KeyStone.Models;
using KeyStone.Services;
using Microsoft.AspNetCore.Authentication.Cookies; // MODIFIED // Added Cookie Authentication - 2025-10-10 07:58 AM
using Microsoft.AspNetCore.Authentication.Negotiate;

var builder = WebApplication.CreateBuilder(args);

// --- Service Configuration ---
builder.Services.Configure<AdSettings>(builder.Configuration.GetSection("AdSettings"));
builder.Services.AddControllers();
builder.Services.AddScoped<IAdService, AdService>();

// --- Authentication & Authorization ---
// MODIFIED START // Replaced Negotiate with Cookie Authentication - 2025-10-10 07:58 AM
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
        options.SlidingExpiration = true;
        options.AccessDeniedPath = "/Forbidden/";
    });
// MODIFIED END // Replaced Negotiate with Cookie Authentication - 2025-10-10 07:58 AM

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
    if (File.Exists(xmlPath))
    {
        c.IncludeXmlComments(xmlPath);
    }
});

var app = builder.Build();

// --- HTTP Request Pipeline ---
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Simple request origin logger
app.Use(async (context, next) =>
{
    var origin = context.Request.Headers["Origin"].FirstOrDefault();
    if (!string.IsNullOrEmpty(origin))
        app.Logger.LogInformation("--> Incoming request from Origin: {Origin}", origin);
    else
        app.Logger.LogInformation("--> Incoming request with no Origin header.");
    await next();
});

// --- Add these lines to serve the frontend ---
app.UseDefaultFiles();
app.UseStaticFiles();

app.UseRouting();

// These must be in this order
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();