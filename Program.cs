using KeyStone.Models;
using KeyStone.Models;
using KeyStone.Services;
using Microsoft.AspNetCore.Authentication.Negotiate;

var builder = WebApplication.CreateBuilder(args);

// --- Service Configuration ---
builder.Services.Configure<AdSettings>(builder.Configuration.GetSection("AdSettings"));
builder.Services.AddControllers();
builder.Services.AddScoped<IAdService, AdService>();

// --- Authentication & Authorization ---
//builder.Services
//    .AddAuthentication(NegotiateDefaults.AuthenticationScheme)
//    .AddNegotiate();

builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

// --- Swagger for API Documentation ---
// Keep registration in all envs, but guard XML include to avoid FileNotFound at startup.
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

// Simple request origin logger (harmless without CORS)
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
app.UseDefaultFiles(); // Serves index.html for the root URL
app.UseStaticFiles();  // Serves files from wwwroot

// app.UsePathBase("/api"); // PathBase is supplied by IIS via --pathbase or ASPNETCORE_PATHBASE.
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();