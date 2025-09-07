using ADApiService.Models;
using ADApiService.Services;
using Microsoft.AspNetCore.Authentication.Negotiate;

var builder = WebApplication.CreateBuilder(args);
var AllowSpecificOrigins = "_myAllowSpecificOrigins";

// --- Service Configuration ---
builder.Services.Configure<AdSettings>(builder.Configuration.GetSection("AdSettings"));

builder.Services.AddCors(options =>
{
    options.AddPolicy(name: AllowSpecificOrigins,
                      policy =>
                      {
                          policy.WithOrigins("http://localhost:7000") // The origin of your ADWebPortal
                                .AllowAnyHeader()
                                .AllowAnyMethod()
                                .AllowCredentials(); // Required for Windows Authentication
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

app.UseCors(AllowSpecificOrigins);

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

