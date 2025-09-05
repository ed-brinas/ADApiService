using ADApiService.Models;
using ADApiService.Services;
using Microsoft.AspNetCore.Authentication.Negotiate;

var builder = WebApplication.CreateBuilder(args);

// --- Configuration & Services ---
builder.Services.Configure<AdSettings>(builder.Configuration.GetSection("AdSettings"));
builder.Services.AddControllers();
builder.Services.AddScoped<IAdService, AdService>();

// --- Authentication & Authorization ---
builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();
builder.Services.AddAuthorization(options =>
{
    // This policy requires an authenticated user for any endpoint that doesn't have a specific authorization attribute.
    options.FallbackPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

// --- API Documentation (Swagger) ---
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "AD User Management API", Version = "v1" });
});

// --- Cross-Origin Resource Sharing (CORS) ---
// Allows the ADWebPortal (running on a different port) to call this API.
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins("http://localhost:7000") // URL of the ADWebPortal
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials(); // Required for Windows Authentication
    });
});


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    // The Swagger UI will be available at /swagger
    app.UseSwaggerUI();
}

// --- IMPORTANT: HTTPS Redirection is now REMOVED ---
// app.UseHttpsRedirection();

// The order of these is important: Routing -> CORS -> Auth -> Authorization -> Endpoints
app.UseRouting();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

