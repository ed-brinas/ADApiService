using ADApiService.Models;
using ADApiService.Services;
using Microsoft.AspNetCore.Authentication.Negotiate;

var builder = WebApplication.CreateBuilder(args);

// 1. Configure CORS
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        // For development, allow the local web portal.
        // In production, you MUST restrict this to your portal's actual domain.
        policy.WithOrigins("https://localhost:7001", "http://localhost:7000")
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials(); // Required for Windows Auth across origins.
    });
});

// 2. Load Configuration and Register Services
builder.Services.Configure<AdSettings>(builder.Configuration.GetSection("AdSettings"));
builder.Services.AddScoped<IAdService, AdService>();
builder.Services.AddControllers();

// 3. Configure Authentication and Authorization
builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();
builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

// 4. Add Swagger for API Documentation
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "AD User Management API", Version = "v1" });
});

var app = builder.Build();

// 5. Configure the HTTP Request Pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseDeveloperExceptionPage();
}

app.UseHttpsRedirection();
app.UseCors(); // IMPORTANT: CORS must be applied before routing and auth.
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

