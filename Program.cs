using ADApiService.Models;
using ADApiService.Services;
using Microsoft.AspNetCore.Authentication.Negotiate;

var builder = WebApplication.CreateBuilder(args);

// --- Configuration ---
// Bind the "AdSettings" section from appsettings.json to the AdSettings class.
builder.Services.Configure<AdSettings>(builder.Configuration.GetSection("AdSettings"));

// --- Services ---
builder.Services.AddControllers();

// Register the AdService for dependency injection.
builder.Services.AddScoped<IAdService, AdService>();

// --- Authentication & Authorization ---
// Add Windows Authentication (Negotiate protocol for Kerberos/NTLM).
builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme)
   .AddNegotiate();

// Configure authorization services.
builder.Services.AddAuthorization(options =>
{
    // This is useful if you need to create policies, but for simple role checks,
    // the [Authorize(Roles = "...")] attribute is sufficient.
    options.FallbackPolicy = options.DefaultPolicy;
});


// --- Swagger for API Documentation ---
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "Active Directory User Management API", Version = "v1" });
});

// --- IIS Integration ---
// This configures the application to run behind IIS, forwarding authentication tokens.
builder.Services.Configure<IISOptions>(options =>
{
    options.AutomaticAuthentication = true;
});


var app = builder.Build();

// --- HTTP Request Pipeline ---
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    // In development, provides detailed exception pages.
    app.UseDeveloperExceptionPage();
}

app.UseHttpsRedirection();

// The order is important here: Authentication must come before Authorization.
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

