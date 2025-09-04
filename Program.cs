var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// This simple configuration serves the index.html file as the default document
// and enables serving other static assets from the wwwroot folder.
app.UseDefaultFiles();
app.UseStaticFiles();

app.Run();

