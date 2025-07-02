var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Swagger in dev

    app.UseSwagger();
    app.UseSwaggerUI();


app.UseHttpsRedirection(); // Optional if you're hosting without HTTPS

app.MapControllers();

app.Run();
