using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class PrivateValidationTestResetsControllerTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string AdminSecret = "private-validation-reset-admin";
    private readonly WebApplicationFactory<Program> _factory;
    private readonly FakeResetService _service = new();

    public PrivateValidationTestResetsControllerTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("IsIntegrationTest", "true");
            builder.UseSetting("AdminSettings:ApiSecret", AdminSecret);
            builder.UseSetting("AdminSettings:AllowedIps", string.Empty);
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IPrivateValidationTestResetService>();
                services.AddSingleton<IPrivateValidationTestResetService>(_service);
            });
        });
    }

    [Fact]
    public async Task Validate_WithoutAdminSecret_IsUnauthorizedAndDoesNotInvokeService()
    {
        var response = await _factory.CreateClient().PostAsJsonAsync(Route("validate"), Request());

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, _service.ValidateCalls);
        Assert.Equal(0, _service.ExecuteCalls);
    }

    [Fact]
    public async Task Validate_WithExactRequest_ReturnsReadOnlyResult()
    {
        var response = await PostAsync("validate", Request());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await Json(response);
        Assert.False(body.GetProperty("executed").GetBoolean());
        Assert.Equal(1, _service.ValidateCalls);
        Assert.Equal(0, _service.ExecuteCalls);
    }

    [Fact]
    public async Task Execute_WithExactRequest_UsesSeparateMutationOperation()
    {
        var response = await PostAsync("execute", Request());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await Json(response);
        Assert.True(body.GetProperty("executed").GetBoolean());
        Assert.Equal(0, _service.ValidateCalls);
        Assert.Equal(1, _service.ExecuteCalls);
    }

    [Fact]
    public async Task Execute_WhenServiceRejectsMismatch_PreservesConflictCode()
    {
        _service.Exception = new("identity_mismatch", 409);

        var response = await PostAsync("execute", Request());

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal("identity_mismatch", (await Json(response)).GetProperty("error").GetString());
    }

    [Fact]
    public async Task Execute_WithProductScopedSecret_IsForbiddenBeforeServiceInvocation()
    {
        var productSecret = $"scoped-reset-{Guid.NewGuid():N}";
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LicenseDbContext>();
            db.Products.Add(new Product
            {
                Id = Request().ProductId,
                Name = $"Reset product {Guid.NewGuid():N}",
                PrivateKeyXml = "private",
                PublicKeyXml = "public",
                ApiSecret = productSecret
            });
            await db.SaveChangesAsync();
        }
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", productSecret);

        var response = await client.PostAsJsonAsync(Route("execute"), Request());

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("global_admin_required", (await Json(response)).GetProperty("error").GetString());
        Assert.Equal(0, _service.ExecuteCalls);
    }

    private async Task<HttpResponseMessage> PostAsync(string operation, PrivateValidationTestResetRequest request)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-Secret", AdminSecret);
        return await client.PostAsJsonAsync(Route(operation), request);
    }

    private static PrivateValidationTestResetRequest Request() => new(
        Guid.Parse("808648bc-a4b9-4f71-bcb1-b7c7e67ca98e"),
        Guid.Parse("982c9153-f095-4490-ad62-888ba9249124"),
        Guid.Parse("9525b0a8-0412-467b-a033-ad7c54a67679"),
        "9e3bd429-7c09-4444-82f2-e7a0e2da6f78",
        "2.2.944",
        1,
        "TKT-999962");

    private static string Route(string operation) =>
        $"/api/admin/private-validation/test-identity-resets/{operation}";

    private static async Task<JsonElement> Json(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();

    private sealed class FakeResetService : IPrivateValidationTestResetService
    {
        public int ValidateCalls { get; private set; }
        public int ExecuteCalls { get; private set; }
        public PrivateValidationTestResetException? Exception { get; set; }

        public Task<PrivateValidationTestResetResult> ValidateAsync(
            PrivateValidationTestResetRequest request,
            CancellationToken cancellationToken = default)
        {
            ValidateCalls++;
            return Result(request, executed: false);
        }

        public Task<PrivateValidationTestResetResult> ExecuteAsync(
            PrivateValidationTestResetRequest request,
            CancellationToken cancellationToken = default)
        {
            ExecuteCalls++;
            return Result(request, executed: true);
        }

        private Task<PrivateValidationTestResetResult> Result(
            PrivateValidationTestResetRequest request,
            bool executed)
        {
            if (Exception != null)
                throw Exception;
            return Task.FromResult(new PrivateValidationTestResetResult(
                request.ProductId,
                request.EnrollmentId,
                request.BindingId,
                request.InstallationId,
                request.ReleaseVersion,
                request.SecurityEpoch,
                "ACTIVE",
                "active",
                7,
                "test_identity_reset_tkt_999962",
                AlreadyApplied: false,
                Executed: executed));
        }
    }
}
