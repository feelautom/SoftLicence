using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

[ApiController]
[Route("api/docs")]
[EnableRateLimiting("DocsAPI")]
public class DocsController : ControllerBase
{
    private readonly DocumentationService _docs;

    public DocsController(DocumentationService docs)
    {
        _docs = docs;
    }

    /// <summary>
    /// Get the full documentation (all sections).
    /// </summary>
    [HttpGet]
    [ResponseCache(Duration = 3600, Location = ResponseCacheLocation.Any)]
    public IActionResult GetFullDocumentation()
    {
        TagLog("DOCS_FULL");

        var content = _docs.GetFullDocumentation();

        if (WantsJson())
            return Ok(new { format = "markdown", sections = _docs.GetSectionIndex().Count, content });

        return Content(content, "text/markdown; charset=utf-8");
    }

    /// <summary>
    /// Get the index of all available sections.
    /// </summary>
    [HttpGet("sections")]
    [ResponseCache(Duration = 3600, Location = ResponseCacheLocation.Any)]
    public IActionResult GetSections()
    {
        TagLog("DOCS_INDEX");
        return Ok(_docs.GetSectionIndex());
    }

    /// <summary>
    /// Get a specific documentation section by ID.
    /// </summary>
    [HttpGet("{section}")]
    [ResponseCache(Duration = 3600, Location = ResponseCacheLocation.Any)]
    public IActionResult GetSection(string section)
    {
        TagLog($"DOCS_SECTION:{section}");

        var content = _docs.GetSection(section);
        if (content is null)
            return NotFound(new { error = "Section not found", available = _docs.GetSectionIndex().Select(s => s.Id) });

        if (WantsJson())
            return Ok(new { section, content });

        return Content(content, "text/markdown; charset=utf-8");
    }

    /// <summary>
    /// Full-text search across all documentation.
    /// </summary>
    [HttpGet("search")]
    [ResponseCache(Duration = 3600, Location = ResponseCacheLocation.Any, VaryByQueryKeys = new[] { "q", "max" })]
    public IActionResult Search([FromQuery] string? q, [FromQuery] int max = 20)
    {
        TagLog($"DOCS_SEARCH:{q}");

        if (string.IsNullOrWhiteSpace(q))
            return BadRequest(new { error = "Query parameter 'q' is required" });

        var results = _docs.Search(q, Math.Clamp(max, 1, 100));
        return Ok(new { query = q, count = results.Count, results });
    }

    private bool WantsJson()
    {
        var accept = HttpContext.Request.Headers.Accept.ToString();
        return accept.Contains("application/json", StringComparison.OrdinalIgnoreCase);
    }

    private void TagLog(string endpoint)
    {
        HttpContext.Items[LogKeys.AppName] = "LLM_DOCS";
        HttpContext.Items[LogKeys.Endpoint] = endpoint;
    }
}
