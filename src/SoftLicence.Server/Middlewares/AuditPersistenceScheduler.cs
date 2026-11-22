namespace SoftLicence.Server.Middlewares;

/// <summary>
/// Preserves non-blocking audit persistence in production while allowing integration hosts to
/// await their own database work before disposing an isolated PostgreSQL fixture.
/// </summary>
internal static class AuditPersistenceScheduler
{
    /// <summary>
    /// Starts one best-effort audit operation. Integration tests receive the operation task so
    /// their HTTP response cannot outlive fixture-owned database activity; production retains
    /// the existing detached execution model.
    /// </summary>
    /// <param name="waitForCompletion">Whether the caller must observe completion.</param>
    /// <param name="persistAsync">The complete audit persistence operation.</param>
    /// <returns>The persistence task for integration tests, otherwise a completed task.</returns>
    internal static Task ScheduleAsync(bool waitForCompletion, Func<Task> persistAsync)
    {
        ArgumentNullException.ThrowIfNull(persistAsync);

        if (waitForCompletion)
            return persistAsync();

        _ = Task.Run(persistAsync);
        return Task.CompletedTask;
    }
}
