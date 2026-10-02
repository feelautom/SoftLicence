using System.Data.Common;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace SoftLicence.Tests.Server;

/// <summary>Adapts the PostgreSQL full model for relational SQLite test fixtures.</summary>
internal static class SqliteFullModelHarness
{
    /// <summary>Gets the interceptor that registers PostgreSQL-compatible connection primitives.</summary>
    internal static DbConnectionInterceptor ConnectionInterceptor { get; } = new ConnectionPrimitiveInterceptor();

    /// <summary>Gets the interceptor that translates PostgreSQL CHECK operators in SQLite schema commands.</summary>
    internal static DbCommandInterceptor CommandInterceptor { get; } = new CheckConstraintInterceptor();

    /// <summary>Registers ordinal collation, CHECK functions and UUID defaults on an open SQLite fixture connection.</summary>
    internal static void RegisterConnection(SqliteConnection connection)
    {
        RegisterUuidDefault(connection);
        connection.CreateCollation("C", static (left, right) => string.CompareOrdinal(left, right));
        connection.CreateFunction<string?, string?, bool?>(
            "regexp",
            static (pattern, value) => pattern is null || value is null
                ? null
                : Regex.IsMatch(value, ToDotNetRegex(pattern), RegexOptions.CultureInvariant),
            isDeterministic: true);
        connection.CreateFunction<object?, long?>(
            "octet_length",
            static value => value switch
            {
                null => null,
                string text => Encoding.UTF8.GetByteCount(text),
                byte[] bytes => bytes.LongLength,
                _ => throw new InvalidOperationException(
                    $"Unsupported SQLite octet_length argument type: {value.GetType().FullName}.")
            },
            isDeterministic: true);
        connection.CreateFunction<string?, string?, string?>(
            "least",
            static (left, right) => (left, right) switch
            {
                (null, null) => null,
                (null, _) => right,
                (_, null) => left,
                _ => string.CompareOrdinal(left, right) <= 0 ? left : right
            },
            isDeterministic: true);
    }

    /// <summary>
    /// Supplies PostgreSQL's UUID default to SQLite seed INSERTs. This nondeterministic fixture
    /// function does not emulate the PostgreSQL UPDATE trigger or prove authority concurrency;
    /// conditional reactivation remains PostgreSQL-only and has its own relational test suite.
    /// </summary>
    internal static void RegisterUuidDefault(SqliteConnection connection) =>
        connection.CreateFunction("gen_random_uuid", static () => Guid.NewGuid().ToString("D"), isDeterministic: false);

    /// <summary>Maps PostgreSQL's strict end anchor to the equivalent .NET anchor.</summary>
    private static string ToDotNetRegex(string pattern) =>
        pattern.EndsWith('$') && !pattern.EndsWith("\\$", StringComparison.Ordinal)
            ? string.Concat(pattern.AsSpan(0, pattern.Length - 1), "\\z")
            : pattern;

    /// <summary>Registers the test-only primitives whenever EF Core opens a SQLite connection.</summary>
    private sealed class ConnectionPrimitiveInterceptor : DbConnectionInterceptor
    {
        /// <inheritdoc/>
        public override void ConnectionOpened(DbConnection connection, ConnectionEndEventData eventData) =>
            RegisterIfSqlite(connection);

        /// <inheritdoc/>
        public override Task ConnectionOpenedAsync(
            DbConnection connection,
            ConnectionEndEventData eventData,
            CancellationToken cancellationToken = default)
        {
            RegisterIfSqlite(connection);
            return Task.CompletedTask;
        }

        /// <summary>Registers primitives only for the SQLite provider used by the fixture.</summary>
        private static void RegisterIfSqlite(DbConnection connection)
        {
            if (connection is SqliteConnection sqliteConnection)
                RegisterConnection(sqliteConnection);
        }
    }

    /// <summary>Translates PostgreSQL regex operators without removing CHECK constraints.</summary>
    private sealed class CheckConstraintInterceptor : DbCommandInterceptor
    {
        /// <inheritdoc/>
        public override InterceptionResult<int> NonQueryExecuting(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<int> result)
        {
            Translate(command);
            return result;
        }

        /// <inheritdoc/>
        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            Translate(command);
            return ValueTask.FromResult(result);
        }

        /// <summary>Rewrites PostgreSQL regex operators only in SQLite schema CHECK commands.</summary>
        private static void Translate(DbCommand command)
        {
            if (command is not SqliteCommand
                || !command.CommandText.Contains("CHECK", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            command.CommandText = command.CommandText
                .Replace(" !~ ", " NOT REGEXP ", StringComparison.Ordinal)
                .Replace(" ~ ", " REGEXP ", StringComparison.Ordinal);
        }
    }
}
