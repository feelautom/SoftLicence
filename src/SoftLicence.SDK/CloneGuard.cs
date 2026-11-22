using System.Security.Cryptography;

namespace SoftLicence.SDK
{
    /// <summary>
    /// Single-use control token pair presented by a guard-aware client on each licence check (server TKT-003615):
    /// lets the server detect a copied or restored installation that keeps running next to the original one.
    /// </summary>
    /// <remarks>
    /// <para>Client contract (server document <c>docs/schema/jeton-anti-clonage.md</c>, section 5):</para>
    /// <list type="number">
    /// <item>Send at most one guarded check at a time per installation; two concurrent pairs are a real collision.</item>
    /// <item>Draw <see cref="NextToken"/> with <see cref="GenerateToken"/> and persist it durably <b>before</b> sending.</item>
    /// <item>On <see cref="CloneGuardOutcome.Outcome"/> <c>ARMED</c>, <c>ACCEPTED</c>, <c>REPLAYED</c> or
    /// <c>REACTIVATED</c>, the next token becomes the current token.</item>
    /// <item>On a network failure or a missing <see cref="LicenseStatusResult.CloneGuard"/>, keep the pair and send the
    /// exact same pair again: the server answers <c>REPLAYED</c> without counting a collision.</item>
    /// <item>On <c>DUPLICATE_DETECTED</c>, keep both tokens unchanged, suspend only the protected features and offer
    /// <see cref="ISoftLicenceClient.ReactivateCloneGuardAsync"/>.</item>
    /// </list>
    /// <para>Tokens are opaque secrets of the installation: never log them.</para>
    /// </remarks>
    public sealed class CloneGuardPresentation
    {
        /// <summary>Length of a token: unpadded base64url of 32 bytes.</summary>
        public const int TokenLength = 43;

        /// <summary>
        /// Validates and captures a token pair. Validation happens here, before any network request, so a malformed
        /// pair never reaches the server.
        /// </summary>
        /// <param name="token">Current token, or <see langword="null"/> when the installation has none yet (first check, or after a key change).</param>
        /// <param name="nextToken">Next token drawn by <see cref="GenerateToken"/> and already persisted.</param>
        /// <param name="vmGenerationId">VM Generation ID exposed by Windows as 32 hexadecimal characters, or <see langword="null"/>.</param>
        /// <exception cref="ArgumentException">
        /// A token is not exactly 43 canonical base64url characters encoding 32 bytes, <paramref name="nextToken"/>
        /// equals <paramref name="token"/>, or <paramref name="vmGenerationId"/> is not 32 hexadecimal characters.
        /// </exception>
        public CloneGuardPresentation(string? token, string nextToken, string? vmGenerationId)
        {
            if (token != null && !IsCanonicalToken(token))
                throw new ArgumentException("The current token must be 43 base64url characters encoding 32 bytes.", nameof(token));
            if (!IsCanonicalToken(nextToken))
                throw new ArgumentException("The next token must be 43 base64url characters encoding 32 bytes.", nameof(nextToken));
            if (string.Equals(token, nextToken, StringComparison.Ordinal))
                throw new ArgumentException("The next token must differ from the current token.", nameof(nextToken));
            if (vmGenerationId != null && !IsVmGenerationId(vmGenerationId))
                throw new ArgumentException("The VM Generation ID must be 32 hexadecimal characters.", nameof(vmGenerationId));
            Token = token;
            NextToken = nextToken;
            VmGenerationId = vmGenerationId;
        }

        /// <summary>Gets the current token, or <see langword="null"/> when the installation has none yet.</summary>
        public string? Token { get; }

        /// <summary>Gets the next token, persisted by the caller before the request.</summary>
        public string NextToken { get; }

        /// <summary>Gets the VM Generation ID sent as a secondary signal, or <see langword="null"/>.</summary>
        public string? VmGenerationId { get; }

        /// <summary>
        /// Draws a new token: 32 bytes from the operating system's cryptographic generator, encoded as unpadded
        /// base64url (43 characters).
        /// </summary>
        /// <returns>A fresh token, never equal to a previous one in practice.</returns>
        public static string GenerateToken()
        {
            var bytes = new byte[32];
            using (var generator = RandomNumberGenerator.Create())
                generator.GetBytes(bytes);
            return Encode(bytes);
        }

        /// <summary>Encodes bytes as unpadded base64url.</summary>
        private static string Encode(byte[] bytes) =>
            Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        /// <summary>
        /// Checks the canonical token form the server accepts: 43 characters of <c>A-Z a-z 0-9 - _</c> decoding to 32
        /// bytes and re-encoding to the same text (the server rejects aliases with non-zero trailing bits).
        /// </summary>
        internal static bool IsCanonicalToken(string? value)
        {
            if (value == null || value.Length != TokenLength)
                return false;
            foreach (var character in value)
            {
                var allowed = (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z')
                    || (character >= '0' && character <= '9') || character == '-' || character == '_';
                if (!allowed)
                    return false;
            }
            try
            {
                var bytes = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + "=");
                return bytes.Length == 32 && string.Equals(Encode(bytes), value, StringComparison.Ordinal);
            }
            catch (FormatException)
            {
                return false;
            }
        }

        /// <summary>Checks that a value is exactly 32 ASCII hexadecimal characters (either case).</summary>
        internal static bool IsVmGenerationId(string value)
        {
            if (value.Length != 32)
                return false;
            foreach (var character in value)
            {
                var hex = (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')
                    || (character >= 'A' && character <= 'F');
                if (!hex)
                    return false;
            }
            return true;
        }
    }

    /// <summary>
    /// <c>cloneGuard</c> member of a check or reactivation answer (server TKT-003615). <see langword="null"/> on
    /// <see cref="LicenseStatusResult.CloneGuard"/> when the server sent none (request without pair, older server,
    /// network failure).
    /// </summary>
    public sealed class CloneGuardOutcome
    {
        /// <summary>Server outcome: <c>ARMED</c>.</summary>
        public const string Armed = "ARMED";
        /// <summary>Server outcome: <c>ACCEPTED</c>.</summary>
        public const string Accepted = "ACCEPTED";
        /// <summary>Server outcome: <c>REPLAYED</c>.</summary>
        public const string Replayed = "REPLAYED";
        /// <summary>Server outcome: <c>DUPLICATE_DETECTED</c> (also the logical status of the check).</summary>
        public const string DuplicateDetected = "DUPLICATE_DETECTED";
        /// <summary>Server outcome: <c>NOT_EVALUATED</c> (status not VALID, keep the current token).</summary>
        public const string NotEvaluated = "NOT_EVALUATED";
        /// <summary>Server outcome: <c>NOT_APPLICABLE</c>.</summary>
        public const string NotApplicable = "NOT_APPLICABLE";
        /// <summary>Server outcome: <c>MALFORMED</c>.</summary>
        public const string Malformed = "MALFORMED";
        /// <summary>Server outcome: <c>UNSUPPORTED_PROTOCOL</c>.</summary>
        public const string UnsupportedProtocol = "UNSUPPORTED_PROTOCOL";
        /// <summary>Server outcome: <c>REACTIVATED</c>.</summary>
        public const string Reactivated = "REACTIVATED";
        /// <summary>Server outcome: <c>REACTIVATION_LIMIT_REACHED</c> (licence daily quota exhausted; retry after midnight UTC).</summary>
        public const string ReactivationLimitReached = "REACTIVATION_LIMIT_REACHED";

        /// <summary>Creates an outcome read from a server answer.</summary>
        /// <param name="outcome">Outcome text exactly as sent by the server.</param>
        /// <param name="reason">Reason (<c>stale_token</c>, <c>token_missing</c>, <c>daily_quota_exhausted</c>), or <see langword="null"/>.</param>
        /// <param name="environmentChanged">True when the server saw a VM Generation ID different from the known one.</param>
        public CloneGuardOutcome(string outcome, string? reason, bool environmentChanged)
        {
            Outcome = outcome;
            Reason = reason;
            EnvironmentChanged = environmentChanged;
        }

        /// <summary>Gets the outcome, compared ordinally against the constants of this class.</summary>
        public string Outcome { get; }

        /// <summary>Gets the machine-readable reason, or <see langword="null"/>.</summary>
        public string? Reason { get; }

        /// <summary>Gets whether an accepted check reported a changed VM Generation ID (information only).</summary>
        public bool EnvironmentChanged { get; }

        /// <summary>
        /// Gets whether the caller must now replace its current token with the next token it presented
        /// (<c>ARMED</c>, <c>ACCEPTED</c>, <c>REPLAYED</c>, <c>REACTIVATED</c>).
        /// </summary>
        public bool NextTokenBecomesCurrent =>
            Outcome == Armed || Outcome == Accepted || Outcome == Replayed || Outcome == Reactivated;
    }
}
