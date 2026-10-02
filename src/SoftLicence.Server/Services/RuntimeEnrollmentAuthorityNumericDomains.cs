namespace SoftLicence.Server.Services;

/// <summary>Represents a non-negative security epoch owned by one exact Runtime enrollment authority scope.</summary>
internal readonly record struct RuntimeEnrollmentSecurityEpoch
{
    private RuntimeEnrollmentSecurityEpoch(int value) => Value = value;

    /// <summary>Gets the validated wire value.</summary>
    internal int Value { get; }

    /// <summary>Creates a security epoch only when the wire value belongs to its non-negative domain.</summary>
    internal static bool TryCreate(int value, out RuntimeEnrollmentSecurityEpoch epoch)
    {
        epoch = value >= 0 ? new(value) : default;
        return value >= 0;
    }

    /// <summary>Returns whether this epoch is lower than an earlier epoch in the same authority scope.</summary>
    internal bool IsRegressionFrom(RuntimeEnrollmentSecurityEpoch previous) => Value < previous.Value;

    /// <summary>Returns whether this epoch is exactly the next epoch in the same authority scope.</summary>
    internal bool IsDirectSuccessorOf(RuntimeEnrollmentSecurityEpoch previous) =>
        previous.Value < int.MaxValue && Value == previous.Value + 1;
}

/// <summary>Represents a non-negative, JSON-safe generation position owned by one exact provider authority lineage.</summary>
internal readonly record struct RuntimeEnrollmentLineageSequence
{
    /// <summary>The largest integer that remains exact in the Website JavaScript consumer.</summary>
    internal const long MaximumWireValue = 9_007_199_254_740_991L;

    private RuntimeEnrollmentLineageSequence(long value) => Value = value;

    /// <summary>Gets the validated wire value.</summary>
    internal long Value { get; }

    /// <summary>Gets the unique genesis position for every independent lineage.</summary>
    internal static RuntimeEnrollmentLineageSequence Genesis => new(0);

    /// <summary>Creates a sequence only when the wire value is non-negative and exactly JSON-safe.</summary>
    internal static bool TryCreate(long value, out RuntimeEnrollmentLineageSequence sequence)
    {
        sequence = value is >= 0 and <= MaximumWireValue ? new(value) : default;
        return value is >= 0 and <= MaximumWireValue;
    }

    /// <summary>Returns whether this is the genesis position.</summary>
    internal bool IsGenesis => Value == 0;

    /// <summary>Returns whether this is exactly the next position in the same lineage.</summary>
    internal bool IsDirectSuccessorOf(RuntimeEnrollmentLineageSequence previous) =>
        previous.Value < MaximumWireValue && Value == previous.Value + 1;

    /// <summary>Creates the next position, failing closed at the exact wire boundary.</summary>
    internal bool TryNext(out RuntimeEnrollmentLineageSequence next)
    {
        next = Value < MaximumWireValue ? new(Value + 1) : default;
        return Value < MaximumWireValue;
    }
}
