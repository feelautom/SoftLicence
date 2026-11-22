namespace SoftLicence.Server.Services;

/// <summary>
/// Seat-capacity rules shared by the authoritative initial-seat allocation of distribution finalize
/// and by the pre-download prediction of the distribution preflight (TKT-001720). Finalize remains
/// the only allocation authority; the preflight may only predict a refusal finalize would also give.
/// </summary>
internal static class InitialSeatAdmission
{
    /// <summary>Exact canonical request value asking the preflight for the initial-installation prediction.</summary>
    internal const string InitialRequest = "initial";

    /// <summary>Internal decision reason of a predicted refusal; never a public code.</summary>
    internal const string PredictedReasonCode = "seat_limit_predicted";

    /// <summary>Public refusal code shared with finalize.</summary>
    internal const string PublicErrorCode = "seat_limit_reached";

    /// <summary>Returns whether a licence without a seat for this machine has no free seat left.</summary>
    /// <param name="maxSeats">Seat limit of the licence.</param>
    /// <param name="activeSeatCount">Number of currently active seats of that licence.</param>
    /// <returns>True when a new seat cannot be established.</returns>
    internal static bool IsCapacityExhausted(int maxSeats, int activeSeatCount) => activeSeatCount >= maxSeats;

    /// <summary>
    /// Returns whether finalize resolves a full licence itself: a one-seat licence switches its seat
    /// automatically, so the preflight never predicts a refusal for it.
    /// </summary>
    /// <param name="maxSeats">Seat limit of the licence.</param>
    /// <returns>True when the automatic seat switch owns the decision.</returns>
    internal static bool UsesAutomaticSwitch(int maxSeats) => maxSeats <= 1;
}
