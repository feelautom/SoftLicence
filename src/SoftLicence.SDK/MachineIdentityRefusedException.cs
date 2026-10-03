namespace SoftLicence.SDK
{
    /// <summary>
    /// Thrown by <see cref="HardwareInfo.GetHardwareId"/> when the machine has no acceptable system UUID, so no
    /// licence hardware identifier exists for it. The message only carries the support code, never the reason.
    /// </summary>
    public sealed class MachineIdentityRefusedException : Exception
    {
        /// <summary>Creates the exception from a refused identity.</summary>
        /// <param name="identity">The refused result of <see cref="MachineIdentity.Resolve"/>.</param>
        public MachineIdentityRefusedException(MachineIdentityResult identity)
            : base("Device refused (code " + identity.SupportCode + ").")
        {
            RefusalCode = identity.RefusalCode ?? string.Empty;
            SupportCode = identity.SupportCode ?? string.Empty;
            ReadFailure = identity.ReadFailure;
        }

        /// <summary>Gets the stable refusal code (<c>UUID_*</c>), for logs only.</summary>
        public string RefusalCode { get; }

        /// <summary>Gets the customer-visible support code (<c>AR-xx</c>).</summary>
        public string SupportCode { get; }

        /// <summary>Gets the technical read failure when the UUID could not be read, for logs only.</summary>
        public string? ReadFailure { get; }
    }
}
