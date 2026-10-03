namespace SoftLicence.SDK
{
    /// <summary>
    /// Licence hardware identifier of the current machine.
    /// </summary>
    /// <remarks>
    /// TKT-001277 (29/09/2026): the identifier is derived from the SMBIOS system UUID only, through
    /// <see cref="MachineIdentity"/>. The former five-component calculation (processor, board, BIOS, disk, machine
    /// name) and its legacy/stable variants were removed; there is a single identifier and a single calculation.
    /// </remarks>
    public static class HardwareInfo
    {
        /// <summary>
        /// Returns the 16-character uppercase hexadecimal licence identifier derived from this machine's system UUID.
        /// </summary>
        /// <returns>The licence hardware identifier.</returns>
        /// <exception cref="MachineIdentityRefusedException">
        /// The system UUID is absent, unreadable, malformed or a known generic value; no identifier is invented.
        /// </exception>
        public static string GetHardwareId()
        {
            var identity = MachineIdentity.Resolve();
            if (!identity.IsAccepted)
                throw new MachineIdentityRefusedException(identity);
            return identity.HardwareId!;
        }
    }
}
