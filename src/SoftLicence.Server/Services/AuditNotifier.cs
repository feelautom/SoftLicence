namespace SoftLicence.Server.Services
{
    public class AuditNotifier
    {
        public event Action? OnNewLog;

        public void NotifyNewLog()
        {
            OnNewLog?.Invoke();
        }
    }
}
