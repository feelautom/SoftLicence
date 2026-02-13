using System;
using System.Timers;

namespace SoftLicence.Server.Services
{
    public class ToastService : IDisposable
    {
        public event Action<string, string, ToastLevel>? OnShow;
        public event Action? OnHide;
        private System.Timers.Timer? _timer;

        public void ShowSuccess(string message) => Show(message, "Succès", ToastLevel.Success);
        public void ShowError(string message) => Show(message, "Erreur", ToastLevel.Error);
        public void ShowInfo(string message) => Show(message, "Info", ToastLevel.Info);

        private void Show(string message, string title, ToastLevel level)
        {
            OnShow?.Invoke(message, title, level);
            StartTimer();
        }

        private void StartTimer()
        {
            _timer?.Stop();
            _timer?.Dispose();
            _timer = new System.Timers.Timer(3000);
            _timer.Elapsed += (s, e) => { OnHide?.Invoke(); _timer.Dispose(); };
            _timer.AutoReset = false;
            _timer.Start();
        }

        public void Dispose() => _timer?.Dispose();
    }

    public enum ToastLevel { Info, Success, Error }
}
