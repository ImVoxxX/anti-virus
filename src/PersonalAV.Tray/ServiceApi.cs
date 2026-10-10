using System.IO;
using System.Windows;
using PersonalAV.Core.Ipc;

namespace PersonalAV.Tray;

internal static class ServiceApi
{
    /// <summary>Sends a request; on a connection failure shows an error (unless quiet) and returns null.</summary>
    public static async Task<PipeResponse?> TrySend(PipeRequest request, bool quiet = false)
    {
        try
        {
            return await PipeClient.RequestAsync(request, TimeSpan.FromSeconds(2));
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or IOException or TimeoutException)
        {
            if (!quiet)
            {
                MessageBox.Show(ex.Message, "PersonalAV", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            return null;
        }
    }
}
