using System.Threading.Tasks;

namespace TwoFactorAuth.Services
{
    public interface ISmsSender
    {
        Task SendSmsAsync(string number, string message);
    }
}
