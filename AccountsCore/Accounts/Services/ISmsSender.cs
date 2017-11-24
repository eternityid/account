using System.Threading.Tasks;

namespace Accounts.Services
{
    public interface ISmsSender
    {
        Task SendSmsAsync(string number, string message);
    }
}
