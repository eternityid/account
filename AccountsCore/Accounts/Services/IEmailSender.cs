using System.Threading.Tasks;

namespace Accounts.Services
{
    public interface IEmailSender
    {
        Task SendEmailAsync(string email, string subject, string message, string clientId);
    }
}
