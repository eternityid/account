using System;
using Accounts.Configurations;
using Microsoft.Extensions.Options;
using Novell.Directory.Ldap;


namespace Accounts.Services
{
    public class ActiveDirectoryUserService
    {
        private readonly LdapConfiguration _ldapConfiguration;

        public ActiveDirectoryUserService(IOptions<LdapConfiguration> ldapConfig)
        {
            _ldapConfiguration = ldapConfig.Value;
        }

        public bool ValidateCredential(string username, string password)
        {
            if (_ldapConfiguration.Domain == null) return false;

            const int ldapVersion = LdapConnection.Ldap_V3;
            var conn = new LdapConnection();

            try
            {
                conn.Connect(_ldapConfiguration.Host, _ldapConfiguration.Port);
                conn.Bind(ldapVersion, $"{_ldapConfiguration.Domain}\\{username}", password);
                conn.Disconnect();
            }
            catch (LdapException)
            {
                // TODO: Log exception. Maybe catch specific exception (message about username/password not correct)
                return false;
            }

            return true;
        }
    }
}