using IdentityServer4;
using IdentityServer4.Models;
using System.Collections.Generic;

namespace Accounts
{

	public static class ClientsConfig
	{
		public static IEnumerable<Client> GetClients()
		{
			var surveyToolClientUrls = GetSurveyToolClientUrls();
			var hrToolClientUrls = GetHrToolClientUrls();
			var hiredNowClientUrls = GetHiredNowClientUrls();

			return new[]
			{
				new Client
				{
					Enabled = true,
					ClientName = "Responsive Insight",
					ClientId = "ResponsiveInsight",
					AllowedGrantTypes = GrantTypes.Implicit,
					AllowAccessTokensViaBrowser = true,
					RequireConsent = false,
                    //IdentityTokenLifetime = 600, //Commented out: Added for testing
                    //AccessTokenLifetime = 71, //Commented out: Added for testing (to not have to wait too long for expiry)
                    RedirectUris = GetRedirectUris(surveyToolClientUrls),
					PostLogoutRedirectUris = surveyToolClientUrls,
					AllowedScopes = new List<string>
					{
						"openid",
						"profile",
						"roles",
						ResourcesConfig.UserManagementScopeName,
						ResourcesConfig.SurveyInternalApiName
					}
				},
				new Client
				{
					Enabled = true,
					ClientName = "Responsive HR",
					ClientId = "ResponsiveHR",
					AllowedGrantTypes = GrantTypes.Implicit,
					AllowAccessTokensViaBrowser = true,
					RequireConsent = false,
                    //IdentityTokenLifetime = 600, //Commented out: Added for testing
                    //AccessTokenLifetime = 71, //Commented out: Added for testing (to not have to wait too long for expiry)
                    RedirectUris = GetRedirectUris(hrToolClientUrls),
					PostLogoutRedirectUris = hrToolClientUrls,
					AllowedScopes = new List<string>
					{
						"openid",
						"profile",
						"roles",
						ResourcesConfig.HRToolInternalApiName
					}
				},
				new Client
				{
					Enabled = true,
					ClientName = "Responsive HR API",
					ClientId = "ResponsiveHR.API",
					AllowedGrantTypes = GrantTypes.ClientCredentials,
					ClientSecrets = { new Secret("GADNcEsH87JeKB3k".Sha256()) },
					AllowedScopes = new List<string> {
						ResourcesConfig.UserManagementScopeName,
						ResourcesConfig.HRToolInternalApiName
					}
				},
				new Client
				{
					Enabled = true,
					ClientName = "HiredNow",
					ClientId = "HiredNow",
					AllowedGrantTypes = GrantTypes.Implicit,
					AllowAccessTokensViaBrowser = true,
					RequireConsent = false,
                    //IdentityTokenLifetime = 600, //Commented out: Added for testing
                    //AccessTokenLifetime = 71, //Commented out: Added for testing (to not have to wait too long for expiry)
                    RedirectUris = GetRedirectUris(hiredNowClientUrls),
					PostLogoutRedirectUris = hiredNowClientUrls,
					AllowedScopes = new List<string>
					{
						"openid",
						"profile",
						"roles",
						ResourcesConfig.HRToolInternalApiName
					}
				},
				new Client
				{
					Enabled = true,
					ClientName = "Penetrace",
					ClientId = "Penetrace",
					AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,

					ClientSecrets =
					{
						new Secret("secret".Sha256())
					},
					AllowedScopes = { ResourcesConfig.RequestPasswordlessUrlScopeName, ResourcesConfig.SurveyInternalApiName }
				}
			};
		}

		public static List<string> GetSurveyToolClientUrls()
		{
			return new List<string>
			{
				"https://localhost:44301/app/",
				"http://localhost:4001/app/",
				"http://localhost:4000/",
				"https://surveytool.orientsoftware.net/",
				"https://surveytool.orientsoftware.net/e2e/",
				"http://surveytool.orientsoftware.net/",
				"http://surveytool.orientsoftware.net/e2e/",
				"https://app-surveytool.orientsoftware.asia/",
				"https://app-surveytool-e2e.orientsoftware.asia/",
				"https://systemtest-responsiveinsight-app.azurewebsites.net/",
				"https://systemtest-responsiveinsight-app-staging.azurewebsites.net/",
                "https://production-responsiveinsight-app.azurewebsites.net/",
                "https://production-responsiveinsight-app-staging.azurewebsites.net/",
                "https://app.responsiveinsight.com/",
				"https://www.responsiveinsight.com/"
            };
		}

		public static List<string> GetHrToolClientUrls()
		{
			return new List<string>
			{
				"http://localhost:34214/app/",
				"http://localhost:4600/app/",
				"http://localhost:4601/",
				"https://hrtool-rel.orientsoftware.net/",
				"https://hr.orientsoftware.net/",
				"https://app.responsivehr.com/",
				"https://production-responsivehr-www.azurewebsites.net/"
			};
		}

		public static List<string> GetHiredNowClientUrls()
		{
			return new List<string>
			{
				"http://localhost:34214/app/",
				"http://localhost:4600/app/",
				"http://localhost:4601/",
				"https://employer.hirednow.com.my/"
			};
		}

		private static List<string> GetRedirectUris(List<string> clientUrls)
		{
			var ret = new List<string>();
			foreach (var clientUrl in clientUrls)
			{
				ret.Add(clientUrl + "#/login/");
				ret.Add(clientUrl + "silent_renew.html");
			}
			return ret;
		}

	}
}