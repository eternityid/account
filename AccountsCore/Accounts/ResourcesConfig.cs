using IdentityModel;
using IdentityServer4.Models;
using System.Collections.Generic;

namespace Accounts
{
    public static class ResourcesConfig
    {
        // API names
        public readonly static string UserManagementApiName = "userManagementApi";
        public readonly static string SurveyInternalApiName = "surveyInternalApi";
        public readonly static string HRToolInternalApiName = "hrtoolInternalApi";

        //Scope names
        public readonly static string UserManagementScopeName = "userManagement";
        public readonly static string RequestPasswordlessUrlScopeName = "requestPasswordlessUrl";

        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Address(),
                new IdentityResources.Email(),
                new IdentityResources.Phone(),
                new IdentityResource("roles", new [] { JwtClaimTypes.Role })
            };
        }

        public static IEnumerable<ApiResource> GetApiResources()
        {
            return new List<ApiResource>
            {
                new ApiResource(UserManagementApiName, "User Management API", new [] { JwtClaimTypes.Role })
                {
                    Scopes = new [] {
                        new Scope(UserManagementScopeName, "Manage users"),
                        new Scope(RequestPasswordlessUrlScopeName, "Request passwordless url for certain users")
                    }
                }
                ,
                new ApiResource(SurveyInternalApiName, "Survey Internal REST API", new [] { JwtClaimTypes.Role, JwtClaimTypes.Email, JwtClaimTypes.GivenName, JwtClaimTypes.FamilyName }),
                new ApiResource(HRToolInternalApiName, "HRTool Internal REST API", new [] { JwtClaimTypes.Role, JwtClaimTypes.PreferredUserName })
            };
        }

    }
}