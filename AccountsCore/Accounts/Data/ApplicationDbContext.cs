using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Accounts.Models;

namespace Accounts.Data
{
    //dotnet ef migrations add AddUserProperties
    //dotnet ef migrations remove
    //dotnet ef database update
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            // Customize the ASP.NET Identity model and override the defaults if needed.
            // For example, you can rename the ASP.NET Identity table names and more.
            // Add your customizations after calling base.OnModelCreating(builder);
        }
    }
    /*

INSERT INTO [AccountsCore].[dbo].[AspNetUsers]
    (
[Id]
,[AccessFailedCount]
,[ConcurrencyStamp]
,[Email]
,[EmailConfirmed]
,[NormalizedEmail]
,[NormalizedUserName]
,[LockoutEnabled]
,[PasswordHash]
,[SecurityStamp]
,[PhoneNumber]
,[PhoneNumberConfirmed]
,[TwoFactorEnabled]
,[UserName]
,[FirstName]
,[LastName]
,[IsActive]
,[CreatedDate]
,[IsAccountInActiveDirectory]
)
(SELECT 
[Id]
,[AccessFailedCount]
,LOWER(NEWID())
,[Email]
,[EmailConfirmed]
,UPPER([Email])
,UPPER([UserName])
,[LockoutEnabled]
,[PasswordHash]
,[SecurityStamp]
,[PhoneNumber]
,[PhoneNumberConfirmed]
,[TwoFactorEnabled]
,[UserName]
,[FirstName]
,[LastName]
,[IsActive]
,[CreatedDate]
,ISNULL ( [IsAccountInActiveDirectory] , 0)
    FROM[Accounts].[dbo].[Users])


INSERT INTO [AccountsCore].[dbo].[AspNetRoles]
([Id]
,[Name],
[NormalizedName])
SELECT
[Id]
,[Name],
UPPER(Name)
  FROM [Accounts].[dbo].[AspNetRoles]



INSERT INTO [AccountsCore].[dbo].[AspNetUserRoles]
([UserId]
,[RoleId])
SELECT
[UserId]
,[RoleId]
FROM [Accounts].[dbo].[AspNetUserRoles] as userroles 
JOIN [Accounts].[dbo].[Users] as users ON userroles.UserId = users.Id


     */
}
