using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Accounts.Data;
using Accounts.Models;
using Accounts.Services;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using Accounts.Configurations;
using IdentityServer4.AspNetIdentity;
using IdentityServer4.Services;
using IdentityServer4.Validation;
using System.Diagnostics;

namespace Accounts
{
	public class Startup
	{
		private string _contentRootPath;

		public Startup(IHostingEnvironment env)
		{
			var builder = new ConfigurationBuilder()
				.SetBasePath(env.ContentRootPath)
				.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
				.AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true);

			if (env.IsDevelopment())
			{
				// For more details on using the user secret store see http://go.microsoft.com/fwlink/?LinkID=532709
				builder.AddUserSecrets<Startup>();
			}
			_contentRootPath = env.ContentRootPath;
			builder.AddEnvironmentVariables();
			Configuration = builder.Build();
		}

		public IConfigurationRoot Configuration { get; }

		// This method gets called by the runtime. Use this method to add services to the container.
		public void ConfigureServices(IServiceCollection services)
		{
			// Add framework services.
			services.AddDbContext<ApplicationDbContext>(options =>
				options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));

			services.AddIdentity<ApplicationUser, IdentityRole>(config =>
				{
					config.SignIn.RequireConfirmedEmail = true;
				})
				.AddEntityFrameworkStores<ApplicationDbContext>()
				.AddDefaultTokenProviders();
			services.AddOptions();
			services.Configure<LdapConfiguration>(Configuration.GetSection("Ldap"));
			services.Configure<SmtpConfiguration>(Configuration.GetSection("Smtp"));

			services.AddCors();
			services.AddMvc();

			services.AddAuthorization(options =>
			{
				options.AddPolicy("UserManagement",
							policy => policy
							  .RequireClaim("Scope", ResourcesConfig.UserManagementScopeName));
				options.AddPolicy("Passwordless",
							policy => policy
							  .RequireRole("PenetraceUsers")
							  .RequireClaim("Scope", ResourcesConfig.RequestPasswordlessUrlScopeName));
			});

			// Add application services.
			services.AddTransient<IEmailSender, AuthMessageSender>();
			services.AddTransient<ISmsSender, AuthMessageSender>();
			var certificate = new X509Certificate2(Path.Combine(_contentRootPath, "idsrv4test.pfx"), "idsrv3test");
            services.AddIdentityServer(options => { options.IssuerUri = Configuration["AuthorityUrl"]; })
				.AddSigningCredential(certificate)
				.AddInMemoryPersistedGrants()
				.AddInMemoryIdentityResources(ResourcesConfig.GetIdentityResources())
				.AddInMemoryApiResources(ResourcesConfig.GetApiResources())
				.AddInMemoryClients(ClientsConfig.GetClients())
				.AddAspNetIdentity<ApplicationUser>();

			services.AddTransient<ActiveDirectoryUserService>();
			services.AddTransient<IProfileService, AspNetIdentityProfileService>();
			services.AddTransient<IResourceOwnerPasswordValidator, ResourceOwnerPasswordValidator>();
			services.AddTransient<SignInServiceWithActiveDirectorySupport>();
			services.AddTransient<UserService>();
		}

		// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
		public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
		{
			loggerFactory.AddConsole(Configuration.GetSection("Logging"));
			loggerFactory.AddDebug();

			if (env.IsDevelopment())
			{
				app.UseDeveloperExceptionPage();
				app.UseDatabaseErrorPage();

				// Browser Link is not compatible with Kestrel 1.1.0
				// For details on enabling Browser Link, see https://go.microsoft.com/fwlink/?linkid=840936
				// app.UseBrowserLink();
			}
			else
			{
				app.UseExceptionHandler("/Home/Error");
			}

			app.UseCors(builder =>
			{
				builder.AllowAnyHeader();
				builder.AllowAnyMethod();
				builder.AllowAnyOrigin();
				builder.AllowCredentials();
			});

			app.UseStaticFiles();

			app.UseIdentity();
			app.UseIdentityServer();

			// Add external authentication middleware below. To configure them please see http://go.microsoft.com/fwlink/?LinkID=532715
			//app.UseGoogleAuthentication(new GoogleOptions
			//{
			//    AuthenticationScheme = "Google",
			//    SignInScheme = "Identity.External", // this is the name of the cookie middleware registered by UseIdentity()
			//    ClientId = "998042782978-s07498t8i8jas7npj4crve1skpromf37.apps.googleusercontent.com",
			//    ClientSecret = "HsnwJri_53zn7VcO1Fm7THBb",
			//});

			app.UseIdentityServerAuthentication(new IdentityServerAuthenticationOptions
			{
				Authority = Configuration["AuthorityUrl"],
				RequireHttpsMetadata = false,

				ApiName = ResourcesConfig.UserManagementApiName,
				AllowedScopes = new[] { ResourcesConfig.UserManagementScopeName, ResourcesConfig.RequestPasswordlessUrlScopeName }
			});

			app.UseMvc(routes =>
			{
				routes.MapRoute(
					name: "default",
					template: "{controller=Home}/{action=Index}/{id?}");
			});

		    using (var serviceScope = app.ApplicationServices.GetRequiredService<IServiceScopeFactory>().CreateScope())
		    {
		        var context = serviceScope.ServiceProvider.GetService<ApplicationDbContext>();
		        context.Database.Migrate();
		        DataSeeder.Initialize(serviceScope.ServiceProvider);
            }
        }
	}
}
