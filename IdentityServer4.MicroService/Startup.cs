using System;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Globalization;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using Swashbuckle.AspNetCore.Swagger;
using IdentityServer4.MicroService.Data;
using IdentityServer4.MicroService.Services;
using IdentityServer4.MicroService.Tenant;
using ApiTracker;
using static IdentityServer4.MicroService.AppConstant;


namespace IdentityServer4.MicroService
{
    public class Startup
    {
        IHostingEnvironment _env;

        public IConfigurationRoot Configuration { get; }

        public Startup(IHostingEnvironment env)
        {
            _env = env;

            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true);
            
            builder.AddEnvironmentVariables();

            var config = builder.Build();

            builder.AddAzureKeyVault($"https://{config["AzureKeyVault:Vault"]}.vault.azure.cn/",
                config["AzureKeyVault:ClientId"],
                config["AzureKeyVault:ClientSecret"]);

            Configuration = builder.Build();
        }

        public async Task<string> GetToken(string authority, string resource, string scope)
        {
            var clientCred = new ClientCredential(
                Configuration["AzureKeyVault:ClientId"],
                Configuration["AzureKeyVault:ClientSecret"]);

                var authContext = new AuthenticationContext(authority, true);

                var result = await authContext.AcquireTokenAsync(resource, clientCred);

                if (result == null)
                    throw new InvalidOperationException("Failed to obtain the JWT token");

                return result.AccessToken;
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            #region Cors
            services.AddCors(options =>
                {
                    options.AddPolicy("default", builder =>
                    {
                        builder.AllowAnyHeader();
                        builder.AllowAnyMethod();
                        builder.AllowAnyOrigin();
                        builder.AllowCredentials();
                    });
                }); 
            #endregion

            var assemblyName = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;

            var connSection = Configuration.GetSection("ConnectionStrings");

            var connectionString = connSection["DBConnection"];

            #region DbContext
            // Add TenantDbContext.
            services.AddDbContext<TenantDbContext>(options =>
                options.UseSqlServer(connectionString));

            // Add ApplicationDbContext.
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(connectionString));

            services.AddIdentity<AppUser, AppRole>(opts =>
            {
                opts.SignIn.RequireConfirmedEmail = true;
                //opts.SignIn.RequireConfirmedPhoneNumber = true;
            })
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();
            #endregion

            #region 联合登陆
            // https://docs.microsoft.com/zh-cn/aspnet/core/security/authentication/social/microsoft-logins
            // https://docs.microsoft.com/zh-cn/aspnet/core/security/authentication/social/facebook-logins
            // https://docs.microsoft.com/zh-cn/aspnet/core/security/authentication/social/google-logins
            // https://docs.microsoft.com/zh-cn/aspnet/core/security/authentication/social/twitter-logins
            services.AddAuthentication(options => {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddWeixin(x=> {
                x.ClientId = Configuration["Authentication:Weixin:ClientId"];
                x.ClientSecret = Configuration["Authentication:Weixin:ClientSecret"];
            })
            .AddWeibo(x=> {
                x.ClientId = Configuration["Authentication:Weibo:ClientId"];
                x.ClientSecret = Configuration["Authentication:Weibo:ClientSecret"];
            })
            .AddGitHub(x=> {
                x.ClientId = Configuration["Authentication:GitHub:ClientId"];
                x.ClientSecret = Configuration["Authentication:GitHub:ClientSecret"];
            })
            .AddQQ(x=> {
                x.ClientId = Configuration["Authentication:QQ:ClientId"];
                x.ClientSecret = Configuration["Authentication:QQ:ClientSecret"];
            })
            .AddFacebook(x => {
                x.AppId = Configuration["Authentication:Facebook:ClientId"];
                x.AppSecret = Configuration["Authentication:Facebook:ClientSecret"];
            })
            .AddTwitter(x => {
                x.ConsumerKey = Configuration["Authentication:Twitter:ClientId"];
                x.ConsumerSecret = Configuration["Authentication:Twitter:ClientSecret"];
            })
            .AddGoogle(x => {
                x.ClientId = Configuration["Authentication:Google:ClientId"];
                x.ClientSecret = Configuration["Authentication:Google:ClientSecret"];
            })
            .AddMicrosoftAccount(x => {
                x.ClientId = Configuration["Authentication:Microsoft:ClientId"];
                x.ClientSecret = Configuration["Authentication:Microsoft:ClientSecret"];
            })
            .AddIdentityServerAuthentication(AppAuthenScheme, isAuth =>
                {
                    isAuth.Authority = "https://" + Configuration["IdentityServer"];
                    isAuth.ApiName = assemblyName.ToLower();
                    isAuth.RequireHttpsMetadata = true;
                });
            #endregion

            // Common Cache Service, for now, no need
            //services.AddDistributedRedisCache(options => {
            //    options.Configuration = Configuration["ConnectionStrings:RedisConnection"];
            //    options.InstanceName = assemblyName;
            //});

            #region Mvc + localization
            // Configure supported cultures and localization options
            services.AddLocalization(options => options.ResourcesPath = "Resources");
            services.Configure<RequestLocalizationOptions>(options =>
            {
                var supportedCultures = new[]
                {
                    new CultureInfo("en-US"),
                    new CultureInfo("zh-CN"),
                };

                // State what the default culture for your application is. This will be used if no specific culture
                // can be determined for a given request.
                options.DefaultRequestCulture = new RequestCulture("zh-CN", "zh-CN");

                // You must explicitly state which cultures your application supports.
                // These are the cultures the app supports for formatting numbers, dates, etc.
                options.SupportedCultures = supportedCultures;

                // These are the cultures the app supports for UI strings, i.e. we have localized resources for.
                options.SupportedUICultures = supportedCultures;

                // You can change which providers are configured to determine the culture for requests, or even add a custom
                // provider with your own logic. The providers will be asked in order to provide a culture for each request,
                // and the first to provide a non-null result that is in the configured supported cultures list will be used.
                // By default, the following built-in providers are configured:
                // - QueryStringRequestCultureProvider, sets culture via "culture" and "ui-culture" query string values, useful for testing
                // - CookieRequestCultureProvider, sets culture via "ASPNET_CULTURE" cookie
                // - AcceptLanguageHeaderRequestCultureProvider, sets culture via the "Accept-Language" request header
                //options.RequestCultureProviders.Insert(0, new CustomRequestCultureProvider(async context =>
                //{
                //  // My custom request culture logic
                //  return new ProviderCultureResult("en");
                //}));
            });

            //https://github.com/Microsoft/aspnet-api-versioning/wiki/API-Documentation#aspnet-core
            services.AddMvcCore().AddVersionedApiExplorer(o => o.GroupNameFormat = "'v'VVV");

            services.AddMvc(options =>
            {
                // for external authentication,maybe not need
                //options.SslPort = 44314;
                // for production, microsoft authentication need https
                options.Filters.Add(new RequireHttpsAttribute());
            })
            .AddViewLocalization(LanguageViewLocationExpanderFormat.Suffix)
            .AddDataAnnotationsLocalization()
            //https://stackoverflow.com/questions/34753498/self-referencing-loop-detected-in-asp-net-core
            .AddJsonOptions(options =>
            {
                options.SerializerSettings.ContractResolver = new CamelCasePropertyNamesContractResolver();
                options.SerializerSettings.ReferenceLoopHandling = ReferenceLoopHandling.Ignore;
            });

            services.AddApiVersioning(o => {
                o.AssumeDefaultVersionWhenUnspecified = true;
                o.ReportApiVersions = true;
            });
            #endregion

            #region SwaggerGen
            services.AddSwaggerGen(c =>
                {
                   // c.TagActionsBy(x => x.RelativePath.Split('/')[0]);

                    c.AddSecurityDefinition("SubscriptionKey",
                        new ApiKeyScheme()
                        {
                            Name = "Ocp-Apim-Subscription-Key",
                            Type = "apiKey",
                            In = "header",
                            Description = "从开放平台申请的Subscription Key，从网关调用接口时必需传入。",
                        });

                    c.AddSecurityDefinition("AccessToken",
                        new ApiKeyScheme()
                        {
                            Name = "Authorization",
                            Type = "apiKey",
                            In = "header",
                            Description = "从身份认证中心颁发的Token，根据接口要求决定是否传入。",
                        });

                    c.AddSecurityDefinition("OAuth2",
                        new OAuth2Scheme()
                        {
                            Type = "oauth2",
                            Flow = "accessCode",
                            AuthorizationUrl = "https://"+ Configuration["IdentityServer"] + "/connect/authorize",
                            TokenUrl = "https://"+ Configuration["IdentityServer"] + "/connect/token",
                            Description = "勾选授权范围，获取Token",
                            Scopes = new Dictionary<string, string>(){
                            { "openid","用户标识" },
                            { "profile","用户资料" },
                            { "campaign.core.apis.all","Game 2.0所有接口权限"},
                            { "campaign.core.identity.all","Identity所有接口权限"}
                            }
                        });

                    c.OperationFilter<FormFileOperationFilter>();

                    var provider = services.BuildServiceProvider()
                                   .GetRequiredService<IApiVersionDescriptionProvider>();

                    foreach (var description in provider.ApiVersionDescriptions)
                    {
                        c.SwaggerDoc(description.GroupName, new Info
                        {
                            Title = assemblyName + description.ApiVersion,
                            Version = description.ApiVersion.ToString(),
                            License = new License()
                            {
                                Name = "MIT",
                                Url = "https://spdx.org/licenses/MIT.html"
                            },
                            Contact = new Contact()
                            {
                                Url = "https://portal.ixingban.com",
                                Name = "Campaign - 开放平台",
                                Email = "wangzhen@jixiuapp.com"
                            },
                            Description = "Swagger document"
                        });
                    }
                });
            #endregion

            services.Configure<ConnectionStrings>(connSection);
            services.Configure<SmsSenderOptions>(Configuration.GetSection("MessageSender:sms"));
            services.Configure<EmailSenderOptions>(Configuration.GetSection("MessageSender:Email"));

            // Add application services.
            services.AddTransient<IEmailSender, EmailSender>();
            services.AddTransient<ISmsSender, SmsSender>();
            services.AddTransient(typeof(SqlService));
            services.AddTransient(typeof(AzureStorageService));
            //services.AddTransient<AzureApiManagementServices>();
            services.AddSingleton<RedisService>();
            services.AddSingleton<TenantService>();
            services.AddSingleton<SwaggerCodeGenService>();

            #region 权限定义
            services.AddAuthorization(options =>
                {
                    #region Client的权限策略
                    options.AddPolicy(ClientScopes.Approve,
                        policy => policy.RequireClaim(ClaimTypes.ClientScope,
                        ClientScopes.Approve, ClientScopes.All));

                    options.AddPolicy(ClientScopes.Create,
                        policy => policy.RequireClaim(ClaimTypes.ClientScope,
                        ClientScopes.Create, ClientScopes.All));

                    options.AddPolicy(ClientScopes.Delete,
                        policy => policy.RequireClaim(ClaimTypes.ClientScope,
                        ClientScopes.Delete, ClientScopes.All));

                    options.AddPolicy(ClientScopes.Read,
                        policy => policy.RequireClaim(ClaimTypes.ClientScope,
                        ClientScopes.Read, ClientScopes.All));

                    options.AddPolicy(ClientScopes.Reject,
                        policy => policy.RequireClaim(ClaimTypes.ClientScope,
                        ClientScopes.Reject, ClientScopes.All));

                    options.AddPolicy(ClientScopes.Update,
                        policy => policy.RequireClaim(ClaimTypes.ClientScope,
                        ClientScopes.Update, ClientScopes.All));

                    options.AddPolicy(ClientScopes.Upload,
                       policy => policy.RequireClaim(ClaimTypes.ClientScope,
                       ClientScopes.Upload, ClientScopes.All));
                    #endregion

                    #region User的权限策略
                    options.AddPolicy(UserPermissions.Approve,
                        policy => policy.RequireClaim(ClaimTypes.UserPermission,
                        UserPermissions.Approve, UserPermissions.All));

                    options.AddPolicy(UserPermissions.Create,
                        policy => policy.RequireClaim(ClaimTypes.UserPermission,
                        UserPermissions.Create, UserPermissions.All));

                    options.AddPolicy(UserPermissions.Delete,
                        policy => policy.RequireClaim(ClaimTypes.UserPermission,
                        UserPermissions.Delete, UserPermissions.All));

                    options.AddPolicy(UserPermissions.Read,
                        policy => policy.RequireClaim(ClaimTypes.UserPermission,
                        UserPermissions.Read, UserPermissions.All));

                    options.AddPolicy(UserPermissions.Reject,
                        policy => policy.RequireClaim(ClaimTypes.UserPermission,
                        UserPermissions.Reject, UserPermissions.All));

                    options.AddPolicy(UserPermissions.Update,
                        policy => policy.RequireClaim(ClaimTypes.UserPermission,
                        UserPermissions.Update, UserPermissions.All));

                    options.AddPolicy(UserPermissions.Upload,
                       policy => policy.RequireClaim(ClaimTypes.UserPermission,
                       UserPermissions.Upload, UserPermissions.All));
                    #endregion
                });
            #endregion

            #region IdentityServer
            // Adds IdentityServer
            // Use Let's encryp Certificate
            //var certPath = _env.WebRootPath + "\\campaigncore.pfx";
            //var cert = new X509Certificate2(certPath, "www.jixiuapp.com",
            //    X509KeyStorageFlags.MachineKeySet |
            //    X509KeyStorageFlags.PersistKeySet |
            //    X509KeyStorageFlags.Exportable);

            X509Certificate2 cert = null;
            using (var kvClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(GetToken)))
            {
                // 有公钥的证书
                var CertificateWithPubKey = kvClient.GetCertificateAsync(
                    $"https://{Configuration["AzureKeyVault:Vault"]}.vault.azure.cn",
                    Configuration["AzureKeyVault:Certificate:Name"],
                    Configuration["AzureKeyVault:Certificate:Version"]).Result;

                // 有私钥的证书
                var CertificateWithPrivateKey = kvClient.GetSecretAsync(CertificateWithPubKey.SecretIdentifier.Identifier).Result;

                // 默认用的是UserKeySet，但在Azure Web App里需要MachineKeySet
                cert = new X509Certificate2(Convert.FromBase64String(CertificateWithPrivateKey.Value), 
                    string.Empty, 
                    X509KeyStorageFlags.MachineKeySet);
            }

            var IdentityServerStore = new Action<DbContextOptionsBuilder>(x =>
            x.UseSqlServer(connectionString,
            opts => opts.MigrationsAssembly(assemblyName)));

            services.AddIdentityServer(config =>
            {
                // keep same Issuer for banlancer
                config.IssuerUri = "https://www.ixingban.com";

                // config.PublicOrigin = "https://openapis.ixingban.com/ids";
                // config.Discovery.CustomEntries.Add("custom_endpoint", "~/api/custom");
            })
              .AddSigningCredential(cert)
              .AddCustomAuthorizeRequestValidator<TenantAuthorizeRequestValidator>()
              .AddCustomTokenRequestValidator<TenantTokenRequestValidator>()
              .AddConfigurationStore(builder => builder.ConfigureDbContext = IdentityServerStore)
              .AddOperationalStore(builder => builder.ConfigureDbContext = IdentityServerStore)
              .AddAspNetIdentity<AppUser>();
            #endregion

            services.Configure<ApiTrackerSetting>(Configuration.GetSection("ApiTrackerSetting"));

            services.AddScoped<ApiTracker.ApiTracker>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app,
            IHostingEnvironment env,
            ILoggerFactory loggerFactory,
            IApiVersionDescriptionProvider provider)
        {
            InitialDBConfig.InitializeDatabase(app);

            app.UseMutitenancy();

            app.UseCors("default");

            #region Localization
            var locOptions = app.ApplicationServices.GetService<IOptions<RequestLocalizationOptions>>();
            app.UseRequestLocalization(locOptions.Value);
            #endregion

            if (env.IsDevelopment())
            {
                loggerFactory.AddConsole(Configuration.GetSection("Logging"));
                loggerFactory.AddDebug();
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseAuthentication();

            app.UseIdentityServer();

            app.UseMvcWithDefaultRoute();

            #region swagger
            app.UseSwagger(x =>
                {
                    x.PreSerializeFilters.Add((doc, req) =>
                    {
                        doc.Schemes = new[] { "https" };

                        doc.Host = Configuration["IdentityServer"];
                    });
                });
            #endregion

            app.UseSwaggerUI(c =>
            {
                foreach (var description in provider.ApiVersionDescriptions)
                {
                    c.SwaggerEndpoint(
                        $"/swagger/{description.GroupName}/swagger.json",
                        description.GroupName.ToUpperInvariant());

                    c.ConfigureOAuth2("test", "1", string.Empty, "API测试专用");
                }

                c.DocExpansion("none");
            });   
        }
    }
}
