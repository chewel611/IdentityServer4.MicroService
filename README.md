# IdentityServer4.MicroService

IdentityServer4.MicroService是一个免费的，开放源代码的微服务框架。基于IdentityServer4与Azure API Management构建。 目前主要由[seven1986](https://github.com/seven1986)创建和维护，它集成了IdentityServer4（令牌颁发、身份验证、单点登录和API访问控制所需的所有协议实现和扩展点），Azure API Management（集中管理所有API，配置访问策略、频次，生成文档与SDK）和其他主流技术。 


### Acknowledgements
  IdentityServer4.MicroService is built using the following great open source projects
  
* [IdentityServer4](https://github.com/IdentityServer)
* [ASP.NET Core](https://github.com/aspnet)
* [Azure API Management](https://azure.microsoft.com/zh-cn/services/api-management/)
* [Swagger Codegen](https://github.com/swagger-api/swagger-codegen)


#### For run this project requires

* Azure Key Valut (统一配置、加密证书保存等)
* Azure Redis （缓存）
* Azure SqlServer （持久还存储，用户、Client、ApiResources等）
* Azure Storage （图片、二进制文件、队列）
* Email & Message （Send Cloud）
* Elastic Search （存储请求的日志）