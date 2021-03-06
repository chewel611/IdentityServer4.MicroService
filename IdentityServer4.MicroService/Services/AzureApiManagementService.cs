﻿using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace IdentityServer4.MicroService.Services
{
    public class AzureApiManagementAuthorizationServerEntity
    {
        public string id { get; set; }
        public string name { get; set; }
        public string description { get; set; }
        public string clientRegistrationEndpoint { get; set; }
        public string authorizationEndpoint { get; set; }
        public List<string> authorizationMethods { get; set; }
        public List<string> clientAuthenticationMethod { get; set; }
        public List<string> tokenBodyParameters { get; set; }
        public string tokenEndpoint { get; set; }
        public bool supportState { get; set; }
        public string defaultScope { get; set; }
        public List<string> grantTypes { get; set; }
        public List<string> bearerTokenSendingMethods { get; set; }
        public string clientId { get; set; }
        public string clientSecret { get; set; }
        public string resourceOwnerUsername { get; set; }
        public string resourceOwnerPassword { get; set; }
    }

    public class AzureApiManagementAuthorizationServers : AzureApiManagement
    {
        public AzureApiManagementAuthorizationServers(string _host,
            string _apiId,
            string _apiKey) : base(_host, _apiId, _apiKey)
        {
        }

        /// <summary>
        /// authorizationServers List
        /// </summary>
        /// <returns></returns>
        public async Task<AzureApiManagementEntities<AzureApiManagementAuthorizationServerEntity>> GetAsync()
        {
            var result = await _GetAsync("/authorizationServers");

            if (result.IsSuccessStatusCode)
            {
                var data = result.Content.ReadAsStringAsync().Result;

                var entities = JsonConvert.DeserializeObject<AzureApiManagementEntities<AzureApiManagementAuthorizationServerEntity>>(data);

                return entities;
            }

            else
            {
                return null;
            }
        }
    }

    public class AzureApiManagement
    {
        protected string host; 

        protected string apiId; 

        protected string apiKey;

        protected const string apiversion = "?api-version=2017-03-01";

        string _token { get; set; }

        DateTime tokenExpiry { get; set; }

        public AzureApiManagement(string _host,
            string _apiId,
            string _apiKey)
        {
            host = _host;
            apiId = _apiId;
            apiKey = _apiKey;
        }

        protected string token
        {
            get
            {
                if (string.IsNullOrEmpty(_token) ||
                    (tokenExpiry - DateTime.UtcNow).Days < 1)
                {
                    tokenExpiry = DateTime.UtcNow.AddDays(10);

                    using (var encoder = new HMACSHA512(Encoding.UTF8.GetBytes(apiKey)))
                    {
                        var dataToSign = apiId + "\n" + tokenExpiry.ToString("O", CultureInfo.InvariantCulture);

                        var hash = encoder.ComputeHash(Encoding.UTF8.GetBytes(dataToSign));

                        var signature = Convert.ToBase64String(hash);

                        var encodedToken = string.Format("SharedAccessSignature uid={0}&ex={1:o}&sn={2}", apiId, tokenExpiry, signature);

                        _token = encodedToken;
                    }
                }

                return _token;
            }
        }

        protected Task<HttpResponseMessage> _GetAsync(string url) => RequestAsync(url, HttpMethod.Get.Method);

        protected Task<HttpResponseMessage> _PutAsync(string url) => RequestAsync(url, HttpMethod.Put.Method);

        protected Task<HttpResponseMessage> _PostAsync(string url) => RequestAsync(url, HttpMethod.Post.Method);

        protected Task<HttpResponseMessage> _DeleteAsync(string url) => RequestAsync(url, HttpMethod.Delete.Method);

        protected Task<HttpResponseMessage> _HeadAsync(string url) => RequestAsync(url, HttpMethod.Head.Method);

        /// <summary>
        /// Request for Rest API Management
        /// </summary>
        /// <param name="path">path</param>
        /// <param name="method">/POST/PUT/GET,etc.</param>
        /// <param name="query">query parameters</param>
        /// <param name="content">http content</param>
        /// <param name="headerItems">request Headers</param>
        /// <param name="mediaType">request media type,default is application/json</param>
        /// <returns></returns>
        public async Task<HttpResponseMessage> RequestAsync(
           string path,
           string method,
           Dictionary<string, string> query = null,
           HttpContent content = null,
           Dictionary<string, string> headerItems = null,
           string mediaType = "application/json")
        {
            var client = new HttpClient();

            client.DefaultRequestHeaders.Add("Authorization", token);

            if (!string.IsNullOrWhiteSpace(mediaType))
            {
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue(mediaType));
            }

            if (headerItems != null)
            {
                foreach (var item in headerItems)
                {
                    client.DefaultRequestHeaders.Add(item.Key, item.Value);
                }
            }

            var requestUri = host + path + apiversion;

            if (query != null)
            {
                requestUri += "&" + string.Join("&", query.Select(x => $"{x.Key}={x.Value}").ToArray());
            }

            var requestMessage = new HttpRequestMessage(new HttpMethod(method), requestUri);

            if (content != null)
            {
                requestMessage.Content = content;
            }

            var response = await client.SendAsync(requestMessage);

            return response;
        }
    }

    public class AzureApiManagementApi : AzureApiManagement
    {
        // 默认的oAuth2 Server ID
        // 59efe9dd88269013808d7cf0

        // 默认的产品ID
        // 5a40b9b788269017d4082616

        AzureApiManagementProduct prdService;

        public AzureApiManagementApi(string _host,
            string _apiId,
            string _apiKey) : base(_host, _apiId, _apiKey)
        {
            prdService = new AzureApiManagementProduct(_host, _apiId, _apiKey);
        }

        /// <summary>
        /// Api List
        /// </summary>
        /// <returns></returns>
        public async Task<string> GetAsync()
        {
            var result = await _GetAsync("/apis");

            if (result.IsSuccessStatusCode)
            {
                return result.Content.ReadAsStringAsync().Result;
            }

            else
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// Api Detail
        /// </summary>
        /// <param name="aid">Api Id</param>
        /// <returns></returns>
        public async Task<string> DetailAsync(string aid)
        {
            var result = await _GetAsync($"/apis/{aid}");

            if (result.IsSuccessStatusCode)
            {
                return result.Content.ReadAsStringAsync().Result;
            }

            else
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// Check Api exists
        /// </summary>
        /// <param name="aid">Api id</param>
        /// <returns></returns>
        public async Task<bool> MetadataAsync(string aid)
        {
            var result = await RequestAsync($"/apis/{aid}", HttpMethod.Head.Method);

            return result.IsSuccessStatusCode;
        }

        /// <summary>
        /// Import or Update Api By swagger Url
        /// 1，check Api exists by {aid}
        /// 2，if exists update Api
        /// 3，if not exists import Api
        /// 4，if set authorizationServerId, update Api authenticationSettings
        /// </summary>
        /// <param name="aid">Api id, not null</param>
        /// <param name="suffix">Api service suffix, not null</param>
        /// <param name="swaggerUrl">Swagger doc url, not null</param>
        /// <param name="productId">Product id</param>
        /// <param name="authorizationServerId">authorize server Id</param>
        /// <param name="scope">scope</param>
        /// <param name="openid">openid</param>
        /// <returns></returns>
        public async Task<bool> ImportOrUpdateAsync(
            string aid,
            string suffix,
            string swaggerUrl,
            string productId = null,
            string authorizationServerId = null,
            string scope = null,
            string openid = null)
        {
            if (string.IsNullOrWhiteSpace(aid) ||
                string.IsNullOrWhiteSpace(suffix) ||
                string.IsNullOrWhiteSpace(swaggerUrl))
            {
                return false;
            }

            var path = $"/apis/{aid}";

            var queryParams = new Dictionary<string, string>
            {
                { "import", "false" },
                { "path", suffix },
            };

            #region content
            var body = new JObject();
            body["id"] = path;
            body["link"] = swaggerUrl;

            var content = new StringContent(body.ToString(),
                Encoding.UTF8,
                "application/vnd.swagger.link+json");
            #endregion

            #region headerItems
            Dictionary<string, string> headerItems = null;

            if (await MetadataAsync(aid))
            {
                headerItems = new Dictionary<string, string>()
                {
                    { "If-Match", "*" }
                };
            }
            #endregion

            var result = await RequestAsync(path, HttpMethod.Put.Method, queryParams, content, headerItems);

            if (result.IsSuccessStatusCode)
            {
                #region Add Api to Product
                // 如果为空，设置到Unlimited 这个Product里，否则需要带上subkey才能call
                if (!string.IsNullOrWhiteSpace(productId))
                {
                    var addApiResult = await prdService.AddApiAsync(productId, aid);
                }
                #endregion

                #region Update Api OAuth2 Settings
                var oAuth2result = await UpdateOAuth2Async(aid, authorizationServerId, scope, openid);
                #endregion
            }

            return result.IsSuccessStatusCode;
        }

        /// <summary>
        /// Update Api authenticationSettings
        /// </summary>
        /// <param name="aid">Api Id</param>
        /// <param name="authorizationServerId">oauth ServerId</param>
        /// <param name="scope">scopes</param>
        /// <param name="openid">openid</param>
        /// <returns></returns>
        public async Task<bool> UpdateOAuth2Async(string aid, string authorizationServerId, string scope = null, string openid = null)
        {
            var body = new JObject();

            body["id"] = $"/apis/{aid}";

            if (!string.IsNullOrWhiteSpace(authorizationServerId))
            {
                body["authenticationSettings"] = JObject.FromObject(new
                {
                    oAuth2 = new
                    {
                        authorizationServerId,
                        scope
                    },

                    openid
                });
            }

            else
            {
                body["authenticationSettings"] = JObject.FromObject(new
                {
                    oAuth2 = ""
                });
            }

            var result = await UpdateAsync(aid, body.ToString());

            return result;
        }

        /// <summary>
        /// Update Api Entity By Model
        /// </summary>
        /// <param name="aid">id</param>
        /// <param name="body">Model</param>
        /// <returns></returns>
        public async Task<bool> UpdateAsync(string aid, string body)
        {
            var path = $"/apis/{aid}";

            var method = "PATCH";

            var content = new StringContent(body, Encoding.UTF8, "application/json");

            var headerItems = new Dictionary<string, string>() { { "If-Match", "*" } };

            var result = await RequestAsync(path, method, null, content, headerItems);

            return result.IsSuccessStatusCode;
        }

        /// <summary>
        /// Delete Api by id
        /// </summary>
        /// <param name="aid">id</param>
        /// <returns></returns>
        public async Task<bool> DeleteAsync(string aid)
        {
            var path = $"/apis/{aid}";

            var headerItems = new Dictionary<string, string>() { { "If-Match", "*" } };

            var result = await RequestAsync(path, HttpMethod.Delete.Method, null, null, headerItems);

            return result.IsSuccessStatusCode;
        }

        /// <summary>
        /// Get Api Policy
        /// </summary>
        /// <returns></returns>
        public async Task<string> GetPolicyAsync(string aid)
        {
            var result = await RequestAsync($"/apis/{aid}/policy",
                HttpMethod.Get.Method,
                null, null, null, "application/vnd.ms-azure-apim.policy+xml");

            if (result.IsSuccessStatusCode)
            {
                return result.Content.ReadAsStringAsync().Result;
            }

            else
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// Set Api Policy
        /// </summary>
        /// <returns></returns>
        public async Task<string> SetPolicyAsync(string aid, string policies)
        {
            var path = $"/apis/{aid}/policy";

            var headerItems = new Dictionary<string, string>()
            {
                { "If-Match", "*" }
            };

            var content = new StringContent(policies, Encoding.UTF8, "application/vnd.ms-azure-apim.policy.raw+xml");

            var result = await RequestAsync(path, HttpMethod.Put.Method, null, content, headerItems);

            if (result.IsSuccessStatusCode)
            {
                return result.Content.ReadAsStringAsync().Result;
            }

            else
            {
                return string.Empty;
            }
        }
    }

    public class AzureApiManagementEntities<T>
    {
        public List<T> value { get; set; }

        public int count { get; set; }

        public string nextLink { get; set; }
    }

    public class AzureApiManagementProductEntity
    {
        public string id { get; set; }
        public string name { get; set; }
        public string description { get; set; }
        public string terms { get; set; }
        public string subscriptionRequired { get; set; }
        public string approvalRequired { get; set; }
        public string subscriptionsLimit { get; set; }
        public string state { get; set; }
    }

    public class AzureApiManagementProduct : AzureApiManagement
    {
        public AzureApiManagementProduct(string _host,
            string _apiId,
            string _apiKey) : base(_host, _apiId, _apiKey)
        {
        }

        /// <summary>
        /// Product List
        /// </summary>
        /// <returns></returns>
        public async Task<AzureApiManagementEntities<AzureApiManagementProductEntity>> GetAsync()
        {
            var result = await _GetAsync("/products");

            if (result.IsSuccessStatusCode)
            {
                var data = result.Content.ReadAsStringAsync().Result;

                var entities = JsonConvert.DeserializeObject<AzureApiManagementEntities<AzureApiManagementProductEntity>>(data);

                return entities;
            }

            else
            {
                return null;
            }
        }

        /// <summary>
        /// Add Api To Product
        /// </summary>
        /// <param name="pid">Product id</param>
        /// <param name="aid">Api id</param>
        /// <returns></returns>
        public async Task<bool> AddApiAsync(string pid, string aid)
        {
            var path = $"{pid}/apis/{aid}";

            var result = await _PutAsync(path);

            return result.IsSuccessStatusCode;
        }
    }

    public class AzureApiManagementUser : AzureApiManagement
    {
        public AzureApiManagementUser(string _host,
            string _apiId,
            string _apiKey) : base(_host, _apiId, _apiKey)
        {
        }

        public async Task<string> GenerateSsoUrlAsync(string uid)
        {
            var path = $"/users/{uid}/generateSsoUrl";

            var response = await _PostAsync(path);

            if (response.IsSuccessStatusCode)
            {
                var responseJson = response.Content.ReadAsStringAsync().Result;

                var signOnURL = JObject.Parse(responseJson)["value"].Value<string>();

                return signOnURL;
            }

            return string.Empty;
        }

        public async Task<bool> AddAsync(string uid, string email, string password)
        {
            if (await MetadataAsync(uid)) { return true; }

            var path = $"/users/{uid}";

            var method = HttpMethod.Put.Method;

            var content = new StringContent(JsonConvert.SerializeObject(new
            {
                firstName = "u",
                lastName = email,
                email,
                password
            }), Encoding.UTF8, "application/json");

            var result = await RequestAsync(path, method, null, content);

            return result.IsSuccessStatusCode;
        }

        public async Task<bool> MetadataAsync(string uid)
        {
            var path = $"/users/{uid}";

            var result = await _HeadAsync(path);

            return result.IsSuccessStatusCode;
        }
    }

    /// <summary>
    /// 必须初始化 调用init方法
    /// </summary>
    public class AzureApiManagementServices
    {
        #region configs
        string host { get; set; }
        string apiId { get; set; }
        string apiKey { get; set; }
        #endregion

        private AzureApiManagement _Management;
        public AzureApiManagement Management
        {
            get
            {

                if (_Management == null)
                {
                    _Management = new AzureApiManagement(host, apiId, apiKey);
                }

                return _Management;
            }
        }

        private AzureApiManagementApi _Apis;
        public AzureApiManagementApi Apis
        {
            get
            {
                if (_Apis == null)
                {
                    _Apis = new AzureApiManagementApi(host, apiId, apiKey);
                }

                return _Apis;
            }
        }

        private AzureApiManagementProduct _Products;
        public AzureApiManagementProduct Products
        {
            get
            {

                if (_Products == null)
                {
                    _Products = new AzureApiManagementProduct(host, apiId, apiKey);
                }

                return _Products;
            }
        }

        private AzureApiManagementUser _Users;
        public AzureApiManagementUser Users
        {
            get
            {

                if (_Users == null)
                {
                    _Users = new AzureApiManagementUser(host, apiId, apiKey);
                }

                return _Users;
            }
        }

        private AzureApiManagementAuthorizationServers _AuthorizationServers;
        public AzureApiManagementAuthorizationServers AuthorizationServers
        {
            get
            {

                if (_AuthorizationServers == null)
                {
                    _AuthorizationServers = new AzureApiManagementAuthorizationServers(host, apiId, apiKey);
                }

                return _AuthorizationServers;
            }
        }

        public AzureApiManagementServices(string _host,
            string _apiId,
            string _apiKey)
        {
            host = _host;
            apiId = _apiId;
            apiKey = _apiKey;
        }
    }
}
