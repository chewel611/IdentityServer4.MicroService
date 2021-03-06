﻿using System;
using System.Linq;
using System.Data;
using System.Data.SqlClient;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Localization;
using Swashbuckle.AspNetCore.SwaggerGen;
using IdentityServer4.MicroService.ApiCodes;
using IdentityServer4.MicroService.Models.CommonModels;
using IdentityServer4.MicroService.Services;
using IdentityServer4.MicroService.Tenant;
using IdentityServer4.MicroService.Models.AppTenantModels;
using static IdentityServer4.MicroService.AppConstant;

namespace IdentityServer4.MicroService.Apis
{
    // Tenant 根据 OwnerUserId 来获取列表、或详情、增删改

    [Route("Tenant")]
    [Authorize(AuthenticationSchemes = AppAuthenScheme, Roles = Roles.Users)]
    public class TenantController : BasicController
    {
        #region Services
        //Database
        readonly TenantDbContext db;
        //redis
        readonly RedisService redis;
        readonly TenantService tenantService;
        #endregion

        public TenantController(
            TenantDbContext _db,
            RedisService _redis,
            IStringLocalizer<TenantController> _localizer,
            TenantService _tenantService
            )
        {
            // 多语言
            l = _localizer;
            redis = _redis;
            db = _db;
            tenantService = _tenantService;
        }

        /// <summary>
        /// Get Tenant List
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        [HttpGet]
        [Authorize(AuthenticationSchemes = AppAuthenScheme, Policy = UserPermissions.Read)]
        [SwaggerOperation("Tenant/Get")]
        public async Task<PagingResult<AppTenant>> Get(PagingRequest<AppTenantQuery> value)
        {
            if (!ModelState.IsValid)
            {
                return new PagingResult<AppTenant>()
                {
                    code = (int)BasicControllerCodes.UnprocessableEntity,
                    error_msg = ModelErrors()
                };
            }

            var query = db.Tenants.AsQueryable();

            query = query.Where(x => x.OwnerUserId == UserId);

            #region filter
            if (!string.IsNullOrWhiteSpace(value.q.Host))
            {
                query = query.Where(x => x.Hosts.Any(h => h.HostName.Equals(value.q.Host)));
            }
            #endregion

            #region total
            var result = new PagingResult<AppTenant>()
            {
                skip = value.skip,
                take = value.take,
                total = await query.CountAsync()
            }; 
            #endregion

            if (result.total > 0)
            {
                #region orderby
                if (!string.IsNullOrWhiteSpace(value.orderby))
                {
                    if (value.asc)
                    {
                        query = query.OrderBy(value.orderby);
                    }
                    else
                    {
                        query = query.OrderByDescending(value.orderby);
                    }
                }
                #endregion

                #region pagingWithData
                var data = await query.Skip(value.skip).Take(value.take)
                            .Include(x => x.Claims)
                            .Include(x => x.Hosts)
                            .Include(x => x.Properties)
                            .ToListAsync(); 
                #endregion

                if (data.Count > 0)
                {
                    result.data = data;
                }
            }

            return result;
        }

        /// <summary>
        /// Get Tenant Detail By Id
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet("{id}")]
        [Authorize(AuthenticationSchemes = AppAuthenScheme, Policy = UserPermissions.Read)]
        [SwaggerOperation("Tenant/Detail")]
        public async Task<ApiResult<AppTenant>> Get(int id)
        {
            var query = db.Tenants.AsQueryable();

            query = query.Where(x => x.OwnerUserId == UserId);

            var entity = await query
                .Include(x => x.Hosts)
                .Include(x => x.Claims)
                .Include(x => x.Properties)
                .FirstOrDefaultAsync(x => x.Id == id);

            if (entity == null)
            {
                return new ApiResult<AppTenant>(l, BasicControllerCodes.NotFound);
            }

            return new ApiResult<AppTenant>(entity);
        }

        /// <summary>
        /// Insert Tenant
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        [HttpPost]
        [Authorize(AuthenticationSchemes = AppAuthenScheme, Policy = UserPermissions.Create)]
        [SwaggerOperation("Tenant/Post")]
        public async Task<ApiResult<long>> Post([FromBody]AppTenant value)
        {
            if (!ModelState.IsValid)
            {
                return new ApiResult<long>(l, BasicControllerCodes.UnprocessableEntity,
                    ModelErrors());
            }

            value.OwnerUserId = UserId;

            db.Add(value);

            await db.SaveChangesAsync();

            return new ApiResult<long>(value.Id);
        }

        /// <summary>
        /// Update Tenant
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        [HttpPut]
        [Authorize(AuthenticationSchemes = AppAuthenScheme, Policy = UserPermissions.Update)]
        [SwaggerOperation("Tenant/Put")]
        public async Task<ApiResult<long>> Put([FromBody]AppTenant value)
        {
            if (!ModelState.IsValid)
            {
                return new ApiResult<long>(l, 
                    BasicControllerCodes.UnprocessableEntity,
                    ModelErrors());
            }

            using (var tran = db.Database.BeginTransaction(IsolationLevel.ReadCommitted))
            {
                try
                {
                    #region Update Entity
                    value.OwnerUserId = UserId;
                    // 需要先更新value，否则更新如claims等属性会有并发问题
                    db.Update(value);
                    db.SaveChanges();
                    #endregion

                    #region Find Entity.Source
                    var source = await db.Tenants.Where(x => x.Id == value.Id)
                                     .Include(x => x.Hosts)
                                     .Include(x => x.Claims)
                                    .AsNoTracking()
                                    .FirstOrDefaultAsync();
                    #endregion

                    #region Update Entity.Claims
                    if (value.Claims != null && value.Claims.Count > 0)
                    {
                        #region delete
                        var EntityIDs = value.Claims.Select(x => x.Id).ToList();
                        if (EntityIDs.Count > 0)
                        {
                            var DeleteEntities = source.Claims.Where(x => !EntityIDs.Contains(x.Id)).Select(x => x.Id).ToArray();

                            if (DeleteEntities.Count() > 0)
                            {
                                var sql = string.Format("DELETE AppTenantClaims WHERE ID IN ({0})",
                                            string.Join(",", DeleteEntities));

                                db.Database.ExecuteSqlCommand(new RawSqlString(sql));
                            }
                        }
                        #endregion

                        #region update
                        var UpdateEntities = value.Claims.Where(x => x.Id > 0).ToList();
                        if (UpdateEntities.Count > 0)
                        {
                            UpdateEntities.ForEach(x =>
                            {
                                db.Database.ExecuteSqlCommand(
                                  new RawSqlString("UPDATE AppTenantClaims SET [ClaimType]=@Type,[ClaimValue]=@Value WHERE Id = " + x.Id),
                                  new SqlParameter("@Type", x.ClaimType),
                                  new SqlParameter("@Value", x.ClaimValue));
                            });
                        }
                        #endregion

                        #region insert
                        var NewEntities = value.Claims.Where(x => x.Id == 0).ToList();
                        if (NewEntities.Count > 0)
                        {
                            NewEntities.ForEach(x =>
                            {
                                db.Database.ExecuteSqlCommand(
                                  new RawSqlString("INSERT INTO AppTenantClaims VALUES (@ClaimType,@ClaimValue,@AppTenantId)"),
                                  new SqlParameter("@ClaimType", x.ClaimType),
                                  new SqlParameter("@ClaimValue", x.ClaimValue),
                                  new SqlParameter("@AppTenantId", source.Id));
                            });
                        }
                        #endregion
                    }
                    #endregion

                    #region Update Entity.Properties
                    if (value.Properties != null && value.Properties.Count > 0)
                    {
                        #region delete
                        var EntityIDs = value.Properties.Select(x => x.Id).ToList();
                        if (EntityIDs.Count > 0)
                        {
                            var DeleteEntities = source.Properties.Where(x => !EntityIDs.Contains(x.Id)).Select(x => x.Id).ToArray();

                            if (DeleteEntities.Count() > 0)
                            {
                                var sql = string.Format("DELETE AppTenantProperty WHERE ID IN ({0})",
                                            string.Join(",", DeleteEntities));

                                db.Database.ExecuteSqlCommand(new RawSqlString(sql));
                            }
                        }
                        #endregion

                        #region update
                        var UpdateEntities = value.Properties.Where(x => x.Id > 0).ToList();
                        if (UpdateEntities.Count > 0)
                        {
                            UpdateEntities.ForEach(x =>
                            {
                                db.Database.ExecuteSqlCommand(
                                  new RawSqlString("UPDATE AppTenantProperty SET [Key]=@Key,[Value]=@Value WHERE Id = " + x.Id),
                                  new SqlParameter("@Key", x.Key),
                                  new SqlParameter("@Value", x.Value));
                            });
                        }
                        #endregion

                        #region insert
                        var NewEntities = value.Properties.Where(x => x.Id == 0).ToList();
                        if (NewEntities.Count > 0)
                        {
                            NewEntities.ForEach(x =>
                            {
                                db.Database.ExecuteSqlCommand(
                                  new RawSqlString("INSERT INTO AppTenantProperty VALUES (@Key,@Value,@AppTenantId)"),
                                  new SqlParameter("@Key", x.Key),
                                  new SqlParameter("@Value", x.Value),
                                  new SqlParameter("@AppTenantId", source.Id));
                            });
                        }
                        #endregion
                    }
                    #endregion

                    #region Update Entity.Hosts
                    if (value.Hosts != null && value.Hosts.Count > 0)
                    {
                        #region delete
                        var EntityIDs = value.Hosts.Select(x => x.Id).ToList();
                        if (EntityIDs.Count > 0)
                        {
                            var DeleteEntities = source.Hosts.Where(x => !EntityIDs.Contains(x.Id)).Select(x => x.Id).ToArray();

                            if (DeleteEntities.Count() > 0)
                            {
                                var sql = string.Format("DELETE AppTenantHosts WHERE ID IN ({0})",
                                            string.Join(",", DeleteEntities));

                                db.Database.ExecuteSqlCommand(new RawSqlString(sql));
                            }
                        }
                        #endregion

                        #region update
                        var UpdateEntities = value.Hosts.Where(x => x.Id > 0).ToList();
                        if (UpdateEntities.Count > 0)
                        {
                            UpdateEntities.ForEach(x =>
                            {
                                db.Database.ExecuteSqlCommand(
                                  new RawSqlString("UPDATE AppTenantHosts SET [HostName]=@HostName WHERE Id = " + x.Id),
                                  new SqlParameter("@HostName", x.HostName));
                            });
                        }
                        #endregion

                        #region insert
                        var NewEntities = value.Hosts.Where(x => x.Id == 0).ToList();
                        if (NewEntities.Count > 0)
                        {
                            NewEntities.ForEach(x =>
                            {
                                db.Database.ExecuteSqlCommand(
                                  new RawSqlString("INSERT INTO AppTenantHosts VALUES (@AppTenantId,@HostName)"),
                                  new SqlParameter("@HostName", x.HostName),
                                  new SqlParameter("@AppTenantId", source.Id));
                            });
                        }
                        #endregion
                    }
                    #endregion

                    tran.Commit();
                }

                catch (Exception ex)
                {
                    tran.Rollback();

                    return new ApiResult<long>(l, 
                        BasicControllerCodes.ExpectationFailed,
                        ex.Message);
                }
            }

            return new ApiResult<long>(value.Id);
        }

        /// <summary>
        /// Delete Tenant
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpDelete("{id}")]
        [Authorize(AuthenticationSchemes = AppAuthenScheme, Policy = UserPermissions.Delete)]
        [SwaggerOperation("Tenant/Delete")]
        public async Task<ApiResult<long>> Delete(int id)
        {
            var entity = await db.Tenants.FirstOrDefaultAsync(x => x.OwnerUserId == UserId && x.Id == id);

            if (entity == null)
            {
                return new ApiResult<long>(l, BasicControllerCodes.NotFound);
            }

            db.Tenants.Remove(entity);

            await db.SaveChangesAsync();

            db.Database.ExecuteSqlCommand(new RawSqlString("DELETE AspNetUserTenants WHERE AppTenantId = " + id));

            return new ApiResult<long>(id);
        }

        /// <summary>
        /// Get Tenant Detail By Host
        /// </summary>
        /// <param name="host"></param>
        /// <returns></returns>
        [HttpGet("Info")]
        [AllowAnonymous]
        [SwaggerOperation("Tenant/Info")]
        public ApiResult<string> Info(string host)
        {
            var entity = tenantService.GetTenant(db, host);

            if (entity == null)
            {
                return new ApiResult<string>(l, BasicControllerCodes.NotFound);
            }

            return new ApiResult<string>(entity.Item1);
        }
    }
}
