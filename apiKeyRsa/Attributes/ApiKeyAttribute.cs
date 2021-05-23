using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using RSALib;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ApiKey.Attributes
{
    [AttributeUsage(validOn: AttributeTargets.Class | AttributeTargets.Method)]
    public class ApiKeyAttribute : Attribute, IAsyncActionFilter
    {
        private const string ApiKeyName = "Authorization";

        public async Task OnActionExecutionAsync(
            ActionExecutingContext context,
            ActionExecutionDelegate next)
        {
            if (!context.HttpContext.Request.Headers.TryGetValue(ApiKeyName, out var extractedApiKey))
            {
                context.Result = new ContentResult()
                {
                    StatusCode = 401,
                    Content = "ApiKey não encontrada"
                };
                return;
            }
            var _configuration = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>();

            bool validPfx = RSAService.DecryptUsingCertificate(extractedApiKey.ToString().Replace("Bearer ", ""), _configuration["RSA_PRIVATEKEY_PATHPFX"], _configuration["ValidKeys"]);

            RSAHandler rsa = new RSAHandler();
            bool validPEM = rsa.IsRSAToken(extractedApiKey.ToString().Replace("Bearer ", ""), _configuration["RSA_PRIVATEKEY_PATHPEM"], _configuration["ValidKeys"].Split('-'));

            if (!validPfx && !validPEM)
            {
                context.Result = new ContentResult()
                {
                    StatusCode = 403,
                    Content = "Acesso não autorizado"
                };
                return;
            }

            await next();
        }
    }

}
