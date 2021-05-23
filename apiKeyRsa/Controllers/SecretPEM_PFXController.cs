using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using RSALib;
using System;
using System.Collections.Generic;

namespace AuthJwt.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    public class SecretPEM_PFXController : ControllerBase
    {
        private IConfiguration configuration;

        public SecretPEM_PFXController(IConfiguration _configuration)
        {
            configuration = _configuration;
        }

        [HttpGet("{key}")]
        public Dictionary<string, object> Get(string key)
        {
            string connString = key;
            Dictionary<string, object> result = new Dictionary<string, object>();

            try
            {
                RSAHandler rsa = new RSAHandler();
                string encryptdatpem = rsa.Encrypt(connString, configuration["RSA_PUBLICKEY_PATHPEM"]);
                result.Add("token", encryptdatpem);

            }
            catch
            {


                var encryptdatpfx = RSAService.EncryptUsingCertificate(connString, configuration["RSA_PUBLICKEY_PATHPFX"]);//vem nulo

                if (string.IsNullOrEmpty(encryptdatpfx)) throw new ArgumentException("RSA keys invalid");



                result.Add("token", encryptdatpfx);

                

            }
            return result;
        }

    }
}
