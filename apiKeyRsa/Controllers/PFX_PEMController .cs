using ApiKey.Attributes;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ApiKey.Controllers
{
    [ApiController]
    [Route("apikey")]
    public class PFX_PEMController : ControllerBase
    {
        [HttpGet]
        [ApiKeyAttribute]
        public IActionResult Get()
        {
            return Ok(new { message = "Você tem acesso!" });
        }

    }
}
