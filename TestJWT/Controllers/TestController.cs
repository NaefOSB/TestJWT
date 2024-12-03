using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace TestJWT.Controllers
{
    [Authorize(Roles = "SuperAdmin,Admin,User")]
    [Route("api/[controller]")]
    [ApiController]
    public class TestController : ControllerBase
    {
        [HttpGet("get-names")]
        public List<string> GetNames()
        {
            List<string> names = new List<string>() { "Naef", "Omar", "Saleh", "Ba-Farag" };

            return names;
        }
    }
}
