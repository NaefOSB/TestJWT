using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using TestJWT.DTOs;
using TestJWT.Services;
using TestJWT.ViewModels;

namespace TestJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterDTO registerDTO)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            AuthViewModel result = await _authService.RegisterAsync(registerDTO);

            if (!result.IsAuthenticated)
                return BadRequest(result.Message);

            return Ok(result);
        }

        [HttpPost("login")]
        public async Task<IActionResult> LoginAsync([FromBody] LoginDTO loginDTO)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            AuthViewModel result = await _authService.LoginAsync(loginDTO);

            if (!result.IsAuthenticated)
                return BadRequest(result.Message);

            return Ok(result);
        }

        [HttpPost("add-to-role")]
        public async Task<IActionResult> AddToRoleAsync([FromBody] AddUserToRoleDTO addUserToRoleDTO)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            string result = await _authService.AddToRoleAsync(addUserToRoleDTO);

            if (!String.IsNullOrEmpty(result))
                return BadRequest(result);

            return Ok(addUserToRoleDTO);
        }
    }
}
