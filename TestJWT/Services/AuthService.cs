using Microsoft.AspNetCore.Identity;
using Microsoft.CodeAnalysis.Options;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TestJWT.DTOs;
using TestJWT.Helper;
using TestJWT.Models;
using TestJWT.ViewModels;

namespace TestJWT.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWT _jwt;
        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IOptions<JWT> jwt)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _jwt = jwt.Value;
        }

        public async Task<AuthViewModel> RegisterAsync(RegisterDTO registerDTO)
        {
            if (await _userManager.FindByEmailAsync(registerDTO.Email) is not null)
                return new AuthViewModel { Message = "Email is already registered" };

            if (await _userManager.FindByNameAsync(registerDTO.Username) is not null)
                return new AuthViewModel { Message = "Username is already registered" };

            ApplicationUser user = new ApplicationUser
            {
                FirstName = registerDTO.FirstName,
                LastName = registerDTO.LastName,
                UserName = registerDTO.Username,
                Email = registerDTO.Email
            };

            var result = await _userManager.CreateAsync(user, registerDTO.Password);

            if (!result.Succeeded)
            {
                string errors = string.Empty;

                foreach (IdentityError error in result.Errors)
                {
                    errors += $"{error.Description}, ";
                }
                return new AuthViewModel { Message = errors };
            }

            await _userManager.AddToRoleAsync(user, "User");

            var jwtSecurityToken = await CreateJwtToken(user);

            return new AuthViewModel
            {
                UserName = user.UserName,
                Email = user.Email,
                IsAuthenticated = true,
                ExpiresOn = jwtSecurityToken.ValidTo,
                Roles = new List<string> { "User" },
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken)
            };
        }

        public async Task<AuthViewModel> LoginAsync(LoginDTO loginDTO)
        {
            AuthViewModel result = new AuthViewModel();

            var user = await _userManager.FindByEmailAsync(loginDTO.Email);

            if (user == null || !await _userManager.CheckPasswordAsync(user, loginDTO.Password))
            {
                result.Message = "Email or Password is incorrect!";
                return result;
            }

            JwtSecurityToken jwtSecurityToken = await CreateJwtToken(user);
            var roles = await _userManager.GetRolesAsync(user);

            result.Email = user.Email;
            result.UserName = user.UserName;
            result.IsAuthenticated = true;
            result.ExpiresOn = jwtSecurityToken.ValidTo;
            result.Roles = roles.ToList();
            result.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);

            return result;
        }

        public async Task<string> AddToRoleAsync(AddUserToRoleDTO addUserToRoleDTO)
        {
            var user = await _userManager.FindByIdAsync(addUserToRoleDTO.UserId);

            if (user is null || !await _roleManager.RoleExistsAsync(addUserToRoleDTO.Role))
                return "Invalid user ID or Role";

            if (await _userManager.IsInRoleAsync(user, addUserToRoleDTO.Role))
                return "User already assign to this role";

            var result = await _userManager.AddToRoleAsync(user, addUserToRoleDTO.Role);

            return result.Succeeded ? string.Empty : "Something went wrong!";
        }

        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();

            foreach (var role in roles)
                roleClaims.Add(new Claim("role", role));

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.Now.AddDays(_jwt.DurationInDays),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }
    }
}
