using TestJWT.DTOs;
using TestJWT.ViewModels;

namespace TestJWT.Services
{
    public interface IAuthService
    {
        Task<AuthViewModel> RegisterAsync(RegisterDTO registerDTO);
        Task<AuthViewModel> LoginAsync(LoginDTO loginDTO);
        Task<string> AddToRoleAsync(AddUserToRoleDTO addUserToRoleDTO);
    }
}
