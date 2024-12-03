using System.ComponentModel.DataAnnotations;

namespace TestJWT.DTOs
{
    public class AddUserToRoleDTO
    {
        [Required]
        public string UserId { get; set; }
        
        [Required]
        public string Role { get; set; }
    }
}
