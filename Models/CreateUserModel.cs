using System.ComponentModel.DataAnnotations;

namespace JWT.Models;
public class CreateUserModel
{
    [Required(ErrorMessage = "É obrigatório informar se o usuário é um admin.")]
    public bool IsAdmin { get; set; } = false;
    
    [Required(ErrorMessage = "O nome de usuário é obrigatório.")]
    public string? Username {get; set;}

    [EmailAddress]
    [Required(ErrorMessage = "O email é obrigatório.")]
    public string? Email { get; set; }

    [Required(ErrorMessage = "Uma senha é obrigatória.")]
    public string? Password { get; set; }
}