using System.ComponentModel.DataAnnotations;

namespace JWT.Models;
public class LoginModel
{
    [Required(ErrorMessage = "É obrigatório informar o nome do usuário.")]
    public string? Username { get; set; }    

    [Required(ErrorMessage = "É obrigatório informar a senha do usuário.")]
    public string? Password { get; set; }    
}