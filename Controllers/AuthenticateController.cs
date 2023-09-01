using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using JWT.Auth;
using JWT.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JWT.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthenticateController : ControllerBase
{
    private readonly IConfiguration _configuration;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;

    public AuthenticateController(
        IConfiguration configuration, 
        UserManager<IdentityUser> userManager, 
        RoleManager<IdentityRole> roleManager)
    {
        _configuration = configuration;
        _userManager = userManager;
        _roleManager = roleManager;
    }

    [HttpPost]
    [Route("register")]
    public async Task<IActionResult> RegisterUserAsync([FromBody] CreateUserModel model) {

        /* -- Verifica se o usuário já está cadastrado -- */
        var userExists = await _userManager.FindByEmailAsync(model.Username); // Verificar se realmente é username ao invés de email

        if (userExists is not null) {
            return StatusCode(
                StatusCodes.Status500InternalServerError,
                new ResponseModel { Success = false, Message = "Esse usuário já está cadastrado."}
            );
        }

        /* -- Cria um usuário novo com os dados passados no POST -- */
        IdentityUser user = new() {
            SecurityStamp = Guid.NewGuid().ToString(),
            Email = model.Email,
            UserName = model.Username
        };

        var result = await _userManager.CreateAsync(user, model.Password);

        /* -- Verifica se ocorreu tudo certo com a criação do usuário -- */
        if (!result.Succeeded) {
            var errorMessage = "";
            foreach (var error in result.Errors) {
                errorMessage += error.Description + Environment.NewLine;
            }

            return StatusCode(
                StatusCodes.Status500InternalServerError,
                new ResponseModel { Success = false, Message = "Houve um erro ao criar o usuário." + Environment.NewLine + errorMessage}
                );
        }

        /* -- Adiciona o cargo do usuário { É limitado a apenas ADMIN e USER? } -- */
        var role = model.IsAdmin ? UserRoles.Admin : UserRoles.User;

        await AddToRoleAsync(user, role);

        return StatusCode(StatusCodes.Status200OK, new ResponseModel { Message = "O usuário foi criado." });
    }

    [HttpPost]
    [Route("login")]
    public async Task<IActionResult> LoginUserAsync([FromBody] LoginModel model) {

        /* -- Tenta encontrar o usuário pelo o nome e então verifica se a senha coincide -- */
        var user = await _userManager.FindByNameAsync(model.Username);

        if (user is not null && await _userManager.CheckPasswordAsync(user, model.Password)) {
            var authClaims = new List<Claim> {
                new (ClaimTypes.Name, user.UserName),
                new (JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var userRoles = await _userManager.GetRolesAsync(user);

            foreach (var userRole in userRoles)
                authClaims.Add(new (ClaimTypes.Role, userRole));

            return Ok(new ResponseModel { Data = GetToken(authClaims) });
        }

        return Unauthorized();
    }

    private TokenModel GetToken(List<Claim> authClaims) {
        var authSigningKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

        var token = new JwtSecurityToken(
            issuer: _configuration["JWT:ValidIssuer"],
            audience: _configuration["JWT:ValidAudience"],
            expires: DateTime.Now.AddHours(1),
            claims: authClaims,
            signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
        );

        return new() {
            Token = new JwtSecurityTokenHandler().WriteToken(token),
            Expiration = token.ValidTo
        };
    }

    private async Task AddToRoleAsync(IdentityUser user, string role) {
        if (!await _roleManager.RoleExistsAsync(role)) 
            await _roleManager.CreateAsync(new(role));

        await _userManager.AddToRoleAsync(user, role);
    }
}