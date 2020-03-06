using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System;
using System.IdentityModel.Tokens.Jwt;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _repo;
        private readonly IConfiguration _config;

        public AuthController(IAuthRepository repo, IConfiguration config)
        {
            _repo = repo;
            _config = config;
        }
        
        [HttpPost("register")]
        public async Task<IActionResult> Register(UserForRegisterDto userForRegisterDto)
        {
            // we dont need to check model state or [FromBody] to the UserForRegisterDto if we add [ApiController] in the top of the controller[]
            /*if(!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }*/
            userForRegisterDto.Username = userForRegisterDto.Username.ToLower();
            if(await _repo.UserExists(userForRegisterDto.Username))
            {
                return BadRequest("Username already exists");
            }

            var userToCreate = new User{
                Usernamen = userForRegisterDto.Username
            };
            var createdUser = await _repo.Register(userToCreate, userForRegisterDto.Password);
            return StatusCode(201);

        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserForLoginDto userForLoginDto)
        {
            
            
            
            var userFromRepo = await _repo.Login(userForLoginDto.Username.ToLower(), userForLoginDto.Password);
            if(userFromRepo == null)
            {
                return Unauthorized();
            }

            /*******  Packages used for token ******
            ****************************************
            Microsoft.IdentityModel.Tokens
            System.IdentityModel.Tokens.Jwt
            ***************************************
            ***************************************/

            // 1. the token contains 2 claims i.e. UserId and UserName

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, userFromRepo.Id.ToString()),
                new Claim(ClaimTypes.Name, userFromRepo.Usernamen)
            };

            // 2. we create a security key in our appsettings.json file

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("AppSettings:Token").Value));

            // 3. the is part of the signing credentials and we choose the hashing algorithm and we create the signiture
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            // 4. we create a token descriptor and pass our claims, expire date and our signature
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = creds
            };

            // 5. we create a new instance of the token handler and we pass our token descriptor in order to create the token
            var tokenHandler = new JwtSecurityTokenHandler();

            var token = tokenHandler.CreateToken(tokenDescriptor);

            // 6. we write the token to the response that we send to the client
            return Ok(new {
                token = tokenHandler.WriteToken(token)
            });

            

            

        }
    }
}