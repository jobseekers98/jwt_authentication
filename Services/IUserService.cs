using DALfile;
using Jwt_Authentication.Helpers;
using Jwt_Authentication.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MODELfile;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Jwt_Authentication.Services
{
    public interface IUserService
    {
        AuthenticateResponse Authenticate(AuthenticateRequest model);
        User GetById(int userId);
    }

    public class UserService : IUserService
    {
        public readonly ApplicationContext _dbcontext;
        private readonly AppSettings _appSettings;
        public UserService(ApplicationContext dbcontext, IOptions<AppSettings> appSettings)
        {
            _dbcontext = dbcontext;
            _appSettings = appSettings.Value;
        }

        public AuthenticateResponse Authenticate(AuthenticateRequest model)
        {
            //var user = _users.SingleOrDefault(x => x.Username == model.Username && x.Password == model.Password);
            var user = _dbcontext.Users.SingleOrDefault(x => x.UserName == model.Username && x.Password == model.Password);
            // return null if user not found
            if (user == null) return null;

            // authentication successful so generate jwt token
            var token = GenerateToken(user);

            return new AuthenticateResponse(user, token);
        }

        public User GetById(int userId)
        {
            return _dbcontext.Users.Where(x => x.Id == userId).FirstOrDefault();
        }

        private string GenerateToken(User user)
        {
            // generate token that is valid for 7 days
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("id", user.Id.ToString()) }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }

}
