﻿using TestApiJWT.Models;

namespace TestApiJWT.Services
{
    public interface IAuthService
    {
        Task<AuthModel> RegisterAsync(RegisterModel model);
        Task<AuthModel> GetTokenAsync(TokenRequestModel model);
        Task<string> AddRoleAsync(AddRoleModel model );
        Task<AuthModel>RefreshTokenAsync(string Token);
        Task<bool>RevokeTokenAsync(string Token);
    }
}
