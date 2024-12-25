using Microsoft.AspNetCore.Mvc;
using TestApiJWT.Models;
using TestApiJWT.Services;

namespace TestApiJWT.Controllers
{
    [Route("api/[controller]")] // Define the route for this controller
    [ApiController] // Specify that this is an API controller
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        // Constructor to initialize the AuthService
        // المُنشئ لتهيئة خدمة المصادقة
        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        // Endpoint to register a new user
        // نقطة نهاية لتسجيل مستخدم جديد
        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterModel model)
        {
            // Validate the request body
            // التحقق من صحة البيانات المرسلة
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            // Call the AuthService to handle the registration logic
            // استدعاء خدمة المصادقة لتنفيذ منطق التسجيل
            var result = await _authService.RegisterAsync(model);

            // Return an error message if authentication fails
            // إرجاع رسالة خطأ إذا فشلت عملية المصادقة
            if (!result.IsAuthenticated)
                return BadRequest(result.Message);

            // Set the refresh token in the HTTP-only cookie
            // تعيين رمز التحديث في كوكي HTTP فقط
            SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpriation);

            // Return the successful result
            // إرجاع النتيجة الناجحة
            return Ok(result);
        }

        // Endpoint to authenticate a user and generate a token
        // نقطة نهاية لمصادقة المستخدم وإنشاء رمز JWT
        [HttpPost("token")]
        public async Task<IActionResult> GetTokenAsync([FromBody] TokenRequestModel model)
        {
            // Validate the request body
            // التحقق من صحة البيانات المرسلة
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            // Call the AuthService to handle token generation
            // استدعاء خدمة المصادقة لإنشاء الرمز
            var result = await _authService.GetTokenAsync(model);

            // Return an error message if authentication fails
            // إرجاع رسالة خطأ إذا فشلت عملية المصادقة
            if (!result.IsAuthenticated)
                return BadRequest(result.Message);

            // If a refresh token is generated, set it in the cookie
            // إذا تم إنشاء رمز تحديث، قم بتعيينه في الكوكي
            if (!string.IsNullOrEmpty(result.RefreshToken))
                SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpriation);

            // Return the successful result
            // إرجاع النتيجة الناجحة
            return Ok(result);
        }

        // Endpoint to add a role to an existing user
        // نقطة نهاية لإضافة دور إلى مستخدم موجود
        [HttpPost("addrole")]
        public async Task<IActionResult> AddRoleAsync([FromBody] AddRoleModel model)
        {
            // Validate the request body
            // التحقق من صحة البيانات المرسلة
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            // Call the AuthService to handle role assignment
            // استدعاء خدمة المصادقة لتعيين الدور
            var result = await _authService.AddRoleAsync(model);

            // Return an error message if the operation fails
            // إرجاع رسالة خطأ إذا فشلت العملية
            if (!string.IsNullOrEmpty(result))
                return BadRequest(result);

            // Return the successful result
            // إرجاع النتيجة الناجحة
            return Ok(model);
        }

        // Endpoint to refresh the JWT token using the refresh token
        // نقطة نهاية لتحديث رمز JWT باستخدام رمز التحديث
        [HttpGet("refreshToken")]
        public async Task<IActionResult> RefeshToken()
        {
            // Retrieve the refresh token from the cookies
            // استرداد رمز التحديث من الكوكي
            var refreshToken = Request.Cookies["refreshToken"];

            // Call the AuthService to refresh the token
            // استدعاء خدمة المصادقة لتحديث الرمز
            var result = await _authService.RefreshTokenAsync(refreshToken);

            // Return an error message if the refresh token is invalid
            // إرجاع رسالة خطأ إذا كان رمز التحديث غير صالح
            if (!result.IsAuthenticated)
                return BadRequest(result);

            // Set the new refresh token in the cookie
            // تعيين رمز التحديث الجديد في الكوكي
            SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpriation);

            // Return the successful result
            // إرجاع النتيجة الناجحة
            return Ok(result);
        }

        // Endpoint to revoke a refresh token
        // نقطة نهاية لإلغاء صلاحية رمز تحديث
        [HttpPost("revokeToken")]
        public async Task<IActionResult> RevokeToken([FromBody] RevokeToken model)
        {
            // Retrieve the token from the request body or cookies
            // استرداد الرمز من جسم الطلب أو الكوكي
            var token = model.Token ?? Request.Cookies["refreshToken"];

            // Validate that the token exists
            // التحقق من وجود الرمز
            if (string.IsNullOrEmpty(token))
                return BadRequest("Token Is Required!");

            // Call the AuthService to revoke the token
            // استدعاء خدمة المصادقة لإلغاء صلاحية الرمز
            var result = await _authService.RevokeTokenAsync(token);

            // Return an error message if the token is invalid
            // إرجاع رسالة خطأ إذا كان الرمز غير صالح
            if (!result)
                return BadRequest("Token Is Invalid!");

            // Return a successful response
            // إرجاع استجابة ناجحة
            return Ok();
        }

        // Private helper method to set the refresh token in cookies
        // دالة مساعدة خاصة لتعيين رمز التحديث في الكوكي
        private void SetRefreshTokenInCookie(string refreshToken, DateTime expires)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true, // Ensure the cookie is only accessible via HTTP
                // التأكد من أن الكوكي يمكن الوصول إليه فقط عبر HTTP
                Expires = expires.ToLocalTime() // Set the expiration date for the cookie
                // تعيين تاريخ انتهاء الصلاحية للكوكي
            };

            // Append the refresh token to the response cookies
            // إضافة رمز التحديث إلى الكوكي للاستجابة
            Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
        }
    }
}
