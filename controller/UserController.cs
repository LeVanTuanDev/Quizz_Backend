using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Data;
using System.Data.SqlClient;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System.Security.Claims;

namespace backend.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class UserController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly JwtToken _jwt;

        public UserController(IConfiguration configuration)
        {
            _configuration = configuration;
            _jwt = new JwtToken();
        }
        // 0. Đăng nhập
        [AllowAnonymous]
        [HttpPost(Name = "LOGIN")]
        [Route("login")]
        public async Task<IActionResult> UserCheckAuthentication()
        {
            try
            {
                if (Request.ContentLength == null || Request.ContentLength == 0)
                {
                    return BadRequest(new { message = "Please input Username and Password!" });
                }

                string connectionString = _configuration.GetConnectionString("DefaultConnection");
                using SqlConnection connection = new(connectionString);
                if (connection.State == ConnectionState.Closed)
                {
                    await connection.OpenAsync();
                }

                using SqlCommand command = new();
                command.Connection = connection;
                command.CommandType = CommandType.StoredProcedure;
                command.CommandText = "sp_Login";

                using (var reader = new StreamReader(Request.Body))
                {
                    var requestBody = await reader.ReadToEndAsync();

                    // Parse the JSON content to a JObject
                    var jsonObject = JObject.Parse(requestBody);
                    if (jsonObject["UserName"] == null)
                        return BadRequest(new { message = "Please input Username!" });

                    command.Parameters.AddWithValue("@UserName", jsonObject["UserName"]?.Value<string>());
                    command.Parameters.AddWithValue("@PassWord", jsonObject["PassWord"]?.Value<string>());
                }

                SqlDataAdapter da = new(command);
                DataTable dt = new();
                da.Fill(dt);

                if (dt.Rows.Count == 0)
                {
                    return BadRequest(new { message = "Tên đăng nhập hoặc mật khẩu không chính xác." });
                }

                var jwt = new JwtToken();
                var tokenString = jwt.GenerateJwtToken(
                    username: dt.Rows[0]["UserName"].ToString()
                );
                return Ok(new { token = tokenString });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message.ToString() });
            }
        }
        // 1. Đăng ký người dùng mới
        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser()
        {
            try
            {
                using var reader = new StreamReader(Request.Body);
                var requestBody = await reader.ReadToEndAsync();
                var jsonObject = JObject.Parse(requestBody);

                if (jsonObject["UserName"] == null || jsonObject["PassWord"] == null || jsonObject["UserRole"] == null)
                    return BadRequest(new { message = "Missing required fields!" });

                string connectionString = _configuration.GetConnectionString("DefaultConnection");
                using SqlConnection connection = new(connectionString);
                await connection.OpenAsync();

                using SqlCommand command = new("sp_Register", connection)
                {
                    CommandType = CommandType.StoredProcedure
                };
                command.Parameters.AddWithValue("@UserName", jsonObject["UserName"].ToString());
                command.Parameters.AddWithValue("@PassWord", jsonObject["PassWord"].ToString());
                command.Parameters.AddWithValue("@UserRole", (int)jsonObject["UserRole"]);

                await command.ExecuteNonQueryAsync();

                return Ok(new { message = "User registered successfully!" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        // 2. Đổi mật khẩu
        [Authorize]
        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword()
        {
            try
            {
                using var reader = new StreamReader(Request.Body);
                var requestBody = await reader.ReadToEndAsync();
                var jsonObject = JObject.Parse(requestBody);

                if (jsonObject["UserName"] == null || jsonObject["OldPassword"] == null || jsonObject["NewPassword"] == null)
                    return BadRequest(new { message = "Missing required fields!" });

                string connectionString = _configuration.GetConnectionString("DefaultConnection");
                using SqlConnection connection = new(connectionString);
                await connection.OpenAsync();

                using SqlCommand command = new("sp_ChangePassword", connection)
                {
                    CommandType = CommandType.StoredProcedure
                };
                command.Parameters.AddWithValue("@UserName", jsonObject["UserName"].ToString());
                command.Parameters.AddWithValue("@OldPassword", jsonObject["OldPassword"].ToString());
                command.Parameters.AddWithValue("@NewPassword", jsonObject["NewPassword"].ToString());

                await command.ExecuteNonQueryAsync();

                return Ok(new { message = "Password changed successfully!" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        // 3. Xóa người dùng
        [HttpPost("delete")]
        public async Task<ActionResult> DeleteUser()
        {
            try
            {
                string authHeader = Request.Headers["Authorization"];
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    return Unauthorized(new { message = "Missing or invalid Authorization header" });
                }

                string token = authHeader["Bearer ".Length..].Trim();

                if (_jwt.ValidateToken(token, out ClaimsPrincipal? claims))
                {
                    var userName = claims?.FindFirst(c => c.Type == "UserName")?.Value;

                    string connectionString = _configuration.GetConnectionString("DefaultConnection");
                    using SqlConnection connection = new(connectionString);
                    await connection.OpenAsync();

                    using SqlCommand command = new("sp_DeleteUser", connection)
                    {
                        CommandType = CommandType.StoredProcedure
                    };

                    using var reader = new StreamReader(Request.Body);
                    var requestBody = await reader.ReadToEndAsync();
                    var jsonObject = JObject.Parse(requestBody);

                    command.Parameters.AddWithValue("@UserId", jsonObject["UserId"]?.Value<int>());
                    command.Parameters.AddWithValue("@UserName", userName);

                    // Thực thi và nhận kết quả
                    var result = await command.ExecuteScalarAsync();
                    string message = result?.ToString() ?? "Không có phản hồi từ server";

                    return Ok(new { message });
                }
                else
                {
                    return Unauthorized(new { message = "Token is invalid" });
                }
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        // 4. Cập nhật thông tin người dùng
        [Authorize]
        [HttpPut("update")]
        public async Task<IActionResult> UpdateUser()
        {
            try
            {
                using var reader = new StreamReader(Request.Body);
                var requestBody = await reader.ReadToEndAsync();
                var jsonObject = JObject.Parse(requestBody);

                string connectionString = _configuration.GetConnectionString("DefaultConnection");
                using SqlConnection connection = new(connectionString);
                await connection.OpenAsync();

                using SqlCommand command = new("sp_UpdateUser", connection)
                {
                    CommandType = CommandType.StoredProcedure
                };
                command.Parameters.AddWithValue("@UserName", jsonObject["UserName"].ToString());
                command.Parameters.AddWithValue("@FullName", jsonObject["FullName"]?.ToString());
                command.Parameters.AddWithValue("@Gender", jsonObject["Gender"]?.ToString());
                command.Parameters.AddWithValue("@Phone", jsonObject["Phone"]?.ToString());

                await command.ExecuteNonQueryAsync();

                return Ok(new { message = "User updated successfully!" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        // 5. Lấy danh sách người dùng
        [Authorize]
        [HttpGet("all-users")]
        public async Task<IActionResult> GetAllUsers()
        {
            try
            {
                string connectionString = _configuration.GetConnectionString("DefaultConnection");
                using SqlConnection connection = new(connectionString);
                await connection.OpenAsync();

                using SqlCommand command = new("sp_GetAllUsers", connection)
                {
                    CommandType = CommandType.StoredProcedure
                };

                using SqlDataReader reader = await command.ExecuteReaderAsync();
                var users = new List<object>();

                while (await reader.ReadAsync())
                {
                    users.Add(new
                    {
                        UserId = reader["UserId"],
                        UserName = reader["UserName"],
                        FullName = reader["FullName"],
                        Gender = reader["Gender"],
                        Phone = reader["Phone"],
                        UserRole = reader["UserRole"]
                    });
                }

                return Ok(users);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error details: " + ex.ToString());
                return BadRequest(new { message = ex.Message });
            }
        }


        // 6. Lấy thông tin người dùng theo ID
        [Authorize]
        [HttpGet("{id}")]
        public async Task<IActionResult> GetUserById(int id)
        {
            try
            {
                string connectionString = _configuration.GetConnectionString("DefaultConnection");
                using SqlConnection connection = new(connectionString);
                await connection.OpenAsync();

                using SqlCommand command = new("sp_GetUserById", connection)
                {
                    CommandType = CommandType.StoredProcedure
                };
                command.Parameters.AddWithValue("@UserId", id);

                using SqlDataReader reader = await command.ExecuteReaderAsync();
                if (!reader.HasRows)
                {
                    return NotFound(new { message = "User not found!" });
                }

                await reader.ReadAsync();
                var user = new
                {
                    UserId = id,
                    UserName = reader["UserName"],
                    FullName = reader["FullName"],
                    Gender = reader["Gender"],
                    Phone = reader["Phone"],
                    UserRole = reader["UserRole"]
                };

                return Ok(user);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error details: " + ex.ToString());
                return BadRequest(new { message = ex.Message });
            }
        }

    }
}