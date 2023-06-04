using Microsoft.AspNetCore.Mvc;
using BCrypt.Net;
using System;
using System.Security.Cryptography;
using Konscious.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using System;
using System.Security.Cryptography;
using Konscious.Security.Cryptography;
using Scrypt;

namespace Farabi_SecureEncryptionExample.Controllers
{
    #region Useless
    [ApiController]
    [Route("[controller]")]
    public class PasswordEncryptionExampleController : ControllerBase
    {
        #endregion Useless

        #region BCrypt
        [HttpGet("BCrypt")]
        public ResponseModel enBCrypt(string password)
        {
            return new ResponseModel
            {
                Message = BCrypt.Net.BCrypt.HashPassword(password),
                Status = 200
            };
        }
        [HttpGet("BCryptVerify")]
        public ResponseModel enBCryptVerify(string password, string hashedPassword)
        {

            return new ResponseModel
            {
                Message = BCrypt.Net.BCrypt.HashPassword(password),
                Status = BCrypt.Net.BCrypt.Verify(password, hashedPassword) ? 200 : 403
            };
        }
        #endregion BCrypt

        #region PBKDF2
        [HttpGet("PBKDF2")]
        public ResponseModel enPBKDF2(string password)
        {
            byte[] salt = new byte[16];
            using (var r = new RNGCryptoServiceProvider())
            {
                r.GetNonZeroBytes(salt);
            }

            int iteration = 1000;
            string hashedPassword = "Felan hichi";
            using (var pbkdf = new Rfc2898DeriveBytes(password, salt, iteration))
            {
                byte[] hash = pbkdf.GetBytes(20);
                byte[] hashSalt = new byte[36];
                Buffer.BlockCopy(salt, 0, hashSalt, 0, 16);
                Buffer.BlockCopy(hash, 0, hashSalt, 16, 20);
                hashedPassword = Convert.ToBase64String(hashSalt);

            }

            return new ResponseModel
            {
                Message = hashedPassword + "\t\t" + Convert.ToBase64String(salt),
                Status = 200
            };
        }
        [HttpGet("PBKDF2Verify")]
        public ResponseModel enPBKDF2Verify(string password, string hashedPassword)
        {
            byte[] hashSalt = Convert.FromBase64String(hashedPassword);
            byte[] salt = new byte[16];

            Buffer.BlockCopy(hashSalt, 0, salt, 0, 16);
            int iteration = 1000;
            bool verify = true;
            using (var pbkdf = new Rfc2898DeriveBytes(password, salt, iteration))
            {
                byte[] hash = pbkdf.GetBytes(20);
                for (int i = 0; i < 20; i++)
                {
                    if (hashSalt[i + 16] != hash[i])
                    {
                        verify = false;
                    }
                }
            }
            return new ResponseModel
            {
                Message = "ok",
                Status = verify ? 200 : 403
            };
        }
        #endregion PBKDF2

        #region Argon2
        [HttpGet("Argon2")]
        public ResponseModel enArgon2(string password)
        {
            var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password));
            argon2.Iterations = 1000;
            argon2.MemorySize = 20;
            argon2.DegreeOfParallelism = 1;
            string msg = Convert.ToBase64String(argon2.GetBytes(32)); // 32-byte hash
            return new ResponseModel
            {
                Message = msg,
                Status = 200
            };
        }
        [HttpGet("Argon2Verify")]
        public ResponseModel enArgon2Verify(string password, string hashedPassword)
        {
            var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password));
            argon2.Iterations = 1000;
            argon2.MemorySize = 20;
            argon2.DegreeOfParallelism = 1;
            var expectedHash = Convert.FromBase64String(hashedPassword);
            var actualHash = argon2.GetBytes(32);

            bool verify = expectedHash.SequenceEqual(actualHash);
            return new ResponseModel
            {
                Message = expectedHash + "",
                Status = verify ? 200 : 403
            };
        }
        #endregion Argon2

        #region Scrypt
        [HttpGet("Scrypt")]
        public ResponseModel enScrypt(string password)
        {

            byte[] salt = new byte[16];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt);
            }


            var encoder = new ScryptEncoder();

            string hashedPassword = encoder.Encode(password);

            return new ResponseModel
            {
                Message = hashedPassword,
                Status = 200
            };
        }
        [HttpGet("ScryptVerify")]
        public ResponseModel enScryptVerify(string password, string hashedPassword)
        {
            var encoder = new ScryptEncoder();

            bool isValid = encoder.Compare(password, hashedPassword);
            
            return new ResponseModel
            {
                Message = isValid+ "",
                Status = isValid ? 200 : 403
            };
        }
        #endregion Scrypt

    }
    #region ResponseModel
    public class ResponseModel
    {
        public string Message { get; set; }
        public int Status { get; set; }
    }
    #endregion ResponseModel

}