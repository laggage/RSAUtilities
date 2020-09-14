using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace RSAUtilities
{
    public static class RSAExtensions
    {
        /// <summary>
        /// 加载私钥文件中的私钥到 <see cref="RSA"/> 对象
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="path">私钥文件路径, 支持PKCS#1, PKCS#8</param>
        public static void ImportPrivateKeyFromPemFile(this RSA rsa, string path)
        {
            if (string.IsNullOrEmpty(path))
                throw new ArgumentNullException(nameof(path));
            if (!File.Exists(path))
                throw new FileNotFoundException("File cannot be found", path);

            string content = File.ReadAllText(path);
            rsa.ImportPemPrivateKey(content);
        }

        /// <summary>
        /// 将经过加密的私钥文件中私钥加载到 <see cref="RSA"/> 对象
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="path"></param>
        /// <param name="password"></param>
        public static void ImportPrivateKeyFromPemFile(this RSA rsa, string path, string password)
        {
            if (string.IsNullOrEmpty(path))
                throw new ArgumentNullException(nameof(path));
            if (!File.Exists(path))
                throw new FileNotFoundException("File cannot be found", path);

            rsa.ImportPemPrivateKey(File.ReadAllText(path), password);
        }

        /// <summary>
        /// 将BASE64编码的私钥加载到 <see cref="RSA"/> 对象
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="pemPrivateKey">
        /// PKCS#1, PKCS#8
        /// 形如:
        /// 
        /// BEGIN RSA PRIVATRE KEY
        /// Base 64 encoded string
        /// END RSA PRIVATE KEY
        /// 
        /// BEGIN PRIVATRE KEY
        /// Base 64 encoded string
        /// END PRIVATE KEY
        /// </param>
        public static void ImportPemPrivateKey(this RSA rsa, string pemPrivateKey)
        {
            string keyType = GetPrivateKeyType(pemPrivateKey); // RSA, Encrypted, ""
            string keyBody = GetKeyBody(pemPrivateKey);
            byte[] key = Convert.FromBase64String(keyBody);

            switch (keyType)
            {
                case "RSA": // PKCS#1
                    rsa.ImportRSAPrivateKey(key, out int _);
                    break;
                default:    // PKCS#8
                    rsa.ImportPkcs8PrivateKey(key, out int _);
                    break;
            }
        }

        /// <summary>
        /// 将经过加密的BASE64编码的私钥加载到 <see cref="RSA"/> 对象
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="encryptedPemPrivateKey">
        /// 加密过的PKCS#8格式的私钥
        /// 
        /// 形如:
        /// BEGIN ENCRYPTED PRIVATRE KEY
        /// Base 64 encoded string
        /// END ENCRYPTED PRIVATE KEY
        /// 
        /// </param>
        /// <param name="password">密码</param>
        public static void ImportPemPrivateKey(this RSA rsa, string encryptedPemPrivateKey, string password)
        {
            string keyBody = GetKeyBody(encryptedPemPrivateKey);
            byte[] key = Convert.FromBase64String(keyBody);
            rsa.ImportEncryptedPkcs8PrivateKey(Encoding.Default.GetBytes(password), key, out int _);
        }

        public static string GetKeyBody(string privateKey) => new Regex("(?<=PRIVATE KEY-----)(.|\n)*(?=-----END)")
                .Match(privateKey).Value
                .Trim();

        /// <summary>
        /// 通过rsa算法加密字符串
        /// </summary>
        /// <param name="text">待加密的字符串</param>
        /// <returns>Base64 encoded encrypted data</returns>
        public static string EncryptToBase64(this RSA rsa, string text)
        {
            return Convert.ToBase64String(rsa.Encrypt(Encoding.UTF8.GetBytes(text), RSAEncryptionPadding.Pkcs1));
        }

        /// <summary>
        /// rsa算法解密经过base64编码的加密内容
        /// </summary>
        /// <param name="base64EncryptedText"></param>
        /// <returns></returns>
        public static string DecryptFromBase64(this RSA rsa, string base64EncryptedText)
        {
             return Encoding.UTF8.GetString(rsa.Decrypt(Convert.FromBase64String(base64EncryptedText), RSAEncryptionPadding.Pkcs1));
        }


        private static string GetPrivateKeyType(string privateKey) => new Regex("(?<=BEGIN).*(?=PRIVATE)")
                .Match(privateKey).Value
                .Trim()
                .ToUpper();
    }
}
