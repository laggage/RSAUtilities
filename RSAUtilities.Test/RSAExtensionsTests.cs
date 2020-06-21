using System;
using System.Security.Cryptography;
using Xunit;
using System.IO;

namespace RSAUtilities.Test
{
    public class RSAExtensionsTests
    {
        [Fact]
        public void LoadPrivateKeyFromFileTest()
        {
            var rsa = RSA.Create();
            rsa.LoadPrivateKeyFromFile("test.key");

            Assert.NotNull(rsa.ExportRSAPrivateKey());
            Assert.Equal(
                RSAExtensions.GetKeyBody(File.ReadAllText("test.key"))
                .Replace("\n", string.Empty)
                .Replace("\r", string.Empty), 
                Convert.ToBase64String(rsa.ExportRSAPrivateKey()));
        }

        [Fact]
        public void LoadEncryptedPrivateKeyFromFileTest()
        {
            string file = "test-encrypted.key";
            string pwd = "123456789";

            var rsa = RSA.Create();
            rsa.LoadEncryptedPrivateKeyFromFile(file, pwd);

            Assert.NotNull(rsa.ExportRSAPrivateKey());
        }
    }
}
