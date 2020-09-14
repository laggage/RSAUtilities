using System;
using System.Security.Cryptography;
using Xunit;
using System.IO;
using System.Text;

namespace RSAUtilities.Test
{
    public class RSAExtensionsTests
    {
        [Fact]
        public void ImportPkcs8PrivateKeyFromPemFileTest()
        {
            var rsa = RSA.Create();
            rsa.ImportPrivateKeyFromPemFile("test-pkcs8.key");

            Assert.NotNull(rsa.ExportRSAPrivateKey());
            Assert.Equal(
                RSAExtensions.GetKeyBody(File.ReadAllText("test-pkcs8.key"))
                .Replace("\n", string.Empty)
                .Replace("\r", string.Empty), 
                Convert.ToBase64String(rsa.ExportPkcs8PrivateKey()));
        }

        [Fact]
        public void ImportPkcs1PrivateKeyFromPemFileTest()
        {
            var rsa = RSA.Create();
            rsa.ImportPrivateKeyFromPemFile("test.key");

            Assert.NotNull(rsa.ExportRSAPrivateKey());
            Assert.Equal(
                RSAExtensions.GetKeyBody(File.ReadAllText("test.key"))
                .Replace("\n", string.Empty)
                .Replace("\r", string.Empty),
                Convert.ToBase64String(rsa.ExportRSAPrivateKey()));
        }

        [Fact]
        public void ImportEncryptedPrivateKeyPemFromFileTest()
        {
            string file = "test-encrypted.key";
            string pwd = "123456789";

            var rsa = RSA.Create();
            rsa.ImportPrivateKeyFromPemFile(file, pwd);

            Assert.NotNull(rsa.ExportRSAPrivateKey());
        }

        [Theory]
        [InlineData("test.key")]
        [InlineData("test-pkcs8.key")]
        public void EncryptTest(string keyFilePath)
        {
            // Arrange
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportPrivateKeyFromPemFile(keyFilePath);
            string plainText = "laggage coding changes myworld";

            // Act
            string encrypted = rsa.EncryptToBase64(plainText);
            string decrypted = rsa.DecryptFromBase64(encrypted);

            // Assert
            Assert.Equal(plainText, decrypted);
        }
    }
}
