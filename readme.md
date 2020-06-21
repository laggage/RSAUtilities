## Description

基于.netstandard2.1, 提供一些扩展方法可以方便的从私钥文件中加载私钥到`RSA`对象, 支持**PKCS#1**, **PKCS#8**, 和**Encrypted PKCS#8**;

## How to use

```csharp
var rsa = RSA.Create();
rsa.LoadPrivateKeyFromFile("test.key");
rsa.Encrypt(...);
```

## Install

```bash
dotnet add package RSAUtilities --version 0.0.1
```