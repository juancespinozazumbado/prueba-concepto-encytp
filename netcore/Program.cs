using Jose;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using AesGcm = System.Security.Cryptography.AesGcm;


string keyHex = "A8AA8DBF16EA510D943A7DB6CCCEAB8E20D3AEC1CB057C7186C842A529B775B6";
string ivHex = "3B097E347861737FCC4B6822";
string plaintext = "4224102259999908";


////USage 

// Encrypt the data
string encryptedDataJson = AES256EncryptData(keyHex, ivHex, plaintext);
// Generate the JWE token
string jweToken = GenerateJWEToken(encryptedDataJson);

Console.WriteLine("Encrypted Data JSON:");
Console.WriteLine(encryptedDataJson);
// Output the JWE token
Console.WriteLine("JWE Token:");
Console.WriteLine(jweToken);


// Decrypt the JWE token
string externalJWEToken = "eyJ0eXAiOiJKT1NFIiwiZW5jIjoiQTI1NkdDTSIsImlhdCI6IjE2MjUwNTc4OTYiLCJhbGciOiJSU0EtT0FFUC0yNTYiLCJraWQiOiIxMjM0NTYifQ.is_GR8obdpAJKMVIdZLefdtcv6b3cbnw5KaIaXUglAu_5zglTS98N4rWv7dnb9Pd4T-4kObNsZiBvpC_kZHrG_-nbeZrrSP9NCpWAz8CJiyGonT_bw0RPZO5zqZ7eFlZ3B9e-DyLmiJs_rJivusAK3h1A7Orh93Cru2ByKlzfCXH5W6s3kxx8NZHmY5TS5JhvPd6wLyQQgKpWt2sm3QVVyWrQP5tdg2Fqo1CY7MZ18f5zvx8C0wVyvFY7HxyNurrkdkG17vaWULkgkoLQSUCcRuA0PbPeK7C99VF6pEnKTSJ2c07aJxOWzmnPTCMGeAAKOw7gNTatMl-fS2XM_tPJg.33S466QcQxDctzbx.BeiVmwBRHK-54_A96EqvQHcT2pxFaQUAKcylI-OFagEK-CMKpZrefFf-w-j0SeGakP_lg1Y5AOG38JWaNCw-Gp790G5JPN5wTX37Jn2u0OVzjM6kkFAIMDutO4ILfO7kTETb193P6mirTYIQ1Ih9CN2TPKghR4-wxXvQq6HXVy816ctamUHIhCNA1yJn3fLcFuhi7R0GCKZCzkgqLCICHh144gDnV1DXQ_LHK1vmGSk1SQtHoQX18eRU8XyjdF18AONc.aMF4t2oEUj46RU79sAXfSQ\r\nGenerated JWE Token: eyJ0eXAiOiJKT1NFIiwiZW5jIjoiQTI1NkdDTSIsImlhdCI6IjE2MjUwNTc4OTYiLCJhbGciOiJSU0EtT0FFUC0yNTYiLCJraWQiOiIxMjM0NTYifQ.is_GR8obdpAJKMVIdZLefdtcv6b3cbnw5KaIaXUglAu_5zglTS98N4rWv7dnb9Pd4T-4kObNsZiBvpC_kZHrG_-nbeZrrSP9NCpWAz8CJiyGonT_bw0RPZO5zqZ7eFlZ3B9e-DyLmiJs_rJivusAK3h1A7Orh93Cru2ByKlzfCXH5W6s3kxx8NZHmY5TS5JhvPd6wLyQQgKpWt2sm3QVVyWrQP5tdg2Fqo1CY7MZ18f5zvx8C0wVyvFY7HxyNurrkdkG17vaWULkgkoLQSUCcRuA0PbPeK7C99VF6pEnKTSJ2c07aJxOWzmnPTCMGeAAKOw7gNTatMl-fS2XM_tPJg.33S466QcQxDctzbx.BeiVmwBRHK-54_A96EqvQHcT2pxFaQUAKcylI-OFagEK-CMKpZrefFf-w-j0SeGakP_lg1Y5AOG38JWaNCw-Gp790G5JPN5wTX37Jn2u0OVzjM6kkFAIMDutO4ILfO7kTETb193P6mirTYIQ1Ih9CN2TPKghR4-wxXvQq6HXVy816ctamUHIhCNA1yJn3fLcFuhi7R0GCKZCzkgqLCICHh144gDnV1DXQ_LHK1vmGSk1SQtHoQX18eRU8XyjdF18AONc.aMF4t2oEUj46RU79sAXfSQ";
string decryptedPayload = DecryptJweToken(externalJWEToken);
// Output the decrypted payload
Console.WriteLine("Decrypted Payload:");
Console.WriteLine(decryptedPayload);
// Output the encrypted data JSON


//######################## metods ##########################################################################

//// Encrypt data using AES-256 GCM 
static string AES256EncryptData(string keyHex, string ivHex, string plaintext)
{
    // Replace these with your actual hex strings

    byte[] key = Convert.FromHexString(keyHex);
    byte[] iv = Convert.FromHexString(ivHex);
    byte[] plaintextBytes = System.Text.Encoding.UTF8.GetBytes(plaintext);
    byte[] ciphertext = new byte[plaintextBytes.Length];
    byte[] tag = new byte[16]; // 128-bit tag

    using (AesGcm aesGcm = new AesGcm(key))
    {
        aesGcm.Encrypt(iv, plaintextBytes, ciphertext, tag);
    }
    string ciphertextHex = BitConverter.ToString(ciphertext).Replace("-", "").ToLower();
    string tagHex = BitConverter.ToString(tag).Replace("-", "").ToLower();

    var encryptedData = new
    {
        ciphertext = ciphertextHex,
        key = keyHex,
        iv = ivHex,
        tag = tagHex
    };

    var encriptedDataJson = System.Text.Json.JsonSerializer.Serialize(encryptedData);

    Console.WriteLine("Ciphertext: " + BitConverter.ToString(ciphertext).Replace("-", "").ToLower());
    Console.WriteLine("Auth Tag: " + BitConverter.ToString(tag).Replace("-", "").ToLower());

    return encriptedDataJson;

}


/// Generate JWE token
static string GenerateJWEToken(string encriptedDataJson)
{
    // Load the RSA public key from PEM file
    string runtimeDirectory = AppDomain.CurrentDomain.BaseDirectory;
    string projectDirectory = runtimeDirectory.Substring(0, runtimeDirectory.IndexOf("bin", StringComparison.Ordinal));
    string publicKeyPem = File.ReadAllText(Path.Combine(projectDirectory, "test_key.pem.pub"));

    // Create RSA instance and import the public key
    using RSA rsa = RSA.Create();
    rsa.ImportFromPem(publicKeyPem.ToCharArray());


    // Define the payload
    var payload = new Dictionary<string, object>
        {
            { "data", encriptedDataJson },
            { "timestamp", DateTime.UtcNow.ToString("o") }
        };

    // Define custom headers
    var headers = new Dictionary<string, object>
        {
            { "typ", "JOSE" },
            //{ "enc", "A256GCM" },
            { "iat", "1625057896" },
            //{ "alg", "RSA-OAEP-256" },
            { "kid", "123456" }
        };

    // Encrypt the payload to generate the JWE token
    string jweToken = Jose.JWT.Encode(
        encriptedDataJson, //payload,
        rsa,
        JweAlgorithm.RSA_OAEP_256,
        JweEncryption.A256GCM,
        extraHeaders: headers
    );

    Console.WriteLine("Generated JWE Token:");
    Console.WriteLine(jweToken);

    return jweToken;

}


/////// DECRYPT 
static string DecryptJweToken(string jweToken)
{
    string runtimeDirectory = AppDomain.CurrentDomain.BaseDirectory;
    string projectDirectory = runtimeDirectory.Substring(0, runtimeDirectory.IndexOf("bin", StringComparison.Ordinal));
    string publicKeyPem = File.ReadAllText(Path.Combine(projectDirectory, "test_key.pem"));

    // Create RSA instance and import the public key
    using RSA rsa = RSA.Create();
    rsa.ImportFromPem(publicKeyPem.ToCharArray());

    
    // Decrypt the token
    string decryptedPayload = Jose.JWT.Decode(jweToken, rsa);

    Console.WriteLine("Decrypted Payload:");
    Console.WriteLine(decryptedPayload);
    // Decrypt the JWE token using the provided RSA key

    return decryptedPayload;
}



