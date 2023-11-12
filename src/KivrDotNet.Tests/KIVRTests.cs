using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;

namespace KivrDotNet.Tests;

[TestClass]
public class KIVRTests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "0048e49bf3b94fa6f0176089f7c20699ab3ac78c7c4a1fee6ba7e288fcaed5df6f82e08776566100b6229085147689ae31f39a306192ba00b1e1f9ffd8dfa45b3f5427262d374bdb261c9410bad461e98359f669bb0e3ca51db0fd96ae21f996351c7dd19a46f90f6c6ec31f6db71920e114f41ae98e275ec17f16e7b102280e8a59c6841929ff5d20ce97353376b1bd925e64398f91",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { KIVR.RedundancySize + KIVR.TagSize, 1, KIVR.NonceSize, KIVR.KeySize, KIVR.TagSize };
        yield return new object[] { KIVR.RedundancySize + KIVR.TagSize, 0, KIVR.NonceSize + 1, KIVR.KeySize, KIVR.TagSize };
        yield return new object[] { KIVR.RedundancySize + KIVR.TagSize, 0, KIVR.NonceSize - 1, KIVR.KeySize, KIVR.TagSize };
        yield return new object[] { KIVR.RedundancySize + KIVR.TagSize, 0, KIVR.NonceSize, KIVR.KeySize + 1, KIVR.TagSize };
        yield return new object[] { KIVR.RedundancySize + KIVR.TagSize, 0, KIVR.NonceSize, KIVR.KeySize - 1, KIVR.TagSize };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, KIVR.KeySize);
        Assert.AreEqual(12, KIVR.NonceSize);
        Assert.AreEqual(16, KIVR.TagSize);
        Assert.AreEqual(20, KIVR.RedundancySize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        KIVR.Encrypt(c, p, n, k, ad);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => KIVR.Encrypt(c, p, n, k, ad));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        KIVR.Decrypt(p, c, n, k, ad);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Tampered(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        var p = new byte[plaintext.Length / 2];
        var parameters = new List<byte[]>
        {
            Convert.FromHexString(ciphertext),
            Convert.FromHexString(nonce),
            Convert.FromHexString(key),
            Convert.FromHexString(associatedData)
        };

        foreach (var param in parameters.Where(param => param.Length > 0)) {
            param[0]++;
            Assert.ThrowsException<CryptographicException>(() => KIVR.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
            param[0]--;
        }
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => KIVR.Decrypt(p, c, n, k, ad));
    }
}
