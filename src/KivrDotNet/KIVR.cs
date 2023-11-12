using System.Security.Cryptography;
using System.Buffers.Binary;
using System.Text;
using Geralt;
using ChaCha20Poly1305 = Geralt.ChaCha20Poly1305;

namespace KivrDotNet;

public static class KIVR
{
    public const int KeySize = ChaCha20.KeySize;
    public const int NonceSize = ChaCha20.NonceSize;
    public const int TagSize = Poly1305.TagSize;
    public const int RedundancySize = BLAKE2b.MaxHashSize - KeySize - NonceSize;
    private const string RedundantData = "KIVR XOR Magic Bytes";

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + RedundancySize + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> temporalData = stackalloc byte[KeySize + NonceSize + RedundancySize];
        Span<byte> tempKey = temporalData[..KeySize], tempNonce = temporalData.Slice(KeySize, NonceSize), mask = temporalData[^RedundancySize..];
        DeriveTemporalData(temporalData, key, nonce, associatedData);

        Span<byte> redundancy = Encoding.UTF8.GetBytes(RedundantData);
        for (int i = 0; i < redundancy.Length; i++) {
            redundancy[i] ^= mask[i];
        }
        Span<byte> paddedPlaintext = new byte[plaintext.Length + RedundancySize];
        redundancy.CopyTo(paddedPlaintext);
        plaintext.CopyTo(paddedPlaintext[RedundancySize..]);

        ChaCha20Poly1305.Encrypt(ciphertext, paddedPlaintext, tempNonce, tempKey, associatedData: ReadOnlySpan<byte>.Empty);
        CryptographicOperations.ZeroMemory(temporalData);
        CryptographicOperations.ZeroMemory(paddedPlaintext);
    }

    private static void DeriveTemporalData(Span<byte> temporalData, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData)
    {
        using var blake2b = new IncrementalBLAKE2b(temporalData.Length);
        blake2b.Update(key);
        blake2b.Update(nonce);
        blake2b.Update(associatedData);
        blake2b.Finalize(temporalData);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, RedundancySize + TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - RedundancySize - TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> temporalData = stackalloc byte[KeySize + NonceSize + RedundancySize];
        Span<byte> tempKey = temporalData[..KeySize], tempNonce = temporalData.Slice(KeySize, NonceSize), mask = temporalData[^RedundancySize..];
        DeriveTemporalData(temporalData, key, nonce, associatedData);

        Span<byte> block0 = stackalloc byte[ChaCha20.BlockSize], macKey = block0[..Poly1305.KeySize];
        ChaCha20.Fill(block0, tempNonce, tempKey);

        Span<byte> paddedPlaintext = new byte[ciphertext.Length - TagSize], redundancy = paddedPlaintext[..RedundancySize];
        ReadOnlySpan<byte> ciphertextNoTag = ciphertext[..^TagSize];
        ChaCha20.Decrypt(paddedPlaintext, ciphertextNoTag, tempNonce, tempKey, counter: 1);

        for (int i = 0; i < redundancy.Length; i++) {
            redundancy[i] ^= mask[i];
        }
        CryptographicOperations.ZeroMemory(temporalData);

        Span<byte> tag = stackalloc byte[Poly1305.TagSize];
        ComputeTag(tag, ciphertextNoTag, associatedData: ReadOnlySpan<byte>.Empty, macKey);
        CryptographicOperations.ZeroMemory(block0);

        bool valid = ConstantTime.Equals(tag, ciphertext[^TagSize..]);
        valid &= ConstantTime.Equals(redundancy, Encoding.UTF8.GetBytes(RedundantData));
        CryptographicOperations.ZeroMemory(tag);

        if (!valid) {
            CryptographicOperations.ZeroMemory(paddedPlaintext);
            throw new CryptographicException();
        }
        paddedPlaintext[RedundancySize..].CopyTo(plaintext);
        CryptographicOperations.ZeroMemory(paddedPlaintext);
    }

    private static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> ciphertextNoTag, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> macKey)
    {
        Span<byte> padding = stackalloc byte[16];
        padding.Clear();

        using var poly1305 = new IncrementalPoly1305(macKey);
        poly1305.Update(associatedData);
        if (associatedData.Length % 16 != 0) {
            poly1305.Update(padding[(associatedData.Length % 16)..]);
        }

        poly1305.Update(ciphertextNoTag);
        if (ciphertextNoTag.Length % 16 != 0) {
            poly1305.Update(padding[(ciphertextNoTag.Length % 16)..]);
        }

        BinaryPrimitives.WriteUInt64LittleEndian(padding[..8], (ulong)associatedData.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(padding[8..], (ulong)ciphertextNoTag.Length);
        poly1305.Update(padding);
        poly1305.Finalize(tag);
    }
}
