using System.Numerics;
using System.Security.Cryptography;

namespace ClipGuard.Core;

public enum Cryptocurrency
{
    Bitcoin,
    /// <summary>以太坊與其他 EVM 鏈（BSC、Polygon…）共用的 0x 地址。</summary>
    Ethereum,
    Tron,
}

/// <summary>
/// 辨識「整段文字就是一個錢包地址」的情形，並盡量驗證檢查碼以減少誤判：
///   BTC 1… / 3…：Base58Check；BTC bc1…：bech32（v0）/ bech32m（v1+）；
///   TRON T…：Base58Check（版本 0x41）；ETH 0x + 40 hex：格式檢查（EIP-55 需 Keccak，未驗證）。
/// </summary>
public static class WalletAddress
{
    /// <summary>
    /// 辨識成功時回傳幣別，並給出可用來比較是否為同一地址的正規化字串。
    /// </summary>
    public static bool TryParse(string? text, out Cryptocurrency currency, out string normalized)
    {
        currency = default;
        normalized = "";
        if (text is null) return false;

        var s = text.Trim();
        if (s.Length is < 26 or > 90) return false;

        if (IsEthereum(s))
        {
            (currency, normalized) = (Cryptocurrency.Ethereum, s.ToLowerInvariant());
            return true;
        }
        if (IsBech32Bitcoin(s))
        {
            (currency, normalized) = (Cryptocurrency.Bitcoin, s.ToLowerInvariant());
            return true;
        }
        if (s[0] is '1' or '3' && IsBase58Check(s, s[0] == '1' ? (byte)0x00 : (byte)0x05))
        {
            (currency, normalized) = (Cryptocurrency.Bitcoin, s);
            return true;
        }
        if (s[0] == 'T' && IsBase58Check(s, 0x41))
        {
            (currency, normalized) = (Cryptocurrency.Tron, s);
            return true;
        }
        return false;
    }

    // ---------- ETH ----------

    private static bool IsEthereum(string s) =>
        s.Length == 42 && s[0] == '0' && s[1] is 'x' or 'X' && !s.AsSpan(2).ContainsAnyExcept(HexChars);

    private static readonly System.Buffers.SearchValues<char> HexChars =
        System.Buffers.SearchValues.Create("0123456789abcdefABCDEF");

    // ---------- Base58Check ----------

    private const string Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    private static bool IsBase58Check(string s, byte version)
    {
        if (s.Length is < 26 or > 35) return false;

        BigInteger value = 0;
        foreach (var c in s)
        {
            var digit = Base58Alphabet.IndexOf(c);
            if (digit < 0) return false;
            value = value * 58 + digit;
        }

        // 1 版本 + 20 雜湊 + 4 檢查碼 = 25 bytes；開頭的 '1' 代表前導 0x00。
        var leadingZeros = s.TakeWhile(c => c == '1').Count();
        var body = value.IsZero ? [] : value.ToByteArray(isUnsigned: true, isBigEndian: true);
        var bytes = new byte[leadingZeros + body.Length];
        body.CopyTo(bytes, leadingZeros);
        if (bytes.Length != 25 || bytes[0] != version) return false;

        var hash = SHA256.HashData(SHA256.HashData(bytes.AsSpan(0, 21)));
        return hash.AsSpan(0, 4).SequenceEqual(bytes.AsSpan(21, 4));
    }

    // ---------- bech32 / bech32m（BIP-173、BIP-350） ----------

    private const string Bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private const uint Bech32Const = 1;
    private const uint Bech32mConst = 0x2bc830a3;

    private static bool IsBech32Bitcoin(string s)
    {
        if (!s.StartsWith("bc1", StringComparison.OrdinalIgnoreCase)) return false;
        // 大小寫混用是無效的 bech32。
        if (s.Any(char.IsUpper) && s.Any(char.IsLower)) return false;

        var lower = s.ToLowerInvariant();
        var data = new int[lower.Length - 3];
        for (var i = 3; i < lower.Length; i++)
        {
            var v = Bech32Charset.IndexOf(lower[i]);
            if (v < 0) return false;
            data[i - 3] = v;
        }
        if (data.Length < 7) return false;

        var version = data[0];
        var programChars = data.Length - 1 - 6;
        // v0：20 bytes（32 字）或 32 bytes（52 字）；v1 taproot：32 bytes。更高版本目前沒有使用。
        var (expectedConst, lengthOk) = version switch
        {
            0 => (Bech32Const, programChars is 32 or 52),
            1 => (Bech32mConst, programChars == 52),
            _ => (0u, false),
        };
        if (!lengthOk) return false;

        int[] hrp = ['b' >> 5, 'c' >> 5, 0, 'b' & 31, 'c' & 31];
        return Polymod([.. hrp, .. data]) == expectedConst;
    }

    private static uint Polymod(int[] values)
    {
        uint[] gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        uint chk = 1;
        foreach (var v in values)
        {
            var top = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ (uint)v;
            for (var i = 0; i < 5; i++)
                if (((top >> i) & 1) != 0) chk ^= gen[i];
        }
        return chk;
    }
}
