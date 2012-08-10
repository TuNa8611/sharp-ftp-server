using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace TwoFactor
{
    public static class HashedOneTimePassword
    {
        public static string GeneratePassword(string secret, long iterationNumber, int digits = 6)
        {
            byte[] counter = BitConverter.GetBytes(iterationNumber);

            byte[] hash = GetHMAC(Encoding.ASCII.GetBytes(secret), counter);

            int offset = hash[hash.Length - 1] & 0xf;

            int binary =
                ((hash[offset] & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8)
                | (hash[offset + 3] & 0xff);

            int password = binary % (int)Math.Pow(10, digits); // 6 digits

            return password.ToString(new string('0', digits));
        }

        private static byte[] GetHMAC(byte[] key, byte[] counter)
        {
            System.Security.Cryptography.HMACSHA1 hmac = new System.Security.Cryptography.HMACSHA1(key, true);

            return hmac.ComputeHash(counter);
        }
    }
}