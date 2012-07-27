using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace TwoFactor
{
    public static class Extensions
    {
        public static long ToUnix(this DateTime val)
        {
            return (long)(val - TimeBasedOneTimePassword.UNIX_EPOCH).TotalSeconds;
        }
    }
}
