// KNOCKOUT: completely unrelated code — no security context, no NotImplementedException
// This file should NOT trigger any security rule.
using System;
using System.Collections.Generic;
using System.Linq;

public static class MathHelpers
{
    public static long Factorial(int n)
    {
        if (n <= 1) return 1;
        long result = 1;
        for (int i = 2; i <= n; i++) result *= i;
        return result;
    }

    public static double Median(double[] values)
    {
        Array.Sort(values);
        int n = values.Length;
        if (n % 2 == 0)
            return (values[n / 2 - 1] + values[n / 2]) / 2.0;
        return values[n / 2];
    }

    public static Dictionary<T, int> CountFrequency<T>(IEnumerable<T> items) where T : notnull
    {
        return items.GroupBy(x => x).ToDictionary(g => g.Key, g => g.Count());
    }

    public static string Reverse(string s)
    {
        return new string(s.Reverse().ToArray());
    }
}
