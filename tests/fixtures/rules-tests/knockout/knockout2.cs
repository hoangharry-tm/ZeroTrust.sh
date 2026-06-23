// KNOCKOUT: completely unrelated code — no security context, no async void
// This file should NOT trigger any security rule.
using System.Threading.Tasks;

public class DataProcessor
{
    public async Task<int> ProcessItemsAsync(int[] items)
    {
        int total = 0;
        foreach (var item in items)
        {
            total += await ProcessItemAsync(item);
        }
        return total;
    }

    private Task<int> ProcessItemAsync(int item)
    {
        return Task.FromResult(item * item);
    }

    public double CalculateAverage(int[] numbers)
    {
        if (numbers.Length == 0) return 0;
        long sum = 0;
        foreach (var n in numbers) sum += n;
        return (double)sum / numbers.Length;
    }
}
