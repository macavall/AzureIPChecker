using System;
using System.IO;
using System.Net;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AzureIPChecker
{
    // Classes to deserialize the JSON structure
    public class AzureIPData
    {
        public int ChangeNumber { get; set; }
        public string Cloud { get; set; }
        public List<ServiceTag> Values { get; set; }
    }

    public class ServiceTag
    {
        public string Name { get; set; }
        public string Id { get; set; }
        public ServiceTagProperties Properties { get; set; }
    }

    public class ServiceTagProperties
    {
        public int ChangeNumber { get; set; }
        public string Region { get; set; }
        public int RegionId { get; set; }
        public string Platform { get; set; }
        public string SystemService { get; set; }
        public List<string> AddressPrefixes { get; set; }
        public List<string> NetworkFeatures { get; set; }
    }

    // Class to handle IP range checking
    public class IPRangeChecker
    {
        private readonly List<(IPAddress Network, int PrefixLength)> _ipRanges = new();

        public IPRangeChecker(List<string> cidrRanges)
        {
            foreach (var cidr in cidrRanges)
            {
                if (TryParseCIDR(cidr, out var network, out var prefixLength))
                {
                    _ipRanges.Add((network, prefixLength));
                }
                else
                {
                    Console.WriteLine($"Warning: Failed to parse CIDR: {cidr}");
                }
            }
        }

        private bool TryParseCIDR(string cidr, out IPAddress network, out int prefixLength)
        {
            network = null;
            prefixLength = 0;

            try
            {
                var parts = cidr.Split('/');
                if (parts.Length != 2) return false;

                if (!IPAddress.TryParse(parts[0], out network)) return false;
                if (!int.TryParse(parts[1], out prefixLength)) return false;

                // Validate prefix length
                if (network.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    if (prefixLength < 0 || prefixLength > 32) return false;
                }
                else if (network.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    if (prefixLength < 0 || prefixLength > 128) return false;
                }
                else
                {
                    return false;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool IsIPInRange(string ipAddress)
        {
            if (!IPAddress.TryParse(ipAddress, out var ip)) return false;

            foreach (var (network, prefixLength) in _ipRanges)
            {
                if (network.AddressFamily != ip.AddressFamily) continue;

                var networkBytes = network.GetAddressBytes();
                var ipBytes = ip.GetAddressBytes();
                var maskBytes = GetMaskBytes(prefixLength, ip.AddressFamily);

                bool isMatch = true;
                for (int i = 0; i < networkBytes.Length; i++)
                {
                    if ((networkBytes[i] & maskBytes[i]) != (ipBytes[i] & maskBytes[i]))
                    {
                        isMatch = false;
                        break;
                    }
                }

                if (isMatch) return true;
            }

            return false;
        }

        private byte[] GetMaskBytes(int prefixLength, System.Net.Sockets.AddressFamily addressFamily)
        {
            int byteCount = addressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 4 : 16;
            byte[] mask = new byte[byteCount];
            int remainingBits = prefixLength;

            for (int i = 0; i < byteCount; i++)
            {
                if (remainingBits >= 8)
                {
                    mask[i] = 0xFF;
                    remainingBits -= 8;
                }
                else
                {
                    mask[i] = (byte)(0xFF << (8 - remainingBits));
                    remainingBits = 0;
                }
            }

            return mask;
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                // Log the current working directory
                Console.WriteLine($"Current working directory: {Environment.CurrentDirectory}");

                // Check if file exists
                string filePath = "AzureIPs.json";
                if (!File.Exists(filePath))
                {
                    Console.WriteLine($"Error: The file '{filePath}' does not exist in the current directory.");
                    return;
                }

                // Read the JSON file
                string jsonContent = File.ReadAllText(filePath);
                if (string.IsNullOrWhiteSpace(jsonContent))
                {
                    Console.WriteLine($"Error: The file '{filePath}' is empty.");
                    return;
                }

                // Validate JSON format
                try
                {
                    JObject.Parse(jsonContent);
                }
                catch (JsonReaderException ex)
                {
                    Console.WriteLine($"Error: Invalid JSON format in '{filePath}'. Details: {ex.Message}");
                    return;
                }

                // Deserialize JSON using Newtonsoft.Json
                AzureIPData azureData;
                try
                {
                    azureData = JsonConvert.DeserializeObject<AzureIPData>(jsonContent);
                }
                catch (JsonException ex)
                {
                    Console.WriteLine($"Error: Failed to deserialize JSON. Details: {ex.Message}");
                    return;
                }

                if (azureData == null || azureData.Values == null)
                {
                    Console.WriteLine("Error: Deserialized JSON data or Values list is null.");
                    return;
                }

                // Collect all address prefixes from all service tags
                var allPrefixes = azureData.Values
                    .SelectMany(v => v.Properties.AddressPrefixes)
                    .ToList();

                if (!allPrefixes.Any())
                {
                    Console.WriteLine("Error: No address prefixes found in the JSON data.");
                    return;
                }

                // Create IP range checker
                var checker = new IPRangeChecker(allPrefixes);

                // Main loop for user input
                while (true)
                {
                    Console.WriteLine("\nEnter an IP address to check (or 'exit' to quit):");
                    string input = Console.ReadLine()?.Trim();

                    if (string.Equals(input, "exit", StringComparison.OrdinalIgnoreCase))
                        break;

                    if (string.IsNullOrEmpty(input))
                    {
                        Console.WriteLine("Please enter a valid IP address.");
                        continue;
                    }

                    // Check if the IP is in any of the ranges
                    bool isInRange = checker.IsIPInRange(input);
                    Console.WriteLine($"The IP address {input} {(isInRange ? "is" : "is not")} in the Azure IP ranges.");
                }
            }
            catch (FileNotFoundException)
            {
                Console.WriteLine("Error: AzureIPs.json file not found.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An unexpected error occurred: {ex.Message}");
            }
        }
    }
}