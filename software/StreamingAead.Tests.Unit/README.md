# StreamingAead.Tests.Unit

To execute the basic set of unit tests, which covers a comprehensive range of edge cases and should complete in ~1 second, use the following command:

```sh
dotnet test --filter "Category != HeavyCompute & Category != LargeStorage"
```

If you wish to run the tests that are more demanding on resources, use the following commands:

```sh
# For tests requiring significant computational power
dotnet test --filter "Category = HeavyCompute"

# For tests requiring substantial storage capacity
set -x TMPDIR "/path/to/your/large/volume/tmp"
dotnet test --filter "Category = LargeStorage"
```

