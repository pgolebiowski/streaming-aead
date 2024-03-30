# StreamingAead.Tests.Interop

## About

This test suite is designed to ensure compatibility between `StreamingAead` and Google's Tink cryptographic library. Specifically, it verifies that data encrypted with one mechanism can be decrypted with the other, and vice versa. Such cross-compatibility testing is crucial for validating interoperability between these systems.

The tests use the Python build of Tink, following the example script provided in the [Tink documentation](https://developers.google.com/tink/encrypt-data#python).

## How to run this?

To first prepare the Python environment, run:

```sh
python3 -m venv venv
source venv/bin/activate.fish # or whatever shell you're using
pip3 install tink
```

Then, while having the virtual environment activated, just execute:

```sh
set -x TMPDIR "/path/to/your/large/volume/tmp"

# Smaller size tests
dotnet test --filter "Category != LargeStorage"

# All tests, including those requiring substantial storage capacity
dotnet test
```
