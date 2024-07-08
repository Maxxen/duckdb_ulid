# DuckDB ULID

This repository is based on https://github.com/duckdb/extension-template, check it out if you want to build and ship your own DuckDB extension.

---

This extension adds a new `ULID` data type to DuckDB, based on [this specification](https://github.com/ulid/spec).
A `ULID` is similar to a `UUID` except that it also contains a timestamp component, which makes it more suitable for use cases where the order of creation is important.

The extension provides the following functions:

- `ulid()`: Returns a new `ULID` value based on the current system time.
- `ulid_timestamp(ulid)`: Returns the timestamp component of a `ULID` value.
- `ulid_epoch_ms(ulid)`: Returns the timestamp component of a `ULID` value in milliseconds since the Unix epoch.

Additionally, the extension provides cast functions to convert between `ULID` and the `VARCHAR` and `UHUGEINT` types.
A pair of `ULID`s will always sort the same regardless if it is cast to `VARCHAR` or `UHUGEINT`.

You can also cast back to `ULID` from `VARCHAR` and `UHUGEINT`. When casting from `VARCHAR` the input string is validated to ensure it is a valid `ULID`. You can use `TRY_CAST(str AS ulid)` to avoid errors when casting invalid strings.

Internally, `ULID`s are represented as `UHUGEINT`.

## Building

To build the extension, run:
```sh
make
```
The main binaries that will be built are:
```sh
./build/release/duckdb
./build/release/test/unittest
./build/release/extension/ulid/ulid.duckdb_extension
```
- `duckdb` is the binary for the duckdb shell with the extension code automatically loaded.
- `unittest` is the test runner of duckdb. Again, the extension is already linked into the binary.
- `ulid.duckdb_extension` is the loadable binary as it would be distributed.

## Running the extension
To run the extension code, simply start the shell with `./build/release/duckdb`.

Now we can use the features from the extension directly in DuckDB, for example by creating a new ULID using the `ulid()` scalar function.
```
D select ulid() as result;
┌────────────────────────────┐
│           result           │
│            ulid            │
├────────────────────────────┤
│ 01J2BD0P4RMKJXQRC4YW2RJ441 │
└────────────────────────────┘
```

## Running the tests
To run the SQL tests in `./test/sql`, simpy invoke:
```sh
make test
```
