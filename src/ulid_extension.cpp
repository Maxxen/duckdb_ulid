#define DUCKDB_EXTENSION_MAIN

#include "ulid_extension.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string.hpp"
#include "duckdb/common/types.hpp"
#include "duckdb/common/uhugeint.hpp"
#include "duckdb/common/unique_ptr.hpp"
#include "duckdb/common/vector.hpp"
#include "duckdb/common/operator/cast_operators.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/extension_util.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"

#include <chrono>

namespace duckdb {

static bool IsLittleEndian() {
	int n = 1;
	return (*char_ptr_cast(&n) == 1);
}

static_assert(sizeof(uhugeint_t) == 16, "uhugeint_t must be 16 bytes long");
static_assert(sizeof(uint8_t) == 1, "uint8_t must be 1 byte long");

struct ULID {
	static uhugeint_t Create(RandomEngine &random) {
		uint8_t data[16];

		const auto time_now = std::chrono::system_clock::now();
		const auto time_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(time_now);
		const auto timestamp = static_cast<int64_t>(time_ms.time_since_epoch().count());

		data[0] = static_cast<uint8_t>(timestamp >> 40);
		data[1] = static_cast<uint8_t>(timestamp >> 32);
		data[2] = static_cast<uint8_t>(timestamp >> 24);
		data[3] = static_cast<uint8_t>(timestamp >> 16);
		data[4] = static_cast<uint8_t>(timestamp >> 8);
		data[5] = static_cast<uint8_t>(timestamp);

		const auto random_a = random.NextRandomInteger();
		const auto random_b = random.NextRandomInteger();
		const auto random_c = random.NextRandomInteger();

		data[6] = static_cast<uint8_t>(random_a >> 24);
		data[7] = static_cast<uint8_t>(random_a >> 16);
		data[8] = static_cast<uint8_t>(random_a >> 8);
		data[9] = static_cast<uint8_t>(random_a);
		data[10] = static_cast<uint8_t>(random_b >> 24);
		data[11] = static_cast<uint8_t>(random_b >> 16);
		data[12] = static_cast<uint8_t>(random_b >> 8);
		data[13] = static_cast<uint8_t>(random_b);
		data[14] = static_cast<uint8_t>(random_c >> 24);
		data[15] = static_cast<uint8_t>(random_c >> 16);

		uhugeint_t ulid;

		ulid.upper = 0;
		ulid.upper |= static_cast<uint64_t>(data[0]) << 56;
		ulid.upper |= static_cast<uint64_t>(data[1]) << 48;
		ulid.upper |= static_cast<uint64_t>(data[2]) << 40;
		ulid.upper |= static_cast<uint64_t>(data[3]) << 32;
		ulid.upper |= static_cast<uint64_t>(data[4]) << 24;
		ulid.upper |= static_cast<uint64_t>(data[5]) << 16;
		ulid.upper |= static_cast<uint64_t>(data[6]) << 8;
		ulid.upper |= static_cast<uint64_t>(data[7]);

		// Set lower to the random data
		ulid.lower = 0;
		ulid.lower |= static_cast<uint64_t>(data[8]) << 56;
		ulid.lower |= static_cast<uint64_t>(data[9]) << 48;
		ulid.lower |= static_cast<uint64_t>(data[10]) << 40;
		ulid.lower |= static_cast<uint64_t>(data[11]) << 32;
		ulid.lower |= static_cast<uint64_t>(data[12]) << 24;
		ulid.lower |= static_cast<uint64_t>(data[13]) << 16;
		ulid.lower |= static_cast<uint64_t>(data[14]) << 8;
		ulid.lower |= static_cast<uint64_t>(data[15]);
		return ulid;
	}
};

static LogicalType ULIDType() {
	LogicalType ulid_type(LogicalType::UHUGEINT);
	ulid_type.SetAlias("ULID");
	return ulid_type;
}

struct ULIDLocalState final : public FunctionLocalState {
	explicit ULIDLocalState(const uint32_t seed) : random_engine(seed) {
	}
	RandomEngine random_engine;

	static unique_ptr<FunctionLocalState> Init(ExpressionState &state, const BoundFunctionExpression &expr,
	                                           FunctionData *bind_data) {
		auto &random_engine = RandomEngine::Get(state.GetContext());
		lock_guard<mutex> guard(random_engine.lock);
		return make_uniq<ULIDLocalState>(random_engine.NextRandomInteger());
	}
};

static void ULIDFunction(const DataChunk &args, ExpressionState &state, Vector &result) {
	auto &lstate = ExecuteFunctionState::GetFunctionState(state)->Cast<ULIDLocalState>();

	result.SetVectorType(VectorType::FLAT_VECTOR);
	const auto result_data = FlatVector::GetData<uhugeint_t>(result);

	for (idx_t i = 0; i < args.size(); i++) {
		result_data[i] = ULID::Create(lstate.random_engine);
	}
}

static bool ULIDToStringCast(Vector &source, Vector &result, idx_t count, CastParameters &) {
	// Crockford's Base32 encoding (https://www.crockford.com/base32.html)
	static constexpr char ENCODE_MAP[33] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

	UnaryExecutor::Execute<uhugeint_t, string_t>(source, result, count, [&](const uhugeint_t &input) {
		// const auto data = reinterpret_cast<const uint8_t*>(&input);
		uint8_t data[16];

		data[0] = static_cast<uint8_t>(input.upper >> 56);
		data[1] = static_cast<uint8_t>(input.upper >> 48);
		data[2] = static_cast<uint8_t>(input.upper >> 40);
		data[3] = static_cast<uint8_t>(input.upper >> 32);
		data[4] = static_cast<uint8_t>(input.upper >> 24);
		data[5] = static_cast<uint8_t>(input.upper >> 16);
		data[6] = static_cast<uint8_t>(input.upper >> 8);
		data[7] = static_cast<uint8_t>(input.upper);

		data[8] = static_cast<uint8_t>(input.lower >> 56);
		data[9] = static_cast<uint8_t>(input.lower >> 48);
		data[10] = static_cast<uint8_t>(input.lower >> 40);
		data[11] = static_cast<uint8_t>(input.lower >> 32);
		data[12] = static_cast<uint8_t>(input.lower >> 24);
		data[13] = static_cast<uint8_t>(input.lower >> 16);
		data[14] = static_cast<uint8_t>(input.lower >> 8);
		data[15] = static_cast<uint8_t>(input.lower);

		char str[26];

		// 10 byte timestamp
		str[0] = ENCODE_MAP[(data[0] & 224) >> 5];
		str[1] = ENCODE_MAP[data[0] & 31];
		str[2] = ENCODE_MAP[(data[1] & 248) >> 3];
		str[3] = ENCODE_MAP[(data[1] & 7) << 2 | (data[2] & 192) >> 6];
		str[4] = ENCODE_MAP[(data[2] & 62) >> 1];
		str[5] = ENCODE_MAP[(data[2] & 1) << 4 | (data[3] & 240) >> 4];
		str[6] = ENCODE_MAP[(data[3] & 15) << 1 | (data[4] & 128) >> 7];
		str[7] = ENCODE_MAP[(data[4] & 124) >> 2];
		str[8] = ENCODE_MAP[(data[4] & 3) << 3 | (data[5] & 224) >> 5];
		str[9] = ENCODE_MAP[data[5] & 31];

		// 16 bytes of entropy
		str[10] = ENCODE_MAP[(data[6] & 248) >> 3];
		str[11] = ENCODE_MAP[(data[6] & 7) << 2 | (data[7] & 192) >> 6];
		str[12] = ENCODE_MAP[(data[7] & 62) >> 1];
		str[13] = ENCODE_MAP[(data[7] & 1) << 4 | (data[8] & 240) >> 4];
		str[14] = ENCODE_MAP[(data[8] & 15) << 1 | (data[9] & 128) >> 7];
		str[15] = ENCODE_MAP[(data[9] & 124) >> 2];
		str[16] = ENCODE_MAP[(data[9] & 3) << 3 | (data[10] & 224) >> 5];
		str[17] = ENCODE_MAP[data[10] & 31];
		str[18] = ENCODE_MAP[(data[11] & 248) >> 3];
		str[19] = ENCODE_MAP[(data[11] & 7) << 2 | (data[12] & 192) >> 6];
		str[20] = ENCODE_MAP[(data[12] & 62) >> 1];
		str[21] = ENCODE_MAP[(data[12] & 1) << 4 | (data[13] & 240) >> 4];
		str[22] = ENCODE_MAP[(data[13] & 15) << 1 | (data[14] & 128) >> 7];
		str[23] = ENCODE_MAP[(data[14] & 124) >> 2];
		str[24] = ENCODE_MAP[(data[14] & 3) << 3 | (data[15] & 224) >> 5];
		str[25] = ENCODE_MAP[data[15] & 31];

		// Return the string
		return StringVector::AddString(result, str, 26);
	});
	return true;
}

static bool StringToULIDCast(Vector &source, Vector &result, idx_t count, CastParameters &params) {
	static constexpr uint8_t DECODE_MAP[256] = {
	    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

	    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

	    0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0xFF, 0x12, 0x13, 0xFF, 0x14, 0x15, 0xFF,
	    0x16, 0x17, 0x18, 0x19, 0x1A, 0xFF, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

	    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

	    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

	    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

	    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

	    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

	bool ok = true;

	UnaryExecutor::ExecuteWithNulls<string_t, uhugeint_t>(
	    source, result, count, [&](const string_t &blob, ValidityMask &mask, const idx_t idx) {
		    // Early-out for mismatched input size
		    if (blob.GetSize() != 26) {
			    if (ok) {
				    ok = false;
				    HandleCastError::AssignError("Invalid ULID string: string must be exactly 26 characters", params);
			    }
			    mask.SetInvalid(idx);
			    return uhugeint_t();
		    }

		    // Decode the string, checking for invalid characters
		    const auto str = blob.GetDataUnsafe();
		    uint8_t decoded_str[26];
		    for (idx_t i = 0; i < 26; i++) {
			    decoded_str[i] = DECODE_MAP[static_cast<int>(str[i])];
			    if (decoded_str[i] == 0xFF) {
				    if (ok) {
					    ok = false;
					    HandleCastError::AssignError(
					        StringUtil::Format("Invalid ULID string: invalid character '%c' at position %d", str[i], i),
					        params);
				    }
				    mask.SetInvalid(idx);
				    return uhugeint_t();
			    }
		    }

		    uint8_t data[16];

		    data[0] = decoded_str[0] << 5 | decoded_str[1];
		    data[1] = decoded_str[2] << 3 | decoded_str[3] >> 2;
		    data[2] = decoded_str[3] << 6 | decoded_str[4] << 1 | decoded_str[5] >> 4;
		    data[3] = decoded_str[5] << 4 | decoded_str[6] >> 1;
		    data[4] = decoded_str[6] << 7 | decoded_str[7] << 2 | decoded_str[8] >> 3;
		    data[5] = decoded_str[8] << 5 | decoded_str[9];

		    // entropy
		    data[6] = decoded_str[10] << 3 | decoded_str[11] >> 2;
		    data[7] = decoded_str[11] << 6 | decoded_str[12] << 1 | decoded_str[13] >> 4;
		    data[8] = decoded_str[13] << 4 | decoded_str[14] >> 1;
		    data[9] = decoded_str[14] << 7 | decoded_str[15] << 2 | decoded_str[16] >> 3;
		    data[10] = decoded_str[16] << 5 | decoded_str[17];
		    data[11] = decoded_str[18] << 3 | decoded_str[19] >> 2;
		    data[12] = decoded_str[19] << 6 | decoded_str[20] << 1 | decoded_str[21] >> 4;
		    data[13] = decoded_str[21] << 4 | decoded_str[22] >> 1;
		    data[14] = decoded_str[22] << 7 | decoded_str[23] << 2 | decoded_str[24] >> 3;
		    data[15] = decoded_str[24] << 5 | decoded_str[25];

		    // Write the data to the result
		    uhugeint_t ulid;
		    ulid.upper = 0;
		    ulid.upper |= static_cast<uint64_t>(data[0]) << 56;
		    ulid.upper |= static_cast<uint64_t>(data[1]) << 48;
		    ulid.upper |= static_cast<uint64_t>(data[2]) << 40;
		    ulid.upper |= static_cast<uint64_t>(data[3]) << 32;
		    ulid.upper |= static_cast<uint64_t>(data[4]) << 24;
		    ulid.upper |= static_cast<uint64_t>(data[5]) << 16;
		    ulid.upper |= static_cast<uint64_t>(data[6]) << 8;
		    ulid.upper |= static_cast<uint64_t>(data[7]);

		    ulid.lower = 0;
		    ulid.lower |= static_cast<uint64_t>(data[8]) << 56;
		    ulid.lower |= static_cast<uint64_t>(data[9]) << 48;
		    ulid.lower |= static_cast<uint64_t>(data[10]) << 40;
		    ulid.lower |= static_cast<uint64_t>(data[11]) << 32;
		    ulid.lower |= static_cast<uint64_t>(data[12]) << 24;
		    ulid.lower |= static_cast<uint64_t>(data[13]) << 16;
		    ulid.lower |= static_cast<uint64_t>(data[14]) << 8;
		    ulid.lower |= static_cast<uint64_t>(data[15]);

		    return ulid;
	    });
	return ok;
}

static void ULIDEpochFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::Execute<uhugeint_t, int64_t>(args.data[0], result, args.size(), [&](const uhugeint_t &input) {
		// shift off the two entropy bytes
		return input.upper >> 16;
	});
}

static void ULIDTimestampFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::Execute<uhugeint_t, timestamp_t>(args.data[0], result, args.size(), [&](const uhugeint_t &input) {
		// shift off the two entropy bytes
		const auto timestamp = input.upper >> 16;
		return Timestamp::FromEpochMs(timestamp);
	});
}

static void LoadInternal(DatabaseInstance &instance) {
	if (!IsLittleEndian()) {
		throw NotImplementedException("ULID extension only supports little endian systems");
	}

	// Register the ULID type
	ExtensionUtil::RegisterType(instance, "ULID", ULIDType());

	// Register the ULID function
	ScalarFunction ulid_function("ulid", {}, ULIDType(), ULIDFunction);
	ulid_function.stability = FunctionStability::VOLATILE;
	ulid_function.init_local_state = ULIDLocalState::Init;
	ExtensionUtil::RegisterFunction(instance, ulid_function);

	// Register the ULID epoch function
	ScalarFunction ulid_epoch_function("ulid_epoch_ms", {LogicalType::UHUGEINT}, LogicalType::BIGINT,
	                                   ULIDEpochFunction);
	ExtensionUtil::RegisterFunction(instance, ulid_epoch_function);

	// Register the ULID timestamp function
	ScalarFunction ulid_timestamp_function("ulid_timestamp", {LogicalType::UHUGEINT}, LogicalType::TIMESTAMP,
	                                       ULIDTimestampFunction);
	ExtensionUtil::RegisterFunction(instance, ulid_timestamp_function);

	// Register ulid to string cast
	ExtensionUtil::RegisterCastFunction(instance, ULIDType(), LogicalType::VARCHAR, BoundCastInfo(ULIDToStringCast), 0);

	// Register string to ulid cast
	ExtensionUtil::RegisterCastFunction(instance, LogicalType::VARCHAR, ULIDType(), BoundCastInfo(StringToULIDCast), 1);

	// Register to uhugeint cast
	ExtensionUtil::RegisterCastFunction(instance, ULIDType(), LogicalType::UHUGEINT,
	                                    BoundCastInfo(DefaultCasts::ReinterpretCast), 1);

	// Register from uhugeint cast
	ExtensionUtil::RegisterCastFunction(instance, LogicalType::UHUGEINT, ULIDType(),
	                                    BoundCastInfo(DefaultCasts::ReinterpretCast), 1);
}

void UlidExtension::Load(DuckDB &db) {
	LoadInternal(*db.instance);
}
std::string UlidExtension::Name() {
	return "ulid";
}

std::string UlidExtension::Version() const {
#ifdef EXT_VERSION_ULID
	return EXT_VERSION_ULID;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

// NOLINTNEXTLINE
DUCKDB_EXTENSION_API void ulid_init(duckdb::DatabaseInstance &db) {
	duckdb::DuckDB db_wrapper(db);
	db_wrapper.LoadExtension<duckdb::UlidExtension>();
}

// NOLINTNEXTLINE
DUCKDB_EXTENSION_API const char *ulid_version() {
	return duckdb::DuckDB::LibraryVersion();
}
}

#ifndef DUCKDB_EXTENSION_MAIN
#error DUCKDB_EXTENSION_MAIN not defined
#endif
