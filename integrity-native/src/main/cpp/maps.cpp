#include "maps.h"

namespace integrity {
namespace {

constexpr int kHexBase = 16;

bool hexDigit(char c, uint8_t* value) {
    if (c >= '0' && c <= '9') {
        *value = static_cast<uint8_t>(c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f') {
        *value = static_cast<uint8_t>(c - 'a' + 10);
        return true;
    }
    if (c >= 'A' && c <= 'F') {
        *value = static_cast<uint8_t>(c - 'A' + 10);
        return true;
    }
    return false;
}

/** Reads hex digits, refusing to wrap. Returns false on no digits or overflow. */
bool parseHex(const char* text, size_t length, size_t* index, uintptr_t* out) {
    uintptr_t value = 0;
    size_t digits = 0;
    uint8_t digit = 0;

    while (*index < length && hexDigit(text[*index], &digit)) {
        if (value > (UINTPTR_MAX - digit) / kHexBase) {
            return false;
        }
        value = value * kHexBase + digit;
        ++(*index);
        ++digits;
    }

    if (digits == 0) {
        return false;
    }
    *out = value;
    return true;
}

}  // namespace

NativeStatus parseMapsLine(const char* line, size_t length, MappedRange* out) {
    if (line == nullptr || out == nullptr || length == 0) {
        return kStatusInvalidInput;
    }

    size_t index = 0;
    uintptr_t start = 0;
    uintptr_t end = 0;

    if (!parseHex(line, length, &index, &start)) {
        return kStatusParseFailed;
    }
    if (index >= length || line[index] != '-') {
        return kStatusParseFailed;
    }
    ++index;
    if (!parseHex(line, length, &index, &end)) {
        return kStatusParseFailed;
    }
    if (index >= length || line[index] != ' ') {
        return kStatusParseFailed;
    }
    ++index;

    // Four permission characters: r w x p/s.
    if (index + 4 > length) {
        return kStatusParseFailed;
    }
    const char r = line[index];
    const char w = line[index + 1];
    const char x = line[index + 2];
    const char p = line[index + 3];
    if ((r != 'r' && r != '-') || (w != 'w' && w != '-') ||
        (x != 'x' && x != '-') || (p != 'p' && p != 's')) {
        return kStatusParseFailed;
    }

    // A kernel would not emit this, so anything producing it is not a maps line.
    if (end < start) {
        return kStatusParseFailed;
    }

    out->start = start;
    out->end = end;
    out->readable = (r == 'r');
    out->writable = (w == 'w');
    out->executable = (x == 'x');
    return kStatusOk;
}

NativeStatus rangeIsReadable(const MappedRange& range, uintptr_t address, size_t length) {
    if (length == 0) {
        return kStatusInvalidInput;
    }
    // The whole point: a range that looks fine until the arithmetic wraps.
    if (address > UINTPTR_MAX - length) {
        return kStatusInvalidInput;
    }
    if (!range.readable) {
        return kStatusUnavailable;
    }
    if (address < range.start || address + length > range.end) {
        return kStatusUnavailable;
    }
    return kStatusOk;
}

}  // namespace integrity
