// Bounded multi-pattern search. SSE2 is part of the Windows x64 baseline.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <emmintrin.h>
#include <intrin.h>

extern "C" __declspec(dllexport) std::size_t find_markers(
    const unsigned char* data, std::size_t size, std::uint64_t* output, std::size_t capacity) {
    static constexpr unsigned char patterns[5][8] = {
        {'B', 'N', 'S', 'H', 0, 0, 0, 0},
        {0x91, 0x68, 0x86, 0x19}, {0x34, 0x12, 0x76, 0x98},
        {0x28, 0xb5, 0x2f, 0xfd}, {0x04, 0x22, 0x4d, 0x18}};
    const auto a = _mm_set1_epi8('B');
    const auto b = _mm_set1_epi8(static_cast<char>(0x91));
    const auto c = _mm_set1_epi8(0x34);
    const auto d = _mm_set1_epi8(0x28);
    const auto e = _mm_set1_epi8(0x04);
    std::size_t count = 0;
    auto check = [&](std::size_t at) {
        unsigned tag;
        switch (data[at]) {
        case 'B': tag = 0; break;
        case 0x91: tag = 1; break;
        case 0x34: tag = 2; break;
        case 0x28: tag = 3; break;
        case 0x04: tag = 4; break;
        default: return true;
        }
        const std::size_t length = tag == 0 ? 8 : 4;
        if (size - at >= length && std::memcmp(data + at, patterns[tag], length) == 0) {
            if (count == capacity) return false;
            output[count++] = (static_cast<std::uint64_t>(at) << 3) | tag;
        }
        return true;
    };
    std::size_t at = 0;
    for (; size - at >= 16; at += 16) {
        const auto block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data + at));
        const auto mask = _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(block, a), _mm_cmpeq_epi8(block, b)),
            _mm_or_si128(_mm_cmpeq_epi8(block, c),
                         _mm_or_si128(_mm_cmpeq_epi8(block, d), _mm_cmpeq_epi8(block, e))));
        auto hits = static_cast<unsigned>(_mm_movemask_epi8(mask));
        while (hits) {
            unsigned long bit;
            _BitScanForward(&bit, hits);
            if (!check(at + bit)) return capacity + 1;
            hits &= hits - 1;
        }
    }
    for (; at < size; ++at) {
        if (!check(at)) return capacity + 1;
    }
    return count;
}
