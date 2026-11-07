// IPC wrapper for the separately fetched, pinned GPL-3.0-or-later ooz decoder
// and the ZBIC decoder used by Eglantine. Game bytes stay in this local process.
#include <cstdio>
#include <cstdint>
#include <climits>
#include <iostream>
#include <string>
#include <vector>
#include <fcntl.h>
#include <io.h>
#include "zstd.h"

int Kraken_Decompress(const unsigned char*, size_t, unsigned char*, size_t);

int main() {
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    std::ios::sync_with_stdio(false);
    std::string mode;
    std::size_t packed, size;
    while (std::cin >> mode >> packed >> size) {
        if (std::cin.get() != '\n' || !packed || !size || size > INT_MAX || packed > INT_MAX) return 2;
        // ooz requires readable/writable padding at the end of its buffers.
        std::vector<unsigned char> input(packed + 64), output(size + 64);
        if (!std::cin.read(reinterpret_cast<char*>(input.data()), packed)) return 3;
        std::uint64_t result = UINT64_MAX;
        if (mode == "oodle") {
            const int decoded = Kraken_Decompress(input.data(), packed, output.data(), size);
            if (decoded >= 0 && static_cast<std::size_t>(decoded) == size) result = size;
        } else if (mode == "zbic") {
            const auto decoded = ZSTD_decompress(output.data(), size, input.data(), packed);
            if (!ZSTD_isError(decoded) && decoded == size) result = size;
        }
        std::cout.write(reinterpret_cast<const char*>(&result), sizeof(result));
        if (result != UINT64_MAX) std::cout.write(reinterpret_cast<const char*>(output.data()), size);
        std::cout.flush();
        if (!std::cout) return 4;
    }
    return 0;
}
