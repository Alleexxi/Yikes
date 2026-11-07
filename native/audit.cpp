// Research harness: use Eglantine's current lowering algorithm on extracted instruction streams.
#include <array>
#include <charconv>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#include "lowering_owned_error.h"

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: audit native-audit.tsv|--stdin report.tsv\n";
        return 2;
    }
    std::ofstream report(argv[2]);
    if (!report) return 2;
    report << "file\tstage\tstatus\tconsumed_bytes\tinput_bytes\terror_offset\topcode\twords\treason\n";
    size_t total = 0, good = 0, bad = 0, malformed = 0;
    std::map<std::string, size_t> reasons;
    std::map<u32, size_t> opcodes;
    const std::filesystem::path manifest_path{argv[1]};
    const bool piped = std::string_view{argv[1]} == "--stdin";
#ifdef _WIN32
    if (piped && _setmode(_fileno(stdin), _O_BINARY) == -1) return 2;
#endif
    std::ifstream manifest;
    if (!piped) {
        manifest.open(manifest_path);
        if (!manifest) return 2;
    }
    std::istream& entries = piped ? std::cin : manifest;
    std::string line;
    while (std::getline(entries, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto delimiter = line.find('\t');
        if (delimiter == std::string::npos) return 2;
        const std::filesystem::path name{line.substr(0, delimiter)};
        const auto second_delimiter = piped ? line.find('\t', delimiter + 1) : std::string::npos;
        if (piped && second_delimiter == std::string::npos) return 2;
        const auto stage = line.substr(delimiter + 1,
            piped ? second_delimiter - delimiter - 1 : std::string::npos);
        if (name.has_parent_path() || name.extension() != ".bin") return 2;
        std::ifstream input;
        std::streamsize length{};
        if (piped) {
            const auto* first = line.data() + second_delimiter + 1;
            const auto* last = line.data() + line.size();
            const auto parsed = std::from_chars(first, last, length);
            if (parsed.ec != std::errc{} || parsed.ptr != last) return 2;
        } else {
            const auto path = manifest_path.parent_path() / "native" / name;
            input.open(path, std::ios::binary | std::ios::ate);
            length = input.tellg();
            input.seekg(0);
        }
        if (length <= 0 || length > 16 * 131072 || length % 16) {
            ++malformed;
            report << name.string() << '\t' << stage << "\tmalformed\n";
            if (piped) return 2;
            continue;
        }
        std::vector<Shader::Ampere::Instruction> instructions(static_cast<size_t>(length) / 16);
        std::istream& binary = piped ? entries : input;
        binary.read(reinterpret_cast<char*>(instructions.data()), length);
        if (!binary) return 2;
        if (stage == "rt") {
            ++total;
            ++bad;
            const std::string reason = "unsupported ray tracing module: instruction ranges are not decoded";
            ++reasons[reason];
            report << name.string() << '\t' << stage << "\trejected\t0\t" << length
                   << "\t\t\t\t" << reason << '\n';
            continue;
        }
        auto result = Shader::Ampere::LowerToMaxwell(instructions,
            {.geometry = stage == "gs", .tensor = true, .native_code_address = 0});
        ++total;
        report << name.string() << '\t' << stage << '\t';
        if (result) {
            ++good;
            report << "accepted\t" << result.source_size << '\t' << length << "\t\t\t\t\n";
        } else {
            ++bad;
            ++reasons[result.error];
            report << "rejected\t" << result.source_size << '\t' << length << '\t'
                   << result.error_offset << '\t';
            if (result.error_offset / 16 < instructions.size()) {
                const auto instruction = instructions[result.error_offset / 16];
                const auto opcode = instruction.Bits(0, 12);
                ++opcodes[opcode];
                report << "0x" << std::hex << opcode << '\t';
                for (const auto word : instruction.words) report << std::setfill('0') << std::setw(8) << word << ' ';
                report << std::dec;
            } else {
                report << "\t";
            }
            report << '\t' << result.error << '\n';
        }
        if (total % 1000 == 0) std::cout << total << " tested; " << good << " accepted; " << bad << " rejected" << std::endl;
    }
    std::cout << "Total " << total << "; accepted " << good << "; rejected " << bad
              << "; malformed " << malformed << '\n';
    for (const auto& [reason, count] : reasons) std::cout << count << "\t" << reason << '\n';
    for (const auto& [opcode, count] : opcodes) std::cout << "opcode 0x" << std::hex << opcode << std::dec << "\t" << count << '\n';
    return malformed ? 2 : 0;
}
