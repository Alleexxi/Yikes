// Research harness: use Eglantine's current lowering algorithm on extracted instruction streams.
#include <array>
#include <charconv>
#include <cstring>
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

namespace {

// Ray-tracing BNSH modules hold several functions (raygen continuations, hit, miss) back to back.
// The control record locates them: u64 at 0xd8 gives a table base; at base+0x10 come the function
// count and base-relative offsets of the start and size arrays, at base+0x24 the relocation count
// and table. Each 40-byte relocation names a MOV whose zero immediate the driver patches with a
// continuation target; it is checked here so code is never confused with metadata.
struct RayFunction { u32 start, size; };
struct RayModule { std::vector<RayFunction> functions; std::vector<u8> code; size_t relocations{}; };

bool Read32(const std::vector<u8>& data, size_t offset, u32& value) {
    if (offset > data.size() || data.size() - offset < 4) return false;
    std::memcpy(&value, data.data() + offset, 4);
    return true;
}

std::string ParseRayModule(const std::vector<u8>& raw, RayModule& module) {
    u32 magic{}, version{}, control_size{}, code_size{};
    if (!Read32(raw, 0, magic) || magic != 0x4d54524e || !Read32(raw, 4, version) || version != 1 ||
        !Read32(raw, 8, control_size) || !Read32(raw, 12, code_size) ||
        u64{control_size} + code_size > raw.size() - 16)
        return "malformed ray tracing module: invalid NRTM envelope";
    const std::vector<u8> control(raw.begin() + 16, raw.begin() + 16 + control_size);
    module.code.assign(raw.begin() + 16 + control_size, raw.begin() + 16 + control_size + code_size);
    u32 base{}, base_high{}, count{}, starts{}, sizes{}, relocation_count{}, relocations{};
    if (!Read32(control, 0xd8, base) || !Read32(control, 0xdc, base_high) || base_high ||
        !Read32(control, u64{base} + 0x10, count) || !Read32(control, u64{base} + 0x14, starts) ||
        !Read32(control, u64{base} + 0x18, sizes) || !Read32(control, u64{base} + 0x24, relocation_count) ||
        !Read32(control, u64{base} + 0x28, relocations) || count == 0 || count > 256 || relocation_count > 4096)
        return "malformed ray tracing module: invalid function table header";
    u64 next = 0;
    for (u32 index = 0; index < count; ++index) {
        RayFunction function{};
        if (!Read32(control, u64{base} + starts + index * 4, function.start) ||
            !Read32(control, u64{base} + sizes + index * 4, function.size))
            return "malformed ray tracing module: function table outside control record";
        if (function.start != next || function.size == 0 || function.size % 16)
            return "malformed ray tracing module: functions are not contiguous 16-byte ranges";
        next += function.size;
        module.functions.push_back(function);
    }
    if (next != code_size) return "malformed ray tracing module: functions do not cover the code";
    for (u32 index = 0; index < relocation_count; ++index) {
        const u64 at = u64{base} + relocations + u64{index} * 40;
        u32 offset{}, word{}, start{}, owner{};
        if (!Read32(control, at, offset) || !Read32(control, at + 0x10, word) ||
            !Read32(control, at + 0x1c, start) || !Read32(control, at + 0x20, owner))
            return "malformed ray tracing module: relocation table outside control record";
        if (owner >= count || module.functions[owner].start != start || offset % 16 ||
            offset >= module.functions[owner].size)
            return "malformed ray tracing module: relocation outside its function";
        u32 actual{}, immediate{};
        Read32(module.code, u64{start} + offset, actual);
        Read32(module.code, u64{start} + offset + 4, immediate);
        if (actual != word || immediate != 0)
            return "malformed ray tracing module: relocation does not match its instruction";
    }
    module.relocations = relocation_count;
    return {};
}

} // namespace

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
            std::vector<u8> raw(static_cast<size_t>(length));
            std::memcpy(raw.data(), instructions.data(), raw.size());
            RayModule module;
            const std::string invalid = ParseRayModule(raw, module);
            report << name.string() << '\t' << stage << '\t';
            if (!invalid.empty()) {
                ++bad;
                ++reasons[invalid];
                report << "rejected\t0\t" << length << "\t\t\t\t" << invalid << '\n';
                continue;
            }
            // Lower every function independently; offsets are relative to the module's code.
            size_t consumed = 0;
            bool rejected = false;
            for (const auto& function : module.functions) {
                std::vector<Shader::Ampere::Instruction> body(function.size / 16);
                std::memcpy(body.data(), module.code.data() + function.start, function.size);
                auto result = Shader::Ampere::LowerToMaxwell(body,
                    {.tensor = true, .native_code_address = 0});
                if (result) {
                    consumed += result.source_size;
                    continue;
                }
                rejected = true;
                ++bad;
                ++reasons[result.error];
                report << "rejected\t" << consumed + result.source_size << '\t' << length << '\t'
                       << function.start + result.error_offset << '\t';
                if (result.error_offset / 16 < body.size()) {
                    const auto instruction = body[result.error_offset / 16];
                    const auto opcode = instruction.Bits(0, 12);
                    ++opcodes[opcode];
                    report << "0x" << std::hex << opcode << '\t';
                    for (const auto word : instruction.words) report << std::setfill('0') << std::setw(8) << word << ' ';
                    report << std::dec;
                } else {
                    report << '\t';
                }
                report << '\t' << result.error << '\n';
                break;
            }
            if (!rejected) {
                ++good;
                report << "accepted\t" << consumed << '\t' << length << "\t\t\t\t\n";
            }
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
