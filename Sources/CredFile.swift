import Foundation

/// Minimal, lossless-ish editor for the AWS shared credentials file (INI).
/// Only the sections we manage are touched; comments and every other profile are preserved.
enum CredFile {
    typealias Section = [(key: String, value: String)]

    /// Pure function: returns `old` with `set` sections replaced/inserted and `remove` sections dropped.
    static func merge(_ old: String, set: [String: Section], remove: Set<String>) -> String {
        var sections: [(name: String?, lines: [String])] = [(nil, [])]
        for line in old.components(separatedBy: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("["), t.hasSuffix("]") {
                sections.append((String(t.dropFirst().dropLast()).trimmingCharacters(in: .whitespaces), []))
            } else {
                sections[sections.count - 1].lines.append(line)
            }
        }
        func body(_ kv: Section) -> [String] { kv.map { "\($0.key) = \($0.value)" } }

        var out: [String] = []
        var seen = Set<String>()
        for s in sections {
            guard let n = s.name else { out += s.lines; continue }
            if let kv = set[n] {
                if !seen.contains(n) { out += ["", "[\(n)]"] + body(kv) }  // duplicate sections collapse into one
                seen.insert(n)
                continue
            }
            if remove.contains(n) { continue }
            out += ["", "[\(n)]"] + s.lines
        }
        for n in set.keys.sorted() where !seen.contains(n) { out += ["", "[\(n)]"] + body(set[n]!) }

        // normalize: single blank line between sections, none at the edges
        var norm: [String] = []
        for l in out {
            let blank = l.trimmingCharacters(in: .whitespaces).isEmpty
            if blank && (norm.last.map { $0.isEmpty } ?? true) { continue }
            norm.append(blank ? "" : l)
        }
        while norm.last == "" { norm.removeLast() }
        return norm.isEmpty ? "" : norm.joined(separator: "\n") + "\n"
    }

    /// Reads, merges and writes atomically (0600). No write at all when nothing changed.
    static func update(at url: URL, set: [String: Section], remove: Set<String>) throws {
        let target = url.resolvingSymlinksInPath()  // keep dotfiles symlinks intact
        let old = (try? String(contentsOf: target, encoding: .utf8)) ?? ""
        let new = merge(old, set: set, remove: remove)
        if new != old { try writeSecure(Data(new.utf8), target) }
    }
}

struct Msg: LocalizedError { let s: String; var errorDescription: String? { s } }

/// Atomic write with 0600 permissions from the first byte (temp file + rename).
func writeSecure(_ data: Data, _ url: URL) throws {
    try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    let tmp = url.path + ".ssobar-tmp"
    unlink(tmp)
    guard FileManager.default.createFile(atPath: tmp, contents: data, attributes: [.posixPermissions: 0o600]) else {
        throw Msg(s: "cannot write \(tmp)")
    }
    guard rename(tmp, url.path) == 0 else {
        let err = String(cString: strerror(errno))
        unlink(tmp)
        throw Msg(s: "rename to \(url.path) failed: \(err)")
    }
}
