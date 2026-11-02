// Tests for CredFile (no XCTest needed, so it runs with just the Command Line Tools).
// Run: Tests/run.sh
import Foundation

var failures = 0
func check(_ name: String, _ got: String, _ want: String) {
    if got == want { print("ok   \(name)") } else {
        failures += 1
        print("FAIL \(name)\n--- got ---\n\(got)--- want ---\n\(want)")
    }
}

let kv: CredFile.Section = [("aws_access_key_id", "NEW"), ("region", "eu-west-1")]

check("insert into empty file", CredFile.merge("", set: ["dev": kv], remove: []),
      "[dev]\naws_access_key_id = NEW\nregion = eu-west-1\n")

check("empty stays empty", CredFile.merge("", set: [:], remove: ["x"]), "")

let input = """
# my comment
[static]
aws_access_key_id = KEEP

[live]
aws_access_key_id = OLD
aws_session_token = OLD
[test]
aws_access_key_id = T


[other]
x = 1

"""
check("replace, remove, keep others and comments",
      CredFile.merge(input, set: ["live": kv, "brandnew": [("a", "b")]], remove: ["test"]), """
# my comment

[static]
aws_access_key_id = KEEP

[live]
aws_access_key_id = NEW
region = eu-west-1

[other]
x = 1

[brandnew]
a = b

""")

check("set wins over remove", CredFile.merge("[a]\nx = 1\n", set: ["a": [("x", "2")]], remove: ["a"]), "[a]\nx = 2\n")

check("duplicate managed sections collapse", CredFile.merge("[a]\nx = 1\n[a]\nx = 9\n", set: ["a": [("x", "2")]], remove: []),
      "[a]\nx = 2\n")

check("whitespace in header", CredFile.merge("[ a ]\nx = 1\n", set: ["a": [("x", "2")]], remove: []), "[a]\nx = 2\n")

let stable = CredFile.merge(input, set: ["live": kv], remove: [])
check("idempotent", CredFile.merge(stable, set: ["live": kv], remove: []), stable)

// file-level behaviour: 0600, no rewrite when unchanged, symlink preserved
let dir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("ssobar-test-\(getpid())")
try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(at: dir) }
let real = dir.appendingPathComponent("real-credentials")
let link = dir.appendingPathComponent("credentials")
try! "[keep]\nx = 1\n".write(to: real, atomically: true, encoding: .utf8)
try! FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)

try! CredFile.update(at: link, set: ["dev": kv], remove: [])
let perms = (try! FileManager.default.attributesOfItem(atPath: real.path)[.posixPermissions] as! NSNumber).intValue
check("written with 0600", String(perms, radix: 8), "600")
let isLink = (try? FileManager.default.destinationOfSymbolicLink(atPath: link.path)) != nil
check("symlink preserved", "\(isLink)", "true")
let inode1 = try! FileManager.default.attributesOfItem(atPath: real.path)[.systemFileNumber] as! NSNumber
try! CredFile.update(at: link, set: ["dev": kv], remove: [])
let inode2 = try! FileManager.default.attributesOfItem(atPath: real.path)[.systemFileNumber] as! NSNumber
check("no rewrite when unchanged", "\(inode1 == inode2)", "true")

if failures > 0 { print("\(failures) failure(s)"); exit(1) }
print("all tests passed")
