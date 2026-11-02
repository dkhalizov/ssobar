// SSOBar — a tiny macOS menu bar app that keeps AWS IAM Identity Center (SSO) role credentials
// in ~/.aws/credentials and refreshes them automatically.
//
// No dependencies: the SSO OIDC and SSO portal APIs are plain HTTPS + JSON (no SigV4 signing needed).
// SPDX-License-Identifier: MIT

import AppKit
import Network
import ServiceManagement

// MARK: - Paths

let home = FileManager.default.homeDirectoryForCurrentUser
let configDir = home.appendingPathComponent(".config/ssobar")
let configURL = configDir.appendingPathComponent("config.json")
let stateURL = configDir.appendingPathComponent("state.json")
let defaultCredsPath = "~/.aws/credentials"

func expandTilde(_ p: String) -> URL {
    URL(fileURLWithPath: p.hasPrefix("~/") ? home.path + String(p.dropFirst(1)) : p)
}

// MARK: - Model

struct Session: Codable {
    var name: String
    var accountId: String
    var roleName: String
    var region: String?      // defaults to Config.ssoRegion
    var profile: String
    var active: Bool
    var key: String { "\(profile)|\(accountId)|\(roleName)" }
}

struct Config: Codable {
    var startUrl: String
    var ssoRegion: String
    var refreshMinutesBefore: Int?   // default 10
    var credentialsFile: String?     // default ~/.aws/credentials
    var sessions: [Session]

    var credsURL: URL { expandTilde(credentialsFile ?? defaultCredsPath) }
}

/// Secrets (0600). Never shown in UI.
struct State: Codable {
    var startUrl: String?
    var region: String?
    var clientId: String?
    var clientSecret: String?
    var clientExpiresAt: Date?
    var accessToken: String?
    var accessExpiresAt: Date?
    var refreshToken: String?
    var managedProfiles: [String]?
}

struct Creds: Sendable { let akid, secret, token: String; let expiration: Date }

struct APIError: LocalizedError {
    let status: Int, code: String, message: String
    var errorDescription: String? { message.isEmpty ? "\(code) (HTTP \(status))" : "\(code): \(message)" }
}
struct NeedsLogin: LocalizedError { var errorDescription: String? { "Not signed in to AWS SSO" } }

// MARK: - Helpers

let encoder: JSONEncoder = {
    let e = JSONEncoder()
    e.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    e.dateEncodingStrategy = .secondsSince1970
    return e
}()
let decoder: JSONDecoder = {
    let d = JSONDecoder()
    d.dateDecodingStrategy = .secondsSince1970
    return d
}()

func num(_ a: Any?) -> Double? { (a as? NSNumber)?.doubleValue }

func http(_ method: String, _ url: URL, json: [String: Any]? = nil, headers: [String: String] = [:]) async throws -> [String: Any] {
    var req = URLRequest(url: url, timeoutInterval: 20)
    req.httpMethod = method
    for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
    if let json {
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: json)
    }
    let (data, resp) = try await URLSession.shared.data(for: req)
    let hr = resp as? HTTPURLResponse
    let status = hr?.statusCode ?? 0
    let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
    guard (200..<300).contains(status) else {
        let code = (obj["error"] as? String)
            ?? hr?.value(forHTTPHeaderField: "x-amzn-errortype").map { String($0.split(separator: ":").first ?? "") }
            ?? "HTTP\(status)"
        let msg = (obj["error_description"] as? String) ?? (obj["message"] as? String) ?? ""
        throw APIError(status: status, code: code, message: msg)
    }
    return obj
}

func portalURL(_ portal: String, _ path: String, _ q: [String: String?]) -> URL {
    var c = URLComponents(string: portal + path)!
    c.queryItems = q.compactMap { k, v in v.map { URLQueryItem(name: k, value: $0) } }
    return c.url!
}

func fetchRoleCreds(portal: String, account: String, role: String, token: String) async throws -> Creds {
    let r = try await http("GET", portalURL(portal, "/federation/credentials", ["account_id": account, "role_name": role]),
                           headers: ["x-amz-sso_bearer_token": token])
    guard let rc = r["roleCredentials"] as? [String: Any],
          let a = rc["accessKeyId"] as? String, let s = rc["secretAccessKey"] as? String, let t = rc["sessionToken"] as? String
    else { throw Msg(s: "GetRoleCredentials: unexpected response") }
    let exp = Date(timeIntervalSince1970: (num(rc["expiration"]) ?? 0) / 1000)
    return Creds(akid: a, secret: s, token: t, expiration: exp)
}

func fetchAll(_ items: [(String, Session)], portal: String, token: String) async -> [String: Result<Creds, Error>] {
    await withTaskGroup(of: (String, Result<Creds, Error>).self) { g in
        for (p, s) in items {
            g.addTask {
                do { return (p, .success(try await fetchRoleCreds(portal: portal, account: s.accountId, role: s.roleName, token: token))) }
                catch { return (p, .failure(error)) }
            }
        }
        var out: [String: Result<Creds, Error>] = [:]
        for await (p, r) in g { out[p] = r }
        return out
    }
}

struct FoundRole: Sendable { let account, accountName, role: String }

func listAllRoles(portal: String, token: String) async throws -> [FoundRole] {
    let h = ["x-amz-sso_bearer_token": token]
    var accounts: [(String, String)] = []
    var next: String? = nil
    repeat {
        let r = try await http("GET", portalURL(portal, "/assignment/accounts", ["max_result": "100", "next_token": next]), headers: h)
        for a in (r["accountList"] as? [[String: Any]]) ?? [] {
            if let id = a["accountId"] as? String { accounts.append((id, a["accountName"] as? String ?? id)) }
        }
        next = r["nextToken"] as? String
    } while next != nil

    return try await withThrowingTaskGroup(of: [FoundRole].self) { g in
        for (id, name) in accounts {
            g.addTask {
                var out: [FoundRole] = []
                var next: String? = nil
                repeat {
                    let r = try await http("GET", portalURL(portal, "/assignment/roles", ["account_id": id, "max_result": "100", "next_token": next]), headers: h)
                    for x in (r["roleList"] as? [[String: Any]]) ?? [] {
                        if let role = x["roleName"] as? String { out.append(FoundRole(account: id, accountName: name, role: role)) }
                    }
                    next = r["nextToken"] as? String
                } while next != nil
                return out
            }
        }
        var all: [FoundRole] = []
        for try await r in g { all += r }
        return all.sorted { ($0.accountName.lowercased(), $0.role) < ($1.accountName.lowercased(), $1.role) }
    }
}

// MARK: - SSO (OIDC device flow + refresh token)

@MainActor final class SSO {
    var st: State
    var startUrl = ""
    var region = "eu-west-1"
    var onStatus: ((String?) -> Void)?
    var loginURL: URL?
    private var tokenTask: (seq: Int, task: Task<String, Error>)?
    private var tokenSeq = 0

    init(state: State) { st = state }

    var oidc: String { "https://oidc.\(region).amazonaws.com" }
    var portal: String { "https://portal.sso.\(region).amazonaws.com" }
    var hasValidAccess: Bool { (st.accessExpiresAt?.timeIntervalSinceNow ?? 0) > 120 && st.accessToken != nil }
    var signedIn: Bool { hasValidAccess || st.refreshToken != nil }

    func configure(startUrl: String, region: String) {
        self.startUrl = startUrl
        self.region = region
        if st.startUrl != startUrl || st.region != region {
            let managed = st.managedProfiles
            st = State(startUrl: startUrl, region: region, managedProfiles: managed)
            save()
        }
    }

    func save() { if let d = try? encoder.encode(st) { try? writeSecure(d, stateURL) } }

    func invalidateAccess() { st.accessToken = nil; st.accessExpiresAt = nil; save() }

    func signOut() {
        if let t = st.accessToken, let u = URL(string: portal + "/logout") {
            Task.detached { _ = try? await http("POST", u, headers: ["x-amz-sso_bearer_token": t]) }
        }
        st.accessToken = nil; st.accessExpiresAt = nil; st.refreshToken = nil
        save()
    }

    /// Single-flight: concurrent callers share one in-flight token request, so at most one device login (= one browser tab) exists.
    func accessToken(interactive: Bool) async throws -> String {
        if hasValidAccess, let t = st.accessToken { return t }
        if let cur = tokenTask {
            do { return try await cur.task.value }
            catch is NeedsLogin where interactive {
                // The shared attempt was silent-only but the user asked explicitly: start an interactive one
                // (or join one that another explicit caller already started).
                if hasValidAccess, let t = st.accessToken { return t }
                if let newer = tokenTask, newer.seq != cur.seq { return try await newer.task.value }
            }
        }
        tokenSeq += 1
        let mine = tokenSeq
        let task = Task { try await self.obtain(interactive: interactive) }
        tokenTask = (mine, task)
        defer { if tokenTask?.seq == mine { tokenTask = nil } }
        return try await task.value
    }

    private func obtain(interactive: Bool) async throws -> String {
        try await ensureClient()
        if let rt = st.refreshToken, let id = st.clientId, let sec = st.clientSecret {
            do {
                let r = try await http("POST", URL(string: oidc + "/token")!, json: [
                    "clientId": id, "clientSecret": sec, "grantType": "refresh_token", "refreshToken": rt,
                ])
                return try storeToken(r)
            } catch let e as APIError where (400..<500).contains(e.status) && e.status != 429
                                            && !e.code.lowercased().contains("throttl") && e.code != "slow_down" {
                // session really ended -> need browser. (Network errors / throttling keep the refresh token.)
                st.refreshToken = nil; st.accessToken = nil
                if e.code.lowercased().contains("client") { st.clientId = nil; st.clientSecret = nil }
                save()
                try await ensureClient()
            }
        }
        guard interactive else { throw NeedsLogin() }
        return try await deviceLogin()
    }

    private func ensureClient() async throws {
        if st.clientId != nil, st.clientSecret != nil, let e = st.clientExpiresAt, e.timeIntervalSinceNow > 86400 { return }
        let r = try await http("POST", URL(string: oidc + "/client/register")!, json: [
            "clientName": "ssobar", "clientType": "public", "scopes": ["sso:account:access"],
        ])
        guard let id = r["clientId"] as? String, let sec = r["clientSecret"] as? String else {
            throw Msg(s: "RegisterClient: unexpected response")
        }
        st.clientId = id; st.clientSecret = sec
        st.clientExpiresAt = num(r["clientSecretExpiresAt"]).map { Date(timeIntervalSince1970: $0) } ?? Date().addingTimeInterval(86400 * 80)
        st.refreshToken = nil
        save()
    }

    private func storeToken(_ r: [String: Any]) throws -> String {
        guard let at = r["accessToken"] as? String else { throw Msg(s: "CreateToken: unexpected response") }
        st.accessToken = at
        st.accessExpiresAt = Date().addingTimeInterval(num(r["expiresIn"]) ?? 3600)
        if let rt = r["refreshToken"] as? String { st.refreshToken = rt }
        save()
        return at
    }

    private func deviceLogin() async throws -> String {
        guard let id = st.clientId, let sec = st.clientSecret else { throw Msg(s: "no OIDC client") }
        let r = try await http("POST", URL(string: oidc + "/device_authorization")!, json: [
            "clientId": id, "clientSecret": sec, "startUrl": startUrl,
        ])
        guard let deviceCode = r["deviceCode"] as? String,
              let uri = (r["verificationUriComplete"] as? String) ?? (r["verificationUri"] as? String),
              let url = URL(string: uri)
        else { throw Msg(s: "StartDeviceAuthorization: unexpected response") }
        var interval = num(r["interval"]) ?? 5
        let deadline = Date().addingTimeInterval(num(r["expiresIn"]) ?? 600)
        let code = r["userCode"] as? String ?? ""

        loginURL = url
        onStatus?("Approve in browser · code \(code)")
        defer { loginURL = nil; onStatus?(nil) }
        NSWorkspace.shared.open(url)

        while Date() < deadline {
            try await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
            do {
                let t = try await http("POST", URL(string: oidc + "/token")!, json: [
                    "clientId": id, "clientSecret": sec,
                    "grantType": "urn:ietf:params:oauth:grant-type:device_code", "deviceCode": deviceCode,
                ])
                return try storeToken(t)
            } catch let e as APIError where e.code == "authorization_pending" {
                continue
            } catch let e as APIError where e.code == "slow_down" {
                interval += 5
            } catch is URLError {
                continue   // network blip (e.g. just woke up): keep polling the same code, don't open a new tab
            }
        }
        throw Msg(s: "Sign-in timed out")
    }
}

// MARK: - App

@MainActor final class App: NSObject, NSApplicationDelegate, NSMenuDelegate {
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    let menu = NSMenu()
    var sso = SSO(state: (try? Data(contentsOf: stateURL)).flatMap { try? decoder.decode(State.self, from: $0) } ?? State())
    var cfg: Config?
    var cfgError: String?
    var cfgMTime: Date?
    var expiry: [String: Date] = [:]     // profile -> creds expiration
    var written: [String: String] = [:]  // profile -> session key currently in credentials file
    var errors: [String] = []
    var status: String?
    /// Browser auto-open policy: at most ONE automatic tab per "you're back" event (launch, wake, unlock,
    /// screen on, successful sign-in), and only while you're actually at the keyboard.
    var autoPromptArmed = true
    var busy = false
    var again: (interactive: Bool, force: Bool)?
    var timer: Timer?
    let net = NWPathMonitor()
    var netUp = true

    func applicationDidFinishLaunching(_ n: Notification) {
        // single instance: a second copy would be a second writer and a second login tab
        if let id = Bundle.main.bundleIdentifier,
           NSRunningApplication.runningApplications(withBundleIdentifier: id).contains(where: { $0 != .current }) {
            NSApp.terminate(nil)
            return
        }
        sso.onStatus = { [weak self] s in
            guard let self else { return }
            self.status = s
            if s != nil { self.autoPromptArmed = false }
            self.updateIcon()
        }
        loadConfig()
        menu.delegate = self
        menu.autoenablesItems = false
        item.menu = menu
        updateIcon()

        let t = Timer(timeInterval: 60, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.tick() }
        }
        t.tolerance = 5
        RunLoop.main.add(t, forMode: .common)   // keep ticking while the menu is open
        timer = t

        // "user is back" events: re-arm one auto prompt and refresh right away
        let ws = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.didWakeNotification, NSWorkspace.screensDidWakeNotification, NSWorkspace.sessionDidBecomeActiveNotification] {
            ws.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.userIsBack() }
            }
        }
        DistributedNotificationCenter.default().addObserver(forName: .init("com.apple.screenIsUnlocked"), object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.userIsBack() }
        }
        // network came back (after wake, Wi-Fi switch, VPN): refresh immediately instead of waiting a minute
        net.pathUpdateHandler = { [weak self] path in
            let up = path.status == .satisfied
            Task { @MainActor in
                guard let self else { return }
                if up && !self.netUp { self.tick() }
                self.netUp = up
            }
        }
        net.start(queue: .main)
        tick()
    }

    func userIsBack() {
        autoPromptArmed = true
        tick()
    }

    /// True only if someone is at the Mac: recent input and screen not locked.
    func userPresent() -> Bool {
        let anyInput = CGEventType(rawValue: ~0)!
        if CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: anyInput) > 120 { return false }
        if let d = CGSessionCopyCurrentDictionary() as? [String: Any], d["CGSSessionScreenIsLocked"] as? Bool == true { return false }
        return true
    }

    // MARK: Config

    func loadConfigIfChanged() {
        let m = (try? FileManager.default.attributesOfItem(atPath: configURL.path))?[.modificationDate] as? Date
        if m != cfgMTime { loadConfig() }
    }

    func loadConfig() {
        cfgMTime = (try? FileManager.default.attributesOfItem(atPath: configURL.path))?[.modificationDate] as? Date
        guard let d = try? Data(contentsOf: configURL) else {
            cfg = Config(startUrl: "https://YOUR-PORTAL.awsapps.com/start/", ssoRegion: "eu-west-1", refreshMinutesBefore: 10, sessions: [])
            saveConfig()
            cfgError = "Set startUrl in config (Edit config…)"
            return
        }
        do {
            let c = try decoder.decode(Config.self, from: d)
            cfg = c
            cfgError = c.startUrl.contains("YOUR-PORTAL") ? "Set startUrl in config (Edit config…)" : nil
            sso.configure(startUrl: c.startUrl, region: c.ssoRegion)
        } catch {
            cfgError = "config.json invalid: \(error.localizedDescription)"
        }
    }

    func saveConfig() {
        guard let cfg, let d = try? encoder.encode(cfg) else { return }
        try? writeSecure(d, configURL)
        cfgMTime = (try? FileManager.default.attributesOfItem(atPath: configURL.path))?[.modificationDate] as? Date
    }

    // MARK: Refresh loop

    func tick(interactive: Bool = false, force: Bool = false) {
        if busy {
            again = ((again?.interactive ?? false) || interactive, (again?.force ?? false) || force)
            return
        }
        busy = true
        Task {
            await refresh(interactive: interactive, force: force)
            busy = false
            updateIcon()
            if let a = again { again = nil; tick(interactive: a.interactive, force: a.force) }
        }
    }

    func refresh(interactive: Bool, force: Bool) async {
        loadConfigIfChanged()
        guard let cfg, !cfg.startUrl.contains("YOUR-PORTAL") else { return }

        var active: [String: Session] = [:]
        for s in cfg.sessions where s.active { active[s.profile] = s }

        let margin = Double((cfg.refreshMinutesBefore ?? 10) * 60)
        let due = active.filter { p, s in
            force || written[p] != s.key || (expiry[p]?.timeIntervalSinceNow ?? -1) < margin
        }.map { ($0.key, $0.value) }

        var set: [String: CredFile.Section] = [:]
        var errs: [String] = []
        if !due.isEmpty {
            let mayPrompt = interactive || (autoPromptArmed && userPresent())
            do {
                var results: [String: Result<Creds, Error>] = [:]
                for attempt in 0..<2 {
                    let tok = try await sso.accessToken(interactive: mayPrompt)
                    results = await fetchAll(due, portal: sso.portal, token: tok)
                    let unauthorized = results.values.contains {
                        if case .failure(let e as APIError) = $0, e.status == 401 { return true }
                        return false
                    }
                    if unauthorized && attempt == 0 { sso.invalidateAccess(); continue }
                    break
                }
                for (p, s) in due {
                    switch results[p] {
                    case .success(let c)?:
                        set[p] = [("aws_access_key_id", c.akid), ("aws_secret_access_key", c.secret),
                                  ("aws_session_token", c.token), ("region", s.region ?? cfg.ssoRegion)]
                        expiry[p] = c.expiration
                        written[p] = s.key
                    case .failure(let e)?:
                        errs.append("\(s.name): \(e.localizedDescription)")
                    case nil: break
                    }
                }
            } catch is NeedsLogin {
                errs.append("Signed out — choose “Sign in…”")
            } catch {
                errs.append(error.localizedDescription)
            }
        }

        var managed = Set(sso.st.managedProfiles ?? [])
        let remove = managed.subtracting(active.keys)
        if !set.isEmpty || !remove.isEmpty {
            do {
                try CredFile.update(at: cfg.credsURL, set: set, remove: remove)
                managed.formUnion(set.keys)
                managed.subtract(remove)
                for p in remove { expiry[p] = nil; written[p] = nil }
                if managed != Set(sso.st.managedProfiles ?? []) { sso.st.managedProfiles = managed.sorted(); sso.save() }
            } catch {
                errs.append("credentials file: \(error.localizedDescription)")
            }
        }
        errors = errs
    }

    // MARK: UI

    func updateIcon() {
        let anyActive = cfg?.sessions.contains { $0.active } ?? false
        let name = status != nil ? "hourglass"
            : (cfgError != nil || !errors.isEmpty) ? "exclamationmark.triangle.fill"
            : anyActive ? "key.fill" : "key"
        let img = NSImage(systemSymbolName: name, accessibilityDescription: "SSOBar")
        img?.isTemplate = true
        item.button?.image = img
    }

    func remaining(_ d: Date) -> String {
        let s = Int(d.timeIntervalSinceNow)
        if s <= 0 { return "expired" }
        return s >= 3600 ? "\(s / 3600)h \(s % 3600 / 60)m" : "\(s / 60)m"
    }

    func note(_ s: String, _ color: NSColor = .secondaryLabelColor) {
        let i = NSMenuItem(title: s, action: nil, keyEquivalent: "")
        i.attributedTitle = NSAttributedString(string: s, attributes: [.foregroundColor: color, .font: NSFont.menuFont(ofSize: 12)])
        menu.addItem(i)
    }

    func action(_ title: String, _ sel: Selector, _ key: String = "") -> NSMenuItem {
        let i = NSMenuItem(title: title, action: sel, keyEquivalent: key)
        i.target = self
        menu.addItem(i)
        return i
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        loadConfigIfChanged()
        menu.removeAllItems()

        if let status {
            note(status, .labelColor)
            _ = action("Open sign-in page again", #selector(reopenLogin))
        } else if sso.signedIn {
            note("Signed in · \(URL(string: sso.startUrl)?.host ?? sso.startUrl)")
            _ = action("Sign out", #selector(signOut))
        } else {
            note("Not signed in")
            _ = action("Sign in…", #selector(signIn))
        }
        if let cfgError { note(cfgError, .systemRed) }
        for e in errors.prefix(6) { note(e, .systemRed) }

        if let cfg {
            var order: [String] = []
            var groups: [String: [Int]] = [:]
            for (i, s) in cfg.sessions.enumerated() {
                if groups[s.profile] == nil { order.append(s.profile) }
                groups[s.profile, default: []].append(i)
            }
            for p in order {
                menu.addItem(.separator())
                menu.addItem(.sectionHeader(title: p))
                for i in groups[p]! {
                    let s = cfg.sessions[i]
                    let it = action(s.name, #selector(toggle(_:)))
                    it.tag = i
                    it.state = s.active ? .on : .off
                    var detail = "\(s.roleName) · \(s.accountId)"
                    if s.active {
                        detail += (written[p] == s.key ? expiry[p].map { " · " + remaining($0) } : nil) ?? " · pending"
                    }
                    let t = NSMutableAttributedString(string: s.name)
                    t.append(NSAttributedString(string: "   " + detail, attributes: [
                        .foregroundColor: NSColor.secondaryLabelColor, .font: NSFont.menuFont(ofSize: 11),
                    ]))
                    it.attributedTitle = t
                }
            }
        }

        menu.addItem(.separator())
        _ = action("Refresh now", #selector(refreshNow), "r")
        _ = action("Discover roles from SSO…", #selector(discover))
        _ = action("Edit config…", #selector(editConfig), ",")
        let login = action("Launch at login", #selector(toggleLaunchAtLogin))
        login.state = SMAppService.mainApp.status == .enabled ? .on : .off
        menu.addItem(.separator())
        let v = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "dev"
        note("SSOBar \(v)")
        _ = action("Quit SSOBar", #selector(quit), "q")
    }

    func alert(_ text: String) {
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.messageText = "SSOBar"
        a.informativeText = text
        a.runModal()
    }

    // MARK: Actions

    @objc func toggle(_ sender: NSMenuItem) {
        guard var c = cfg, c.sessions.indices.contains(sender.tag) else { return }
        let i = sender.tag
        if c.sessions[i].active {
            c.sessions[i].active = false
        } else {
            for j in c.sessions.indices where c.sessions[j].profile == c.sessions[i].profile { c.sessions[j].active = false }
            c.sessions[i].active = true
        }
        cfg = c
        saveConfig()
        updateIcon()
        tick(interactive: true)
    }

    @objc func signIn() {
        Task {
            do { _ = try await sso.accessToken(interactive: true); tick(force: true) }
            catch { alert(error.localizedDescription) }
        }
    }

    @objc func signOut() {
        autoPromptArmed = false   // don't pop a browser tab right after an explicit sign-out
        sso.signOut()
        updateIcon()
    }
    @objc func reopenLogin() { if let u = sso.loginURL { NSWorkspace.shared.open(u) } }
    @objc func refreshNow() { tick(interactive: true, force: true) }

    @objc func editConfig() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        p.arguments = ["-t", configURL.path]
        try? p.run()
    }

    @objc func discover() {
        Task {
            do {
                let tok = try await sso.accessToken(interactive: true)
                let found = try await listAllRoles(portal: sso.portal, token: tok)
                guard var c = cfg else { return }
                var added = 0
                for f in found where !c.sessions.contains(where: { $0.accountId == f.account && $0.roleName == f.role }) {
                    c.sessions.append(Session(name: "\(f.accountName) · \(f.role)", accountId: f.account, roleName: f.role,
                                              region: nil, profile: "default", active: false))
                    added += 1
                }
                if added > 0 { cfg = c; saveConfig() }
                alert("Found \(found.count) roles in SSO, added \(added) new (profile “default”).\nUse Edit config… to rename them or change profiles.")
            } catch {
                alert(error.localizedDescription)
            }
        }
    }

    @objc func toggleLaunchAtLogin() {
        let s = SMAppService.mainApp
        do { if s.status == .enabled { try s.unregister() } else { try s.register() } }
        catch { alert("Launch at login: \(error.localizedDescription)") }
    }

    @objc func quit() { NSApp.terminate(nil) }
}

// MARK: - main

MainActor.assumeIsolated {
    let app = NSApplication.shared
    let delegate = App()
    app.delegate = delegate
    app.setActivationPolicy(.accessory)
    app.run()
}
