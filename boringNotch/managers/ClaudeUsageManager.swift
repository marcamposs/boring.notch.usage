//
//  ClaudeUsageManager.swift
//  boringNotch
//

import AppKit
import Combine
import CryptoKit
import Defaults
import Foundation
import Network
import Security

struct ClaudeUsageData {
    var h5Utilization: Double = 0   // 0.0–1.0
    var d7Utilization: Double = 0   // 0.0–1.0
    var h5ResetDate: Date?
    var d7ResetDate: Date?
}

@MainActor
class ClaudeUsageManager: ObservableObject {
    static let shared = ClaudeUsageManager()

    @Published var usageData: ClaudeUsageData = .init()
    @Published var isLoading: Bool = false
    @Published var errorMessage: String?
    @Published var lastUpdated: Date?

    @Published var isLoggingIn: Bool = false
    @Published var loginError: String?
    @Published private(set) var isConnected: Bool = false

    private var pollingTimer: Timer?
    private let oauthService = "com.boringnotch.claude-oauth"

    // Public OAuth client id used by Claude Code.
    private let oauthClientID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
    private let oauthScopes = "org:create_api_key user:profile user:inference"
    private let callbackPort: UInt16 = 54545
    private var redirectURI: String { "http://localhost:\(callbackPort)/callback" }

    // Decoded credentials are cached in memory so the Keychain is read once at
    // launch instead of on every SwiftUI render and every poll.
    private var cachedCredentials: OAuthCredentials?

    // Transient login-flow state.
    private var listener: NWListener?
    private var pendingVerifier: String?
    private var pendingState: String?
    private var pendingAuthURL: URL?

    private init() {
        cachedCredentials = loadOAuthCredentialsFromKeychain()
        isConnected = cachedCredentials != nil
    }

    // MARK: - Keychain

    // All queries opt into the data-protection keychain: access is gated by the
    // app's entitlements/access-group rather than an interactive ACL, so a
    // sandboxed app reads its own items without any permission prompts.

    private func saveToKeychain(service: String, value: String) {
        let base: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecUseDataProtectionKeychain: true
        ]
        SecItemDelete(base as CFDictionary)

        var add = base
        add[kSecValueData] = Data(value.utf8)
        add[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlock

        let status = SecItemAdd(add as CFDictionary, nil)
        if status != errSecSuccess {
            NSLog("ClaudeUsage: keychain save failed (OSStatus \(status))")
        }
    }

    private func loadFromKeychain(service: String) -> String? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecUseDataProtectionKeychain: true,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func deleteFromKeychain(service: String) {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecUseDataProtectionKeychain: true
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - OAuth credentials

    private struct OAuthCredentials: Codable {
        var accessToken: String
        var refreshToken: String?
        var expiresAt: Date?
    }

    private func loadOAuthCredentialsFromKeychain() -> OAuthCredentials? {
        guard let json = loadFromKeychain(service: oauthService),
              let data = json.data(using: .utf8)
        else { return nil }
        return try? JSONDecoder().decode(OAuthCredentials.self, from: data)
    }

    private func storeOAuthCredentials(_ creds: OAuthCredentials) {
        cachedCredentials = creds
        isConnected = true
        guard let data = try? JSONEncoder().encode(creds),
              let json = String(data: data, encoding: .utf8)
        else { return }
        saveToKeychain(service: oauthService, value: json)
    }

    func clearOAuthCredentials() {
        cachedCredentials = nil
        isConnected = false
        deleteFromKeychain(service: oauthService)
        usageData = .init()
        lastUpdated = nil
        errorMessage = nil
    }

    // MARK: - Polling

    func startPolling(interval: TimeInterval = 120) {
        stopPolling()
        Task { await fetchUsage() }
        pollingTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                await self?.fetchUsage()
            }
        }
    }

    func stopPolling() {
        pollingTimer?.invalidate()
        pollingTimer = nil
    }

    // MARK: - Fetch

    func fetchUsage() async {
        guard !isLoading else { return }
        isLoading = true
        errorMessage = nil

        do {
            usageData = try await performOAuthUsageRequest()
            lastUpdated = Date()
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }

        isLoading = false
    }

    private func usageError(_ message: String, code: Int = 0) -> NSError {
        NSError(domain: "ClaudeUsage", code: code, userInfo: [NSLocalizedDescriptionKey: message])
    }

    // MARK: - OAuth usage

    private func performOAuthUsageRequest() async throws -> ClaudeUsageData {
        guard var creds = cachedCredentials else {
            throw usageError("Not signed in — open Settings to connect your Claude plan")
        }

        // Refresh proactively when the token is expired or about to expire.
        if let expiry = creds.expiresAt, expiry.timeIntervalSinceNow < 60 {
            creds = try await refreshOAuthToken(creds)
        }

        do {
            return try await oauthUsage(token: creds.accessToken)
        } catch let error as NSError where error.code == 401 {
            // Token rejected mid-flight — refresh once and retry.
            creds = try await refreshOAuthToken(creds)
            return try await oauthUsage(token: creds.accessToken)
        }
    }

    private func oauthUsage(token: String) async throws -> ClaudeUsageData {
        var request = URLRequest(url: URL(string: "https://api.anthropic.com/api/oauth/usage")!)
        request.httpMethod = "GET"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("oauth-2025-04-20", forHTTPHeaderField: "anthropic-beta")
        request.timeoutInterval = 15

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw URLError(.badServerResponse)
        }

        switch http.statusCode {
        case 200:
            return try parseOAuthUsage(data)
        case 401:
            throw usageError("OAuth token expired", code: 401)
        case 429:
            throw usageError("Rate limited by Anthropic — try again later", code: 429)
        default:
            throw usageError("Usage request failed (HTTP \(http.statusCode))", code: http.statusCode)
        }
    }

    private struct OAuthUsageResponse: Decodable {
        struct Window: Decodable {
            let utilization: Double
            let resets_at: String?
        }
        let five_hour: Window?
        let seven_day: Window?
    }

    private func parseOAuthUsage(_ data: Data) throws -> ClaudeUsageData {
        let decoded = try JSONDecoder().decode(OAuthUsageResponse.self, from: data)
        var result = ClaudeUsageData()

        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let plain = ISO8601DateFormatter()
        func parseDate(_ string: String?) -> Date? {
            guard let string else { return nil }
            return fractional.date(from: string) ?? plain.date(from: string)
        }

        if let five = decoded.five_hour {
            result.h5Utilization = min(max(five.utilization / 100, 0), 1)
            result.h5ResetDate = parseDate(five.resets_at)
        }
        if let seven = decoded.seven_day {
            result.d7Utilization = min(max(seven.utilization / 100, 0), 1)
            result.d7ResetDate = parseDate(seven.resets_at)
        }
        return result
    }

    // MARK: - OAuth token refresh

    private struct TokenResponse: Decodable {
        let access_token: String
        let refresh_token: String?
        let expires_in: Double?
    }

    private func refreshOAuthToken(_ creds: OAuthCredentials) async throws -> OAuthCredentials {
        guard let refreshToken = creds.refreshToken else {
            throw usageError("Session expired — sign in again in Settings", code: 401)
        }

        var request = URLRequest(url: URL(string: "https://console.anthropic.com/v1/oauth/token")!)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 15
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "grant_type": "refresh_token",
            "refresh_token": refreshToken,
            "client_id": oauthClientID
        ])

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw usageError("Couldn't refresh your session — sign in again in Settings", code: 401)
        }

        let decoded = try JSONDecoder().decode(TokenResponse.self, from: data)
        var updated = creds
        updated.accessToken = decoded.access_token
        if let newRefresh = decoded.refresh_token {
            updated.refreshToken = newRefresh
        }
        if let expiresIn = decoded.expires_in {
            updated.expiresAt = Date().addingTimeInterval(expiresIn)
        }
        storeOAuthCredentials(updated)
        return updated
    }

    // MARK: - OAuth login (PKCE + loopback redirect)

    func startLogin() {
        guard !isLoggingIn else { return }
        loginError = nil

        let verifier = Self.randomURLSafeString(byteCount: 32)
        let state = Self.randomURLSafeString(byteCount: 32)
        pendingVerifier = verifier
        pendingState = state

        var components = URLComponents(string: "https://claude.ai/oauth/authorize")!
        components.queryItems = [
            URLQueryItem(name: "client_id", value: oauthClientID),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "redirect_uri", value: redirectURI),
            URLQueryItem(name: "scope", value: oauthScopes),
            URLQueryItem(name: "code_challenge", value: Self.codeChallenge(for: verifier)),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
            URLQueryItem(name: "state", value: state)
        ]
        guard let url = components.url else {
            loginError = "Couldn't build the sign-in URL."
            return
        }
        pendingAuthURL = url

        isLoggingIn = true
        do {
            try startCallbackServer()
        } catch {
            finishLogin(.failure(usageError("Couldn't start the sign-in listener on port \(callbackPort).")))
        }
    }

    func cancelLogin() {
        guard isLoggingIn else { return }
        cleanupLogin()
        isLoggingIn = false
        loginError = nil
    }

    private func cleanupLogin() {
        listener?.cancel()
        listener = nil
        pendingVerifier = nil
        pendingState = nil
        pendingAuthURL = nil
    }

    private func finishLogin(_ result: Result<Void, Error>) {
        cleanupLogin()
        isLoggingIn = false
        switch result {
        case .success:
            loginError = nil
            if Defaults[.showClaudeUsage] {
                startPolling(interval: Defaults[.claudeUsageRefreshInterval])
            } else {
                Task { await fetchUsage() }
            }
        case .failure(let error):
            loginError = error.localizedDescription
        }
    }

    // MARK: - Loopback callback server

    private func startCallbackServer() throws {
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        params.requiredLocalEndpoint = .hostPort(
            host: .ipv4(.loopback),
            port: NWEndpoint.Port(rawValue: callbackPort)!
        )

        let listener = try NWListener(using: params)
        self.listener = listener

        listener.stateUpdateHandler = { [weak self] state in
            Task { @MainActor in
                guard let self else { return }
                switch state {
                case .ready:
                    if let url = self.pendingAuthURL {
                        NSWorkspace.shared.open(url)
                    }
                case .failed(let error):
                    self.finishLogin(.failure(self.usageError(
                        "Couldn't start the sign-in listener (\(error.localizedDescription)).")))
                default:
                    break
                }
            }
        }

        listener.newConnectionHandler = { [weak self] connection in
            connection.start(queue: .main)
            Task { @MainActor in
                self?.receiveRequest(on: connection)
            }
        }

        listener.start(queue: .main)
    }

    private func receiveRequest(on connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] data, _, _, _ in
            let request = data.flatMap { String(data: $0, encoding: .utf8) }
            Task { @MainActor in
                guard let self else { return }
                guard let request,
                      let requestLine = request.split(separator: "\r\n").first,
                      let path = requestLine.split(separator: " ").dropFirst().first
                else {
                    connection.cancel()
                    return
                }
                self.handleCallback(path: String(path), connection: connection)
            }
        }
    }

    private func handleCallback(path: String, connection: NWConnection) {
        guard path.hasPrefix("/callback") else {
            respond(on: connection, success: false)
            return
        }

        let items = URLComponents(string: "http://localhost\(path)")?.queryItems ?? []
        let code = items.first { $0.name == "code" }?.value
        let returnedState = items.first { $0.name == "state" }?.value
        let oauthError = items.first { $0.name == "error" }?.value

        respond(on: connection, success: oauthError == nil && code != nil && returnedState != nil)

        if let oauthError {
            finishLogin(.failure(usageError("Sign-in was denied (\(oauthError)).")))
            return
        }
        guard let code, let returnedState else {
            finishLogin(.failure(usageError("The sign-in response was incomplete — please try again.")))
            return
        }
        guard returnedState == pendingState else {
            finishLogin(.failure(usageError("Sign-in could not be verified — please try again.")))
            return
        }
        guard let verifier = pendingVerifier else {
            finishLogin(.failure(usageError("The sign-in session expired — please try again.")))
            return
        }
        Task { await exchangeCode(code, state: returnedState, verifier: verifier) }
    }

    private func respond(on connection: NWConnection, success: Bool) {
        let title = success ? "Signed in" : "Sign-in failed"
        let message = success
            ? "You're connected. You can close this tab and return to boring.notch."
            : "Something went wrong. Return to boring.notch and try again."
        let html = """
        <!doctype html><html><head><meta charset="utf-8"><title>\(title)</title>
        <style>html,body{height:100%;margin:0}body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;\
        background:#1c1c1e;color:#fff;display:flex;align-items:center;justify-content:center}\
        .card{text-align:center;padding:32px}h1{font-size:20px;margin:0 0 8px}\
        p{color:#9b9b9f;margin:0;font-size:14px}</style></head>
        <body><div class="card"><h1>\(title)</h1><p>\(message)</p></div></body></html>
        """
        let body = Data(html.utf8)
        let header = "HTTP/1.1 200 OK\r\n" +
            "Content-Type: text/html; charset=utf-8\r\n" +
            "Content-Length: \(body.count)\r\n" +
            "Connection: close\r\n\r\n"
        var payload = Data(header.utf8)
        payload.append(body)
        connection.send(content: payload, completion: .contentProcessed { _ in
            connection.cancel()
        })
    }

    private func exchangeCode(_ code: String, state: String, verifier: String) async {
        do {
            var request = URLRequest(url: URL(string: "https://console.anthropic.com/v1/oauth/token")!)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.timeoutInterval = 20
            request.httpBody = try JSONSerialization.data(withJSONObject: [
                "grant_type": "authorization_code",
                "code": code,
                "state": state,
                "client_id": oauthClientID,
                "redirect_uri": redirectURI,
                "code_verifier": verifier
            ])

            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                let status = (response as? HTTPURLResponse)?.statusCode ?? -1
                throw usageError("Sign-in couldn't be completed (HTTP \(status)).")
            }

            let decoded = try JSONDecoder().decode(TokenResponse.self, from: data)
            var creds = OAuthCredentials(accessToken: decoded.access_token)
            creds.refreshToken = decoded.refresh_token
            if let expiresIn = decoded.expires_in {
                creds.expiresAt = Date().addingTimeInterval(expiresIn)
            }
            storeOAuthCredentials(creds)
            finishLogin(.success(()))
        } catch {
            finishLogin(.failure(error))
        }
    }

    // MARK: - PKCE helpers

    private static func randomURLSafeString(byteCount: Int) -> String {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        _ = SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes)
        return Data(bytes).base64URLEncodedString()
    }

    private static func codeChallenge(for verifier: String) -> String {
        let hash = SHA256.hash(data: Data(verifier.utf8))
        return Data(hash).base64URLEncodedString()
    }
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
