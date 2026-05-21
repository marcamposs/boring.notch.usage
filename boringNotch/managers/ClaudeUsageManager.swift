//
//  ClaudeUsageManager.swift
//  boringNotch
//

import Combine
import Defaults
import Foundation
import Security

struct ClaudeUsageData {
    var h5Utilization: Double = 0   // 0.0–1.0
    var d7Utilization: Double = 0   // 0.0–1.0
    var h5ResetDate: Date?
    var d7ResetDate: Date?
}

enum ClaudeAuthMode: String, CaseIterable, Identifiable, Defaults.Serializable {
    case oauth = "Claude Pro/Max"
    case apiKey = "API Key"

    var id: String { rawValue }
}

@MainActor
class ClaudeUsageManager: ObservableObject {
    static let shared = ClaudeUsageManager()

    @Published var usageData: ClaudeUsageData = .init()
    @Published var isLoading: Bool = false
    @Published var errorMessage: String?
    @Published var lastUpdated: Date?

    private var pollingTimer: Timer?
    private let apiKeyService = "com.boringnotch.claude-api-key"
    private let oauthService = "com.boringnotch.claude-oauth"

    // Public OAuth client id used by Claude Code for token refresh.
    private let oauthClientID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"

    private init() {}

    // MARK: - Keychain

    private func saveToKeychain(service: String, value: String) {
        let data = Data(value.utf8)
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecValueData: data
        ]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }

    private func loadFromKeychain(service: String) -> String? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data
        else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func deleteFromKeychain(service: String) {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - API key

    var apiKey: String {
        get { loadFromKeychain(service: apiKeyService) ?? "" }
        set {
            if newValue.isEmpty {
                deleteFromKeychain(service: apiKeyService)
            } else {
                saveToKeychain(service: apiKeyService, value: newValue)
            }
        }
    }

    // MARK: - OAuth credentials

    private struct OAuthCredentials: Codable {
        var accessToken: String
        var refreshToken: String?
        var expiresAt: Date?
    }

    var hasOAuthCredentials: Bool {
        loadOAuthCredentials() != nil
    }

    private func loadOAuthCredentials() -> OAuthCredentials? {
        guard let json = loadFromKeychain(service: oauthService),
              let data = json.data(using: .utf8)
        else { return nil }
        return try? JSONDecoder().decode(OAuthCredentials.self, from: data)
    }

    private func storeOAuthCredentials(_ creds: OAuthCredentials) {
        guard let data = try? JSONEncoder().encode(creds),
              let json = String(data: data, encoding: .utf8)
        else { return }
        saveToKeychain(service: oauthService, value: json)
    }

    func clearOAuthCredentials() {
        deleteFromKeychain(service: oauthService)
    }

    /// Accepts either the full Claude Code credentials JSON
    /// (`{"claudeAiOauth":{...}}`) or a bare `sk-ant-oat…` access token.
    /// Returns true when valid credentials were stored.
    @discardableResult
    func saveOAuthInput(_ raw: String) -> Bool {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            clearOAuthCredentials()
            return false
        }

        if let data = trimmed.data(using: .utf8),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            let oauth = (obj["claudeAiOauth"] as? [String: Any]) ?? obj
            if let token = oauth["accessToken"] as? String, !token.isEmpty {
                var creds = OAuthCredentials(accessToken: token)
                creds.refreshToken = oauth["refreshToken"] as? String
                if let ms = oauth["expiresAt"] as? Double {
                    creds.expiresAt = Date(timeIntervalSince1970: ms / 1000)
                }
                storeOAuthCredentials(creds)
                return true
            }
        }

        if trimmed.hasPrefix("sk-ant-oat") {
            storeOAuthCredentials(OAuthCredentials(accessToken: trimmed))
            return true
        }

        return false
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
        isLoading = true
        errorMessage = nil

        do {
            let data: ClaudeUsageData
            switch Defaults[.claudeAuthMode] {
            case .apiKey:
                let key = apiKey
                guard !key.isEmpty else { throw usageError("No API key set") }
                data = try await performProbeRequest(apiKey: key)
            case .oauth:
                data = try await performOAuthUsageRequest()
            }
            usageData = data
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

    // MARK: - API key probe

    private func performProbeRequest(apiKey: String) async throws -> ClaudeUsageData {
        var request = URLRequest(url: URL(string: "https://api.anthropic.com/v1/messages")!)
        request.httpMethod = "POST"
        request.setValue(apiKey, forHTTPHeaderField: "x-api-key")
        request.setValue("2023-06-01", forHTTPHeaderField: "anthropic-version")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 15

        let body: [String: Any] = [
            "model": "claude-haiku-4-5-20251001",
            "max_tokens": 1,
            "messages": [["role": "user", "content": "."]]
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (_, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw URLError(.badServerResponse)
        }

        if http.statusCode == 401 {
            throw usageError("Invalid API key", code: 401)
        }

        var result = ClaudeUsageData()
        let headers = http.allHeaderFields
        if let raw = headers["anthropic-ratelimit-unified-5h-utilization"] as? String,
           let val = Double(raw) {
            result.h5Utilization = val
        }
        if let raw = headers["anthropic-ratelimit-unified-7d-utilization"] as? String,
           let val = Double(raw) {
            result.d7Utilization = val
        }
        if let raw = headers["anthropic-ratelimit-unified-5h-reset"] as? String,
           let epoch = Double(raw) {
            result.h5ResetDate = Date(timeIntervalSince1970: epoch)
        }
        if let raw = headers["anthropic-ratelimit-unified-7d-reset"] as? String,
           let epoch = Double(raw) {
            result.d7ResetDate = Date(timeIntervalSince1970: epoch)
        }

        return result
    }

    // MARK: - OAuth usage

    private func performOAuthUsageRequest() async throws -> ClaudeUsageData {
        guard var creds = loadOAuthCredentials() else {
            throw usageError("Not connected — paste your Claude Code credentials in Settings")
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
            throw usageError("OAuth token expired — paste fresh Claude Code credentials in Settings", code: 401)
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
            throw usageError("Could not refresh OAuth token — paste fresh Claude Code credentials in Settings", code: 401)
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
}
