//
//  ClaudeUsageManager.swift
//  boringNotch
//

import Combine
import Foundation
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

    private var pollingTimer: Timer?
    private let keychainService = "com.boringnotch.claude-api-key"

    private init() {}

    // MARK: - Keychain

    var apiKey: String {
        get { loadKeyFromKeychain() ?? "" }
        set {
            if newValue.isEmpty {
                deleteKeyFromKeychain()
            } else {
                saveKeyToKeychain(newValue)
            }
        }
    }

    private func saveKeyToKeychain(_ key: String) {
        let data = Data(key.utf8)
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecValueData: data
        ]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }

    private func loadKeyFromKeychain() -> String? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data
        else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func deleteKeyFromKeychain() {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychainService
        ]
        SecItemDelete(query as CFDictionary)
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

    // MARK: - API fetch

    func fetchUsage() async {
        let key = apiKey
        guard !key.isEmpty else {
            errorMessage = "No API key set"
            return
        }

        isLoading = true
        errorMessage = nil

        do {
            let data = try await performProbeRequest(apiKey: key)
            usageData = data
            lastUpdated = Date()
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }

        isLoading = false
    }

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

        // API key errors
        if http.statusCode == 401 {
            throw NSError(domain: "ClaudeUsage", code: 401, userInfo: [NSLocalizedDescriptionKey: "Invalid API key"])
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
}
