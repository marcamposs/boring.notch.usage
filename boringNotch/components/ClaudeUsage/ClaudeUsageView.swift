//
//  ClaudeUsageView.swift
//  boringNotch
//

import Defaults
import SwiftUI

struct ClaudeUsageView: View {
    @ObservedObject private var manager = ClaudeUsageManager.shared
    @State private var now = Date()
    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            header
            gaugesRow
            Spacer(minLength: 0)
        }
        .frame(height: 120)
        .onReceive(timer) { _ in now = Date() }
    }

    private var header: some View {
        HStack(spacing: 4) {
            Image("ClaudeLogo")
                .renderingMode(.template)
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(width: 14, height: 14)
                .foregroundColor(.claudeAccent)
            Text("Claude")
                .font(.title3)
                .fontWeight(.semibold)
                .foregroundColor(.white)
            Spacer()
            if manager.isLoading {
                ProgressView()
                    .scaleEffect(0.5)
                    .frame(width: 12, height: 12)
            } else {
                Button {
                    Task { await manager.fetchUsage() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                        .font(.caption2)
                        .foregroundColor(Color(white: 0.5))
                }
                .buttonStyle(PlainButtonStyle())
            }
        }
    }

    private var gaugesRow: some View {
        VStack(spacing: 8) {
            if let error = manager.errorMessage {
                errorView(error)
            } else {
                usageRow(
                    label: "5h",
                    utilization: manager.usageData.h5Utilization,
                    resetDate: manager.usageData.h5ResetDate
                )
                usageRow(
                    label: "7d",
                    utilization: manager.usageData.d7Utilization,
                    resetDate: manager.usageData.d7ResetDate
                )
            }
        }
    }

    private func usageRow(label: String, utilization: Double, resetDate: Date?) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 0) {
                Text(label)
                    .font(.caption2)
                    .fontWeight(.medium)
                    .foregroundColor(Color(white: 0.55))
                    .frame(width: 18, alignment: .leading)
                UsageBar(value: utilization, color: barColor(for: utilization))
                Text("\(Int(utilization * 100))%")
                    .font(.caption2)
                    .fontWeight(.medium)
                    .foregroundColor(barColor(for: utilization))
                    .frame(width: 28, alignment: .trailing)
            }
            if let reset = resetDate, reset > now {
                HStack(spacing: 0) {
                    Spacer().frame(width: 18)
                    Text("resets \(countdownString(to: reset))")
                        .font(.system(size: 9))
                        .foregroundColor(Color(white: 0.4))
                }
            }
        }
    }

    private func errorView(_ message: String) -> some View {
        VStack(spacing: 4) {
            Image(systemName: "exclamationmark.triangle")
                .font(.caption)
                .foregroundColor(.yellow)
            Text(message)
                .font(.system(size: 9))
                .foregroundColor(Color(white: 0.55))
                .multilineTextAlignment(.center)
                .lineLimit(3)
        }
        .frame(maxWidth: .infinity)
    }

    private func barColor(for value: Double) -> Color {
        if value >= 0.9 { return .red }
        if value >= 0.7 { return .orange }
        return .claudeAccent
    }

    private func countdownString(to date: Date) -> String {
        let secs = Int(date.timeIntervalSince(now))
        guard secs > 0 else { return "soon" }
        let h = secs / 3600
        let m = (secs % 3600) / 60
        let s = secs % 60
        if h > 0 { return String(format: "%dh %02dm", h, m) }
        if m > 0 { return String(format: "%dm %02ds", m, s) }
        return String(format: "%ds", s)
    }
}

struct UsageBar: View {
    let value: Double   // 0.0–1.0
    let color: Color

    var body: some View {
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                RoundedRectangle(cornerRadius: 2)
                    .fill(Color(white: 0.18))
                    .frame(height: 6)
                RoundedRectangle(cornerRadius: 2)
                    .fill(color)
                    .frame(width: max(CGFloat(value) * geo.size.width, value > 0 ? 4 : 0), height: 6)
            }
            .frame(height: geo.size.height, alignment: .center)
        }
        .frame(height: 6)
    }
}

#Preview {
    ClaudeUsageView()
        .frame(width: 120)
        .padding()
        .background(.black)
}
