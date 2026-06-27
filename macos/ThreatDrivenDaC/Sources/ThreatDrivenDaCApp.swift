import AppKit
import SwiftUI

@main
struct ThreatDrivenDaCApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                .frame(minWidth: 1180, minHeight: 760)
        }
        .windowStyle(.titleBar)
    }
}

enum AppSection: String, CaseIterable, Identifiable {
    case detection = "Run Detection"
    case tests = "Run Tests"
    case dashboard = "View Dashboard"
    case report = "View Report"

    var id: String { rawValue }
}

enum LogSet: String, CaseIterable, Identifiable {
    case suspicious = "suspicious"
    case benign = "benign"
    case both = "both"

    var id: String { rawValue }

    var label: String {
        switch self {
        case .suspicious: return "Suspicious sample"
        case .benign: return "Benign sample"
        case .both: return "Both samples"
        }
    }
}

struct BridgeResponse: Decodable {
    let ok: Bool
    let alerts: [AlertRecord]?
    let summary: AlertSummary?
    let reportMarkdown: String?
    let exitCode: Int?
    let output: String?
    let error: String?

    enum CodingKeys: String, CodingKey {
        case ok
        case alerts
        case summary
        case reportMarkdown = "report_markdown"
        case exitCode = "exit_code"
        case output
        case error
    }
}

struct AlertSummary: Decodable {
    let totalAlerts: Int
    let severityCounts: [String: Int]
    let criticalHigh: Int
    let threatIntelMatches: Int
    let affectedUsers: [String]
    let affectedAccounts: [String]
    let mitreTactics: [String]

    enum CodingKeys: String, CodingKey {
        case totalAlerts = "total_alerts"
        case severityCounts = "severity_counts"
        case criticalHigh = "critical_high"
        case threatIntelMatches = "threat_intel_matches"
        case affectedUsers = "affected_users"
        case affectedAccounts = "affected_accounts"
        case mitreTactics = "mitre_tactics"
    }
}

struct AlertRecord: Decodable, Identifiable {
    let alertId: String
    let title: String
    let severity: String
    let riskScore: Int
    let timestamp: String?
    let affectedAccount: String?
    let affectedUser: String?
    let sourceIp: String?
    let awsRegion: String?
    let eventName: String?
    let matchedRuleId: String
    let matchedRuleTitle: String
    let threatIntelContext: [ThreatIntelContext]
    let mitreAttack: [MitreMapping]
    let recommendedAction: String
    let falsePositiveNotes: String
    let rawEvent: JSONValue?

    var id: String { alertId }

    enum CodingKeys: String, CodingKey {
        case alertId = "alert_id"
        case title
        case severity
        case riskScore = "risk_score"
        case timestamp
        case affectedAccount = "affected_account"
        case affectedUser = "affected_user"
        case sourceIp = "source_ip"
        case awsRegion = "aws_region"
        case eventName = "event_name"
        case matchedRuleId = "matched_rule_id"
        case matchedRuleTitle = "matched_rule_title"
        case threatIntelContext = "threat_intel_context"
        case mitreAttack = "mitre_attack"
        case recommendedAction = "recommended_action"
        case falsePositiveNotes = "false_positive_notes"
        case rawEvent = "raw_event"
    }
}

struct ThreatIntelContext: Decodable, Identifiable {
    let indicator: String
    let type: String
    let threatType: String
    let confidence: Int
    let severity: String
    let source: String

    var id: String { "\(type):\(indicator):\(source)" }

    enum CodingKeys: String, CodingKey {
        case indicator
        case type
        case threatType = "threat_type"
        case confidence
        case severity
        case source
    }
}

struct MitreMapping: Decodable, Identifiable {
    let tactic: String
    let techniqueId: String
    let technique: String

    var id: String { "\(tactic):\(techniqueId)" }

    enum CodingKeys: String, CodingKey {
        case tactic
        case techniqueId = "technique_id"
        case technique
    }
}

enum JSONValue: Decodable, CustomStringConvertible {
    case string(String)
    case number(Double)
    case bool(Bool)
    case object([String: JSONValue])
    case array([JSONValue])
    case null

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([String: JSONValue].self) {
            self = .object(value)
        } else {
            self = .array(try container.decode([JSONValue].self))
        }
    }

    var description: String {
        switch self {
        case .string(let value): return value
        case .number(let value): return String(value)
        case .bool(let value): return String(value)
        case .object(let value):
            let body = value.keys.sorted().map { "\"\($0)\": \(value[$0]?.description ?? "null")" }.joined(separator: ", ")
            return "{ \(body) }"
        case .array(let value): return "[\(value.map(\.description).joined(separator: ", "))]"
        case .null: return "null"
        }
    }
}

@MainActor
final class AppModel: ObservableObject {
    @Published var selectedSection: AppSection = .detection
    @Published var selectedLogSet: LogSet = .suspicious
    @Published var isRunning = false
    @Published var status = "Ready"
    @Published var lastExitCode: Int?
    @Published var alerts: [AlertRecord] = []
    @Published var summary: AlertSummary?
    @Published var reportMarkdown = ""
    @Published var testOutput = ""
    @Published var errorMessage: String?
    @Published var selectedAlert: AlertRecord?

    private let bridge = PythonBridge()

    func runDetection() {
        selectedSection = .detection
        runBridge(command: ["analyze", "--logs", selectedLogSet.rawValue]) { response in
            self.alerts = response.alerts ?? []
            self.summary = response.summary
            self.reportMarkdown = response.reportMarkdown ?? ""
            self.selectedAlert = self.alerts.first
        }
    }

    func runTests() {
        selectedSection = .tests
        runBridge(command: ["test"]) { response in
            self.testOutput = response.output ?? ""
            self.lastExitCode = response.exitCode
        }
    }

    func loadReport() {
        selectedSection = .report
        runBridge(command: ["report", "--logs", selectedLogSet.rawValue]) { response in
            self.summary = response.summary
            self.reportMarkdown = response.reportMarkdown ?? ""
        }
    }

    private func runBridge(command: [String], onSuccess: @escaping (BridgeResponse) -> Void) {
        isRunning = true
        errorMessage = nil
        lastExitCode = nil
        status = "Running \(command.first ?? "command")..."

        Task.detached {
            let result = self.bridge.run(arguments: command)
            await MainActor.run {
                self.isRunning = false
                self.lastExitCode = result.exitCode

                switch result.payload {
                case .success(let response):
                    self.status = response.ok ? "Completed" : "Failed"
                    self.errorMessage = response.error
                    if response.ok {
                        onSuccess(response)
                    }
                case .failure(let error):
                    self.status = "Failed"
                    self.errorMessage = error
                }
            }
        }
    }
}

struct BridgeRunResult {
    let exitCode: Int
    let payload: BridgePayload
}

enum BridgePayload {
    case success(BridgeResponse)
    case failure(String)
}

struct PythonBridge {
    func run(arguments: [String]) -> BridgeRunResult {
        guard let repoRoot = findRepositoryRoot() else {
            return BridgeRunResult(exitCode: 1, payload: .failure("Could not locate the repository root from the app bundle. Build and run the app from this project."))
        }

        let pythonPath = repoRoot.appendingPathComponent(".venv/bin/python3")
        guard FileManager.default.isExecutableFile(atPath: pythonPath.path) else {
            return BridgeRunResult(exitCode: 1, payload: .failure("Missing .venv/bin/python3. Run: python3 -m venv .venv && source .venv/bin/activate && python3 -m pip install -r requirements.txt"))
        }

        let process = Process()
        process.executableURL = pythonPath
        process.currentDirectoryURL = repoRoot
        process.environment = [
            "PYTHONPATH": repoRoot.path,
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin"
        ]
        process.arguments = ["-m", "src.macos_bridge"] + arguments

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = errorPipe

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return BridgeRunResult(exitCode: 1, payload: .failure(error.localizedDescription))
        }

        let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let stderr = String(data: errorPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let exitCode = Int(process.terminationStatus)
        let jsonText = output.trimmingCharacters(in: .whitespacesAndNewlines)

        guard let data = jsonText.data(using: .utf8), !jsonText.isEmpty else {
            return BridgeRunResult(exitCode: exitCode, payload: .failure(stderr.isEmpty ? "Python bridge returned no JSON output." : stderr))
        }

        do {
            let response = try JSONDecoder().decode(BridgeResponse.self, from: data)
            return BridgeRunResult(exitCode: exitCode, payload: .success(response))
        } catch {
            return BridgeRunResult(exitCode: exitCode, payload: .failure("Could not decode bridge JSON: \(error.localizedDescription)\n\(stderr)"))
        }
    }

    private func findRepositoryRoot() -> URL? {
        var candidates: [URL] = []
        candidates.append(Bundle.main.bundleURL)
        candidates.append(URL(fileURLWithPath: FileManager.default.currentDirectoryPath))

        for candidate in candidates {
            var current = candidate
            for _ in 0..<10 {
                if FileManager.default.fileExists(atPath: current.appendingPathComponent("src/macos_bridge.py").path),
                   FileManager.default.fileExists(atPath: current.appendingPathComponent("rules").path) {
                    return current
                }
                let parent = current.deletingLastPathComponent()
                if parent.path == current.path { break }
                current = parent
            }
        }
        return nil
    }
}

struct ContentView: View {
    @StateObject private var model = AppModel()

    var body: some View {
        NavigationSplitView {
            SidebarView()
                .environmentObject(model)
        } detail: {
            DetailView()
                .environmentObject(model)
        }
    }
}

struct SidebarView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("ThreatDriven-DaC")
                .font(.title2)
                .fontWeight(.semibold)

            Picker("Log sample", selection: $model.selectedLogSet) {
                ForEach(LogSet.allCases) { logSet in
                    Text(logSet.label).tag(logSet)
                }
            }

            Divider()

            ForEach(AppSection.allCases) { section in
                Button(section.rawValue) {
                    handle(section)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            Spacer()

            StatusPanel()
        }
        .padding()
        .frame(minWidth: 240)
    }

    private func handle(_ section: AppSection) {
        switch section {
        case .detection:
            model.runDetection()
        case .tests:
            model.runTests()
        case .dashboard:
            model.selectedSection = .dashboard
            if model.summary == nil {
                model.runDetection()
            }
        case .report:
            model.loadReport()
        }
    }
}

struct StatusPanel: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Status")
                .font(.headline)
            if model.isRunning {
                ProgressView()
            }
            Text(model.status)
                .font(.callout)
            if let exitCode = model.lastExitCode {
                Text("Exit code: \(exitCode)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if let error = model.errorMessage, !error.isEmpty {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
            }
        }
    }
}

struct DetailView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Group {
            switch model.selectedSection {
            case .detection:
                DetectionView()
            case .tests:
                TestsView()
            case .dashboard:
                DashboardView()
            case .report:
                ReportView()
            }
        }
        .padding()
    }
}

struct DetectionView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Header(title: "Detection Run", subtitle: "Run the Python detection pipeline against bundled CloudTrail-style samples.")
            SummaryCards(summary: model.summary)
            AlertTable()
            AlertDetail(alert: model.selectedAlert)
            Spacer()
        }
    }
}

struct DashboardView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Header(title: "SOC Dashboard", subtitle: "Native overview of alert severity, threat intelligence, MITRE coverage, and analyst context.")
                SummaryCards(summary: model.summary)
                SeverityBars(summary: model.summary)
                AlertTable()
                ThreatIntelPanel(alerts: model.alerts)
                MitrePanel(alerts: model.alerts)
                AlertDetail(alert: model.selectedAlert)
            }
        }
    }
}

struct TestsView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Header(title: "Automated Tests", subtitle: "Runs pytest through the repository .venv and shows captured output.")
            TextEditor(text: .constant(model.testOutput.isEmpty ? "Click Run Tests in the sidebar." : model.testOutput))
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
        }
    }
}

struct ReportView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Header(title: "Analyst Report", subtitle: "Markdown report generated by the Python reporting module.")
            TextEditor(text: .constant(model.reportMarkdown.isEmpty ? "Click View Report in the sidebar." : model.reportMarkdown))
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
        }
    }
}

struct Header: View {
    let title: String
    let subtitle: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.largeTitle)
                .fontWeight(.semibold)
            Text(subtitle)
                .foregroundStyle(.secondary)
        }
    }
}

struct SummaryCards: View {
    let summary: AlertSummary?

    var body: some View {
        let values = [
            ("Total alerts", summary?.totalAlerts ?? 0),
            ("Critical / High", summary?.criticalHigh ?? 0),
            ("Threat intel", summary?.threatIntelMatches ?? 0),
            ("Affected users", summary?.affectedUsers.count ?? 0),
            ("MITRE tactics", summary?.mitreTactics.count ?? 0)
        ]

        HStack(spacing: 12) {
            ForEach(values, id: \.0) { label, value in
                VStack(alignment: .leading, spacing: 8) {
                    Text(label)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text("\(value)")
                        .font(.title)
                        .fontWeight(.bold)
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(nsColor: .controlBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }
        }
    }
}

struct SeverityBars: View {
    let summary: AlertSummary?
    private let order = ["critical", "high", "medium", "low"]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Severity Distribution")
                .font(.headline)
            ForEach(order, id: \.self) { severity in
                let value = summary?.severityCounts[severity] ?? 0
                HStack {
                    Text(severity.capitalized)
                        .frame(width: 80, alignment: .leading)
                    ProgressView(value: Double(value), total: Double(max(summary?.totalAlerts ?? 1, 1)))
                    Text("\(value)")
                        .frame(width: 28, alignment: .trailing)
                }
            }
        }
        .padding()
        .background(Color(nsColor: .controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

struct AlertTable: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Alerts")
                .font(.headline)
            if model.alerts.isEmpty {
                Text(model.summary?.totalAlerts == 0 ? "No alerts for the selected sample." : "Click Run Detection in the sidebar.")
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 16)
            } else {
                Table(model.alerts, selection: Binding(
                    get: { model.selectedAlert?.id },
                    set: { id in model.selectedAlert = model.alerts.first { $0.id == id } }
                )) {
                    TableColumn("Severity") { alert in Text(alert.severity.uppercased()) }
                    TableColumn("Risk") { alert in Text("\(alert.riskScore)") }
                    TableColumn("Rule") { alert in Text(alert.matchedRuleTitle) }
                    TableColumn("User") { alert in Text(alert.affectedUser ?? "unknown") }
                    TableColumn("Source IP") { alert in Text(alert.sourceIp ?? "unknown") }
                    TableColumn("Region") { alert in Text(alert.awsRegion ?? "unknown") }
                    TableColumn("Event") { alert in Text(alert.eventName ?? "unknown") }
                }
                .frame(minHeight: 220)
            }
        }
    }
}

struct ThreatIntelPanel: View {
    let alerts: [AlertRecord]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Threat Intelligence Matches")
                .font(.headline)
            let matches = alerts.flatMap { alert in
                alert.threatIntelContext.map { (alert.alertId, $0) }
            }
            if matches.isEmpty {
                Text("No threat-intelligence matches.")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(matches, id: \.1.id) { alertId, match in
                    Text("\(match.indicator) | \(match.threatType) | confidence \(match.confidence) | \(alertId)")
                        .font(.callout)
                }
            }
        }
        .padding()
        .background(Color(nsColor: .controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

struct MitrePanel: View {
    let alerts: [AlertRecord]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("MITRE ATT&CK Coverage")
                .font(.headline)
            let tactics = Dictionary(grouping: alerts.flatMap(\.mitreAttack), by: \.tactic)
            if tactics.isEmpty {
                Text("No MITRE mappings.")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(tactics.keys.sorted(), id: \.self) { tactic in
                    let techniques = Set((tactics[tactic] ?? []).map { "\($0.techniqueId) \($0.technique)" }).sorted().joined(separator: ", ")
                    Text("\(tactic): \(techniques)")
                        .font(.callout)
                }
            }
        }
        .padding()
        .background(Color(nsColor: .controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

struct AlertDetail: View {
    let alert: AlertRecord?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Alert Detail")
                .font(.headline)

            if let alert {
                VStack(alignment: .leading, spacing: 10) {
                    Text(alert.title)
                        .font(.title3)
                        .fontWeight(.semibold)
                    Text("Rule \(alert.matchedRuleId) | \(alert.severity.uppercased()) | Risk \(alert.riskScore)")
                        .foregroundStyle(.secondary)
                    Text("Recommended action: \(alert.recommendedAction)")
                    Text("False positive notes: \(alert.falsePositiveNotes)")
                    Text("MITRE: \(alert.mitreAttack.map { "\($0.tactic) / \($0.techniqueId) \($0.technique)" }.joined(separator: "; "))")
                    if !alert.threatIntelContext.isEmpty {
                        Text("Threat intel: \(alert.threatIntelContext.map { "\($0.indicator) \($0.threatType) confidence \($0.confidence)" }.joined(separator: "; "))")
                    }
                    Text("Raw event: \(alert.rawEvent?.description ?? "none")")
                        .font(.system(.callout, design: .monospaced))
                        .textSelection(.enabled)
                }
            } else {
                Text("Select an alert to inspect MITRE mappings, IOC context, recommendations, and raw event data.")
                    .foregroundStyle(.secondary)
            }
        }
        .padding()
        .background(Color(nsColor: .controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}
