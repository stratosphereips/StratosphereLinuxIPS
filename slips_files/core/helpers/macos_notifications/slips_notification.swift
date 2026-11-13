import AppKit
import Foundation
import UserNotifications

final class NotificationDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    /// Start notification work after macOS has registered the application.
    func applicationDidFinishLaunching(_ notification: Notification) -> Void {
        beginNotification()
    }

    /// Present a notification while this small helper is running.
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        if #available(macOS 11.0, *) {
            completionHandler([.banner, .list])
        } else {
            completionHandler([.alert])
        }
    }
}

/// Exit with an optional diagnostic and the supplied process status.
func finish(_ message: String?, code: Int32 = 0) -> Never {
    if let message = message {
        FileHandle.standardError.write(Data((message + "\n").utf8))
    }
    exit(code)
}

let arguments = CommandLine.arguments
let statusOnly = arguments.dropFirst() == ["--status"]
let authorizeOnly = arguments.dropFirst() == ["--authorize"]
guard arguments.count == 3 || statusOnly || authorizeOnly else {
    finish("Usage: SlipsNotification <title> <message>, --status or --authorize", code: 2)
}
let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let center = UNUserNotificationCenter.current()
let delegate = NotificationDelegate()
center.delegate = delegate
app.delegate = delegate
DispatchQueue.main.asyncAfter(deadline: .now() + (authorizeOnly ? 60 : 4)) {
    finish("Slips notification timed out; check its permission in System Settings.", code: 3)
}

/// Submit the supplied title and message to macOS Notification Center.
func deliver() -> Void {
    if authorizeOnly { finish(nil) }
    let content = UNMutableNotificationContent()
    content.title = arguments[1]
    content.body = arguments[2]
    let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
    center.add(request) { error in
        if let error = error {
            finish(error.localizedDescription, code: 1)
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { finish(nil) }
    }
}

/// Resolve permission and deliver only after application launch completes.
func beginNotification() -> Void {
    center.getNotificationSettings { settings in
        if statusOnly {
            print(settings.authorizationStatus.rawValue)
            finish(nil)
        }
        switch settings.authorizationStatus {
        case .authorized, .provisional:
            DispatchQueue.main.async { deliver() }
        case .notDetermined:
            center.requestAuthorization(options: [.alert]) { granted, error in
                guard granted else {
                    finish(error?.localizedDescription ?? "Allow Slips notifications in System Settings.", code: 2)
                }
                DispatchQueue.main.async { deliver() }
            }
        default:
            finish("Slips notifications are disabled in System Settings.", code: 2)
        }
    }
}
app.run()
