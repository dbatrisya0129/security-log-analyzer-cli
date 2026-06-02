import argparse
import csv
from collections import defaultdict, Counter
from datetime import datetime, timedelta


TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def load_logs(file_path):
    logs = []

    with open(file_path, "r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for row in reader:
            logs.append({
                "timestamp": datetime.strptime(row["timestamp"], TIME_FORMAT),
                "username": row["username"],
                "ip_address": row["ip_address"],
                "event": row["event"]
            })

    return logs


def detect_suspicious_logins(logs, threshold=3, minutes=5):
    failed_logins = defaultdict(list)
    alerts = []

    for log in logs:
        if log["event"] == "LOGIN_FAILED":
            key = (log["username"], log["ip_address"])
            failed_logins[key].append(log["timestamp"])

    for (username, ip_address), timestamps in failed_logins.items():
        timestamps.sort()

        for i in range(len(timestamps)):
            window_start = timestamps[i]
            window_end = window_start + timedelta(minutes=minutes)

            count = 0
            for t in timestamps[i:]:
                if t <= window_end:
                    count += 1

            if count >= threshold:
                alerts.append({
                    "username": username,
                    "ip_address": ip_address,
                    "failed_attempts": count,
                    "within_minutes": minutes,
                    "first_attempt": window_start.strftime(TIME_FORMAT),
                    "risk": "HIGH"
                })
                break

    return alerts


def generate_summary(logs, alerts):
    total_events = len(logs)
    event_counts = Counter(log["event"] for log in logs)
    user_counts = Counter(log["username"] for log in logs)
    ip_counts = Counter(log["ip_address"] for log in logs)

    suspicious_users = set(alert["username"] for alert in alerts)

    return {
        "total_events": total_events,
        "successful_logins": event_counts.get("LOGIN_SUCCESS", 0),
        "failed_logins": event_counts.get("LOGIN_FAILED", 0),
        "logout_events": event_counts.get("LOGOUT", 0),
        "admin_logins": event_counts.get("ADMIN_LOGIN", 0),
        "suspicious_accounts": len(suspicious_users),
        "most_active_user": user_counts.most_common(1)[0][0] if user_counts else "N/A",
        "most_active_ip": ip_counts.most_common(1)[0][0] if ip_counts else "N/A"
    }


def print_alerts(alerts):
    print("\n=== Suspicious Login Detection ===")

    if not alerts:
        print("No suspicious login activity detected.")
        return

    for index, alert in enumerate(alerts, start=1):
        print(f"\nAlert #{index}")
        print(f"Username        : {alert['username']}")
        print(f"IP Address      : {alert['ip_address']}")
        print(f"Failed Attempts : {alert['failed_attempts']}")
        print(f"Time Window     : {alert['within_minutes']} minutes")
        print(f"First Attempt   : {alert['first_attempt']}")
        print(f"Risk Level      : {alert['risk']}")
        print("Reason          : Possible brute-force login attempt")


def print_summary(summary):
    print("\n=== Security Summary Report ===")
    print(f"Total Events        : {summary['total_events']}")
    print(f"Successful Logins   : {summary['successful_logins']}")
    print(f"Failed Logins       : {summary['failed_logins']}")
    print(f"Logout Events       : {summary['logout_events']}")
    print(f"Admin Logins        : {summary['admin_logins']}")
    print(f"Suspicious Accounts : {summary['suspicious_accounts']}")
    print(f"Most Active User    : {summary['most_active_user']}")
    print(f"Most Active IP      : {summary['most_active_ip']}")


def main():
    parser = argparse.ArgumentParser(
        description="Security Log Analyzer CLI - Detect suspicious login activity and generate summary reports."
    )

    parser.add_argument(
        "file",
        help="Path to the CSV log file"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Number of failed login attempts before alert is triggered"
    )

    parser.add_argument(
        "--minutes",
        type=int,
        default=5,
        help="Time window in minutes for suspicious login detection"
    )

    args = parser.parse_args()

    try:
        logs = load_logs(args.file)
        alerts = detect_suspicious_logins(logs, args.threshold, args.minutes)
        summary = generate_summary(logs, alerts)

        print_alerts(alerts)
        print_summary(summary)

    except FileNotFoundError:
        print("Error: Log file not found.")
    except KeyError:
        print("Error: CSV file must contain timestamp, username, ip_address, and event columns.")
    except ValueError:
        print("Error: Timestamp format must be YYYY-MM-DD HH:MM:SS.")


if __name__ == "__main__":
    logs = load_logs("sample_logs.csv")
    alerts = detect_suspicious_logins(logs)
    summary = generate_summary(logs, alerts)

    print_alerts(alerts)
    print_summary(summary)