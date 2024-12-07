import csv
from collections import Counter

# Configuration
FAILED_LOGIN_THRESHOLD = 10  # as suggested in the assignment 

# Function to parse the log file
def parse_log(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
        
    ip_counter = Counter()
    endpoint_counter = Counter()
    failed_logins = Counter()
    
    for line in lines:
        parts = line.split()
        ip_address = parts[0]
        status_code = parts[8]
        endpoint = parts[6]
        
        # Counting requests per IP
        ip_counter[ip_address] += 1
        
        # Counting endpoint accesses
        endpoint_counter[endpoint] += 1
        
        # Detecting failed login attempts (HTTP status 401 or "Invalid credentials")
        if status_code == "401" or "Invalid credentials" in line:
            failed_logins[ip_address] += 1
    
    return ip_counter, endpoint_counter, failed_logins


# Function to write results to CSV
def write_to_csv(ip_counter, endpoint_counter, failed_logins):
    with open('log_analysis_results.csv', 'w', newline='') as csvfile: 
# results will be saved to a csv file named log_analysis_reults.csv
        writer = csv.writer(csvfile)

        # Write a title and requests per IP section
        writer.writerow(['Requests Per IP'])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_counter.most_common():
            writer.writerow([ip, count])

        writer.writerow([])  # Empty row for separation, enhances readability

        # Write Most Frequently Accessed Endpoint
        writer.writerow(['Most Frequently Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        most_accessed_endpoint = endpoint_counter.most_common(1)[0]
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        writer.writerow([])  # Empty row for separation

        # Write Suspicious Activity section
        writer.writerow(['Suspicious Activity Detected'])
        writer.writerow(['IP Address', 'Failed Login Attempts'])
        suspicious_activities = [
            [ip, failed_count] 
            for ip, failed_count in failed_logins.items() 
            if failed_count > FAILED_LOGIN_THRESHOLD
        ]

        if suspicious_activities:
            for ip, failed_count in suspicious_activities:
                writer.writerow([ip, failed_count])
        else:
            writer.writerow(['No suspicious activity detected.', ''])

        writer.writerow([])  # Final empty row for clarity



# Function to display results in terminal
def display_results(ip_counter, endpoint_counter, failed_logins):
    # Display Requests per IP
    print(f"{'IP Address':<20}{'Request Count':<20}")
    for ip, count in ip_counter.most_common():
        print(f"{ip:<20}{count:<20}")
    
    # Display Most Accessed Endpoint
    most_accessed_endpoint = endpoint_counter.most_common(1)[0]
    print(f"\nMost Frequently Accessed Endpoint: \n{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    # Display Suspicious Activity
    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20}{'Failed Login Attempts':<20}")
    suspicious_ips = [ip for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD]
    if suspicious_ips:
        for ip, failed_count in failed_logins.items():
            if failed_count > FAILED_LOGIN_THRESHOLD:
                print(f"{ip:<20}{failed_count:<20}")
    else:
        print("No suspicious activity detected.")
    

# Main function to run the log analysis
def main():
    file_path = 'sample.log'  # Provide the correct path to the log file
    ip_counter, endpoint_counter, failed_logins = parse_log(file_path)
    display_results(ip_counter, endpoint_counter, failed_logins)
    write_to_csv(ip_counter, endpoint_counter, failed_logins)


main()
