"""
Description:
 Generates various reports from a gateway log file.

Usage:
 python log_investigation.py log_path

Parameters:
 log_path = Path of the gateway log file
"""
import log_analysis_lib
import pandas as pd

# Get the log file path from the command line
# Because this is outside of any function, log_path is a global variable
log_path = log_analysis_lib.get_file_path_from_cmd_line()

def main():
    # Determine how much traffic is on each port
    port_traffic = tally_port_traffic()

    # Per step 9, generate reports for ports that have 100 or more records
    for port, count in port_traffic.items():
        if count >= 100:
            generate_port_traffic_report(port)

    # Generate report of invalid user login attempts
    generate_invalid_user_report()

    # Generate log of records from source IP 220.195.35.40
    generate_source_ip_log('220.195.35.40')

def tally_port_traffic():
    """Produces a dictionary of destination port numbers (key) that appear in a 
    specified log file and a count of how many times they appear (value)

    Returns:
        dict: Dictionary of destination port number counts
    """
    # TODO: Complete function body per step 7

    des_port_log = log_analysis_lib.filter_log_by_regex(log_path, r' DPT=(.*?) ')[1]

    des_port_tally = {}

    for dpt in des_port_log:
        des_port_tally[dpt[0]] = des_port_tally.get(dpt[0], 0) + 1

    return des_port_tally

def generate_port_traffic_report(port_number):
    """Produces a CSV report of all network traffic in a log file for a specified 
    destination port number.

    Args:
        port_number (str or int): Destination port number
    """
    # TODO: Complete function body per step 8
    # Get data from records that contain the specified destination port

    portNUM_regex = r'^(.*\s[0-9]+)\s+(.*)\s+myth kernel.*SRC=(.*?)\s+.*DST=(.*?)\s+.*SPT=(.*?)\s+.*DPT=' + f'({port_number})'
    report_records = log_analysis_lib.filter_log_by_regex(log_path,portNUM_regex) 
    
    

    # Generate the CSV report

    report_df = pd.DataFrame(report_records)
    report_subtitles = ('Date', 'Time', 'Source Ip Address', 'Destination IP Address', 'Source Port', 'Destination Port')
    report_filename = f'destination_port_{port_number}_report.csv'
    report_df.to_csv(report_filename, header=report_subtitles, index = False)

    return

def generate_invalid_user_report():
    """Produces a CSV report of all network traffic in a log file that show
    an attempt to login as an invalid user.
    """
    # TODO: Complete function body per step 10
    # Get data from records that show attempted invalid user login
    INVALID_user_regex = r'^(.*\s[0-9]+)\s+(.*)\s+myth kernel.*SRC=(.*?)\s+.*DST=(.*?)\s+.*SPT=(.*?)\s+.*DPT=(.*?)\s+.*Invalid user'
    report_records = log_analysis_lib.filter_log_by_regex(log_path,INVALID_user_regex)
    
    # Generate the CSV report
    report_df = pd.DataFrame(report_records)
    report_subtitles = ('Date', 'Time', 'Source Ip Address', 'Destination IP Address', 'Source Port', 'Destination Port')
    report_filename = 'invalid_user_report.csv'
    report_df.to_csv(report_filename, header=report_subtitles, index = False)
    return

def generate_source_ip_log(ip_address):
    """Produces a plain text .log file containing all records from a source log
    file that contain a specified source IP address.

    Args:
        ip_address (str): Source IP address
    """
    # TODO: Complete function body per step 11
    # Gets all records that have the specified source IP address
    # Saves all records to a plain-text .log file
    return

if __name__ == '__main__':
    main()