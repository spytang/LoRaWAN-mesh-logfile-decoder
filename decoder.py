#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This script processes a LoRaWAN mesh log file (e.g., a.log), finds ALL
'mesh_packet' entries (even multiple on the same line), decodes the payload,
and outputs a consolidated CSV file.
"""

import re
import csv
import sys
from typing import Dict, Any, Optional

# --- LoRaWAN Decoding Logic (adapted from your keyless_decoder.py) ---
# This part remains unchanged as it was correct.
MTYPE_MAP = {
    0: "Join Request",
    1: "Join Accept",
    2: "Unconfirmed Data Up",
    3: "Unconfirmed Data Down",
    4: "Confirmed Data Up",
    5: "Confirmed Data Down",
    6: "RFU",
    7: "Proprietary",
}

def decode_phy_payload_keyless(phy: bytes) -> Optional[Dict[str, Any]]:
    """
    Parses the unencrypted fields of a LoRaWAN PHYPayload.
    """
    if len(phy) < 12:
        return None

    try:
        mhdr = phy[0]
        mtype_code = (mhdr >> 5) & 0x7
        mtype_str = MTYPE_MAP.get(mtype_code, "Unknown")

        dev_addr_le = phy[1:5]
        dev_addr_be = dev_addr_le[::-1].hex().upper()

        fctrl = phy[5]
        fopts_len = fctrl & 0x0F
        fcnt = int.from_bytes(phy[6:8], "little")

        fhdr_len = 7 + fopts_len
        if 1 + fhdr_len > len(phy) - 4:
            return None

        idx_after_fhdr = 1 + fhdr_len
        payload_body_len = len(phy) - 1 - fhdr_len - 4

        fport: Optional[int] = None
        frm_len = 0
        if payload_body_len > 0:
            fport = phy[idx_after_fhdr]
            frm_len = payload_body_len - 1
        
        if frm_len < 0:
            frm_len = 0

        return {
            "MType": f"{mtype_str} ({mtype_code})",
            "DevAddr": dev_addr_be,
            "FCnt": fcnt,
            "FPort": fport,
            "FRM_Length": frm_len,
        }
    except IndexError:
        return None

# --- Log File Processing (Corrected Logic) ---

def parse_packet_content(content: str) -> Optional[Dict[str, str]]:
    """
    Parses the string content from within a single 'mesh_packet: [...]' block.
    """
    data = dict(re.findall(r'([\w_]+):\s*([\w:]+)', content))
    
    # The payload can be long, so we re-extract it specifically to ensure we get all of it.
    payload_match = re.search(r"lorawan_phy_payload:\s*([0-9a-fA-F]+)", content)
    if not payload_match:
        return None # Skip if there's no payload
    
    data['lorawan_phy_payload'] = payload_match.group(1)

    if "Uplink" in content:
        data['Type'] = 'Uplink'
    elif "Downlink" in content:
        data['Type'] = 'Downlink'
    else:
        data['Type'] = 'Unknown'
        
    return data

def process_log_file(input_filename: str, output_filename: str) -> None:
    """
    Reads the entire log file, finds all mesh_packet entries, processes them,
    and writes the results to a CSV file.
    """
    headers = [
        'Type', 'hop_count', 'uplink_id', 'timestamp', 'relay_id', 'mic',
        'lorawan_phy_payload', 'MType', 'DevAddr', 'FCnt', 'FPort', 'FRM_Length'
    ]

    print(f"Starting processing of '{input_filename}'...")
    
    try:
        with open(input_filename, 'r', encoding='utf-8') as infile:
            # Read the entire file content at once.
            log_content = infile.read()

        # Find all occurrences of "mesh_packet: [...]" and extract their content.
        # The '([^\]]+)' part captures everything up to the closing bracket ']'.
        all_packets = re.findall(r"mesh_packet:\s*\[([^\]]+)\]", log_content)
        
        if not all_packets:
            print("Warning: No 'mesh_packet' entries found in the file.", file=sys.stderr)
            return

        with open(output_filename, 'w', newline='', encoding='utf-8') as outfile:
            writer = csv.DictWriter(outfile, fieldnames=headers, extrasaction='ignore')
            writer.writeheader()
            
            for i, packet_content in enumerate(all_packets):
                # 1. Parse the content of this specific packet
                log_data = parse_packet_content(packet_content)
                if not log_data:
                    continue

                # 2. Decode the payload
                decoded_data = None
                payload_hex = log_data.get('lorawan_phy_payload')
                if payload_hex:
                    try:
                        payload_bytes = bytes.fromhex(payload_hex)
                        decoded_data = decode_phy_payload_keyless(payload_bytes)
                    except ValueError:
                        print(f"Warning: Could not decode invalid hex payload in packet #{i+1}", file=sys.stderr)
                
                # 3. Combine and write to CSV
                if decoded_data:
                    log_data.update(decoded_data)
                
                writer.writerow(log_data)
        
        print(f"Processing complete. Successfully processed {len(all_packets)} packet entries.")
        print(f"Output saved to '{output_filename}'")

    except FileNotFoundError:
        print(f"Error: Input file '{input_filename}' not found.", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)


# --- Main Execution Block ---
if __name__ == "__main__":
    INPUT_LOG_FILE = 'mesh_packets.log'
    OUTPUT_CSV_FILE = 'decoded_log.csv'
    
    process_log_file(INPUT_LOG_FILE, OUTPUT_CSV_FILE)