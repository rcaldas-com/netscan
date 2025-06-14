# Network Scanner

This project is a Python-based network scanner designed to identify devices on a local network. It provides detailed information about each device, including potential repeaters, IP addresses, brand/model, access credentials, and other useful network data such as NAT and exposed ports.

## Features

- Scans the local network for connected devices.
- Identifies potential repeaters and their details.
- Gathers IP addresses and brand/model information of devices.
- Attempts to retrieve access credentials for devices.
- Collects information about NAT configurations and exposed ports.

## Requirements

To run this project, you need to have Python installed along with the required libraries.  
It is recommended to use a virtual environment (venv) to manage dependencies.

> **Important:**  
> This script must be run as root (or with sudo) to access the network interface and perform ARP scans.

## Setup

1. **Clone the repository to your local machine:**
   ```
   git clone <repository-url>
   cd netscan
   ```

2. **Create and activate a virtual environment:**
   ```
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install the dependencies:**
   ```
   pip install -r requirements.txt
   ```

## Usage

1. **Run the network scanner as root:**
   ```
   sudo venv/bin/python src/netscan.py
   ```

2. **Follow the on-screen instructions to scan your network.**

## Contributing

Contributions are welcome! If you have suggestions for improvements or new features, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.