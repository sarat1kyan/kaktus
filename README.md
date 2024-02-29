# kaktus
# Windows System Hardening Script

[![Windows Hardening](https://img.shields.io/badge/Windows-Hardening-blue)](https://github.com/your_username/windows-system-hardening)

Automate the process of hardening Windows systems based on Security Technical Implementation Guides (STIGs) with this PowerShell script. Enhance the security posture of Windows operating systems by applying security configurations, including Local Group Policy Object (LGPO) settings and registry changes.

## Features

- **Automated Hardening**: Detects Windows version and applies appropriate hardening configurations.
- **LGPO Tool Integration**: Uses LGPO tool to apply security settings.
- **Rollback Functionality**: Provides rollback functionality in case of errors during execution.
- **Email Notifications**: Supports email notifications for reporting script execution status.
- **Customizable Parameters**: Easily customize script parameters for your environment.

## Usage

1. **Clone the repository** to your local machine:

    ```bash
    git clone https://github.com/sarat1kyan/kaktus.git
    ```

2. **Customize the script parameters** in `kaktus.ps1` as needed.

3. **Run the script**:

    ```powershell
    .\kaktus.ps1
    ```

## Configuration

- `lgpoToolExecutable`: Name of the LGPO tool executable file.
- `scriptDirectory`: Path to the directory containing the script files.
- `logFile`: Path to the log file for recording script execution details.
- `confirmChanges`: Boolean value indicating whether to confirm changes before applying.
- `emailFrom`: Email address from which notifications will be sent.
- `emailTo`: Email address to which notifications will be sent.
- `smtpServer`: SMTP server address for sending email notifications.

## Contributions

Contributions are welcome! If you find any issues or have suggestions for improvements, feel free to open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).
