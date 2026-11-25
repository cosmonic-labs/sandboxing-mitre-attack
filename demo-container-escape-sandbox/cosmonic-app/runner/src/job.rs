//! The CI jobs, and the runner's step interpreter.
//!
//! The runner's flaw is the ordinary one for a CI runner: it executes the
//! steps of whatever job it is handed, and a job is attacker-controlled input
//! (a pull request from a fork that edits the pipeline file: "poisoned
//! pipeline execution"). Nothing here vets a step before running it.
//!
//! The poisoned jobs below stop at reachability. Each step asks whether a
//! container runtime's control plane can be reached from where the runner
//! runs: a socket path, a credential path, a client binary, or a read-only
//! API endpoint (`/_ping`, `/version`, `/healthz`). No step asks a runtime to
//! create, start or change anything.

use crate::probes::{self, Step};

/// One job: a name, the ATT&CK techniques it is reaching for, and its steps.
pub struct Job {
    pub id: &'static str,
    pub name: &'static str,
    pub attack: &'static str,
    /// The first command an attacker's job would run, as a one-liner.
    pub payload: &'static str,
    /// The job file, as the runner receives it.
    pub source: &'static str,
}

/// T1609 / T1610 by way of the Docker (or containerd) daemon.
pub const DOCKER: Job = Job {
    id: "docker",
    name: "Escape via docker.sock",
    attack: "T1609 Container Administration Command, T1610 Deploy Container",
    payload: "docker -H unix:///var/run/docker.sock version",
    source: "\
# .ci/pipeline.job  (changed in a pull request from a fork)
job: build-and-test
steps:
  - exec   :: docker version :: start the docker CLI to ask the daemon for its version
  - env    :: DOCKER_HOST :: look up DOCKER_HOST for the daemon's address
  - list   :: /var/run :: list /var/run for runtime sockets
  - socket :: /var/run/docker.sock :: open the Docker daemon's Unix socket
  - socket :: /run/containerd/containerd.sock :: open containerd's Unix socket
  - get    :: http://127.0.0.1:2375/_ping :: ping the Docker API over TCP on loopback
  - get    :: http://host.docker.internal:2375/version :: ask the Docker API on the host for its version
",
};

/// T1613 / T1552.007 / T1609 by way of the kubelet and the Kubernetes API.
pub const KUBE: Job = Job {
    id: "kube",
    name: "Reach the kubelet and the Kubernetes API",
    attack: "T1613 Container and Resource Discovery, T1552.007 Container API credentials, \
T1609 Container Administration Command",
    payload: "kubectl version",
    source: "\
# .ci/pipeline.job  (changed in a pull request from a fork)
job: integration
steps:
  - exec   :: kubectl version :: start kubectl to ask the API server for its version
  - env    :: KUBERNETES_SERVICE_HOST :: look up the API server address every pod is given
  - secret :: /var/run/secrets/kubernetes.io/serviceaccount/token :: read the pod's service-account token
  - read   :: /proc/1/cgroup :: read /proc/1/cgroup to learn which container runtime this is
  - read   :: /proc/self/mountinfo :: read /proc/self/mountinfo to find host mounts
  - get    :: https://kubernetes.default.svc/version :: ask the Kubernetes API server for its version
  - get    :: https://10.0.0.1:10250/healthz :: ask a node's kubelet whether it is healthy
",
};

/// A step the runner could not parse. Reported, never silently dropped.
fn unparsed(line: &str) -> Step {
    Step {
        block: "runner",
        action: "parse the step".to_string(),
        target: line.to_string(),
        call: "(none)",
        result: "the runner did not understand this step; nothing was attempted".to_string(),
        why: "",
        blocked: true,
    }
}

/// Run every step of a job, in order, and collect the runtime's answers.
///
/// VULN: the runner executes every step in the job file. It has no allow-list
/// of step kinds or targets and does not ask where the job came from.
pub async fn run(job: &Job) -> Vec<Step> {
    let mut steps = Vec::new();
    for line in job.source.lines() {
        let Some(body) = line.trim().strip_prefix("- ") else {
            continue; // comments, `job:` and `steps:` lines
        };
        let mut parts = body.splitn(3, "::").map(str::trim);
        let (Some(verb), Some(target), Some(action)) = (parts.next(), parts.next(), parts.next())
        else {
            steps.push(unparsed(body));
            continue;
        };
        let step = match verb {
            "exec" => {
                let mut words = target.split_whitespace();
                let program = words.next().unwrap_or_default();
                let args: Vec<&str> = words.collect();
                probes::spawn(action, program, &args)
            }
            "env" => probes::env_var(action, target),
            "list" => probes::list_dir(action, target),
            "socket" => probes::open_socket(action, target),
            "secret" => probes::read_file("secret", action, target),
            "read" => probes::read_file("discover", action, target),
            "get" => probes::http_get(action, target).await,
            _ => unparsed(body),
        };
        steps.push(step);
    }
    steps
}
