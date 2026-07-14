package main

import (
	"fmt"
	"os/exec"
)

// reloadTelegraf sends SIGHUP to PID 1 inside the telegraf container via
// `docker exec`, which Telegraf treats as a live config reload with no gap in
// metrics collection — the reload mechanism decided in plan §9.4, requiring the
// config-watcher container to have the host's Docker socket mounted.
func reloadTelegraf(containerName string) error {
	cmd := exec.Command("docker", "exec", containerName, "kill", "-SIGHUP", "1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("reload: docker exec %s kill -SIGHUP 1: %w (output: %s)", containerName, err, out)
	}
	return nil
}
