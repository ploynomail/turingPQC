// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cpu_test

import (
	"os"
	"os/exec"
	"testing"

	. "github.com/ploynomail/turingPQC/internal/cpu"
	"github.com/ploynomail/turingPQC/internal/godebug"
	"github.com/ploynomail/turingPQC/internal/testenv"
)

func MustHaveDebugOptionsSupport(t *testing.T) {
	if !DebugOptions {
		t.Skipf("skipping test: cpu feature options not supported by OS")
	}
}

func MustSupportFeatureDetection(t *testing.T) {
	// TODO: add platforms that do not have CPU feature detection support.
}

func runDebugOptionsTest(t *testing.T, test string, options string) {
	MustHaveDebugOptionsSupport(t)

	testenv.MustHaveExec(t)

	env := "GODEBUG=" + options

	cmd := exec.Command(os.Args[0], "-test.run=^"+test+"$")
	cmd.Env = append(cmd.Env, env)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s with %s: run failed: %v output:\n%s\n",
			test, env, err, string(output))
	}
}

func TestDisableAllCapabilities(t *testing.T) {
	MustSupportFeatureDetection(t)
	runDebugOptionsTest(t, "TestAllCapabilitiesDisabled", "cpu.all=off")
}

func TestAllCapabilitiesDisabled(t *testing.T) {
	MustHaveDebugOptionsSupport(t)

	if godebug.New("#cpu.all").Value() != "off" {
		t.Skipf("skipping test: GODEBUG=cpu.all=off not set")
	}

	for _, o := range Options {
		want := false
		if got := *o.Feature; got != want {
			t.Errorf("%v: expected %v, got %v", o.Name, want, got)
		}
	}
}
