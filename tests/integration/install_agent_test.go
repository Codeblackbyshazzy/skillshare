//go:build !online

package integration

import (
	"os"
	"path/filepath"
	"testing"

	"skillshare/internal/testutil"
)

func TestInstall_AgentFlag_ParsesCorrectly(t *testing.T) {
	sb := testutil.NewSandbox(t)
	defer sb.Cleanup()

	sb.WriteConfig(`source: ` + sb.SourcePath + `
targets: {}
`)

	// --kind with invalid value should error
	result := sb.RunCLI("install", "--kind", "invalid", "test")
	result.AssertFailure(t)
	result.AssertAnyOutputContains(t, "must be 'skill' or 'agent'")
}

func TestInstall_AgentFlagShort_ParsesCorrectly(t *testing.T) {
	sb := testutil.NewSandbox(t)
	defer sb.Cleanup()

	sb.WriteConfig(`source: ` + sb.SourcePath + `
targets: {}
`)

	// -a without value should error
	result := sb.RunCLI("install", "-a")
	result.AssertFailure(t)
	result.AssertAnyOutputContains(t, "requires agent name")
}

func TestCheck_Agents_EmptyDir(t *testing.T) {
	sb := testutil.NewSandbox(t)
	defer sb.Cleanup()

	sb.WriteConfig(`source: ` + sb.SourcePath + `
targets: {}
`)

	// Create agents source dir
	agentsDir := filepath.Join(filepath.Dir(sb.SourcePath), "agents")
	os.MkdirAll(agentsDir, 0755)

	result := sb.RunCLI("check", "agents")
	result.AssertSuccess(t)
	result.AssertAnyOutputContains(t, "No agents found")
}

func TestCheck_Agents_LocalAgent(t *testing.T) {
	sb := testutil.NewSandbox(t)
	defer sb.Cleanup()

	sb.WriteConfig(`source: ` + sb.SourcePath + `
targets: {}
`)

	// Create agents source dir with a local agent
	agentsDir := filepath.Join(filepath.Dir(sb.SourcePath), "agents")
	os.MkdirAll(agentsDir, 0755)
	os.WriteFile(filepath.Join(agentsDir, "tutor.md"), []byte("# Tutor agent"), 0644)

	result := sb.RunCLI("check", "agents")
	result.AssertSuccess(t)
	result.AssertAnyOutputContains(t, "tutor")
	result.AssertAnyOutputContains(t, "local")
}

func TestCheck_Agents_JsonOutput(t *testing.T) {
	sb := testutil.NewSandbox(t)
	defer sb.Cleanup()

	sb.WriteConfig(`source: ` + sb.SourcePath + `
targets: {}
`)

	agentsDir := filepath.Join(filepath.Dir(sb.SourcePath), "agents")
	os.MkdirAll(agentsDir, 0755)
	os.WriteFile(filepath.Join(agentsDir, "tutor.md"), []byte("# Tutor"), 0644)

	result := sb.RunCLI("check", "agents", "--json")
	result.AssertSuccess(t)
	result.AssertAnyOutputContains(t, `"name"`)
	result.AssertAnyOutputContains(t, `"status"`)
}

func TestEnable_KindAgent_ParsesCorrectly(t *testing.T) {
	sb := testutil.NewSandbox(t)
	defer sb.Cleanup()

	sb.WriteConfig(`source: ` + sb.SourcePath + `
targets: {}
`)

	// Create agents source dir
	agentsDir := filepath.Join(filepath.Dir(sb.SourcePath), "agents")
	os.MkdirAll(agentsDir, 0755)

	// Disable an agent — --kind goes after -g (mode flag)
	result := sb.RunCLI("disable", "-g", "--kind", "agent", "tutor")
	result.AssertSuccess(t)
	result.AssertAnyOutputContains(t, ".agentignore")

	// Verify .agentignore was created
	agentIgnorePath := filepath.Join(agentsDir, ".agentignore")
	if !sb.FileExists(agentIgnorePath) {
		t.Error(".agentignore should be created")
	}
}

func TestUninstall_AgentsPositional_ParsesCorrectly(t *testing.T) {
	sb := testutil.NewSandbox(t)
	defer sb.Cleanup()

	sb.WriteConfig(`source: ` + sb.SourcePath + `
targets: {}
`)

	// Positional "agents" with nonexistent agent — should parse correctly (no "unknown option")
	result := sb.RunCLI("uninstall", "-g", "agents", "nonexistent")
	result.AssertOutputNotContains(t, "unknown option")
}

func TestInstall_MixedRepo_InstallsAgentsToAgentsDir(t *testing.T) {
	sb := testutil.NewSandbox(t)
	defer sb.Cleanup()

	sb.WriteConfig(`source: ` + sb.SourcePath + `
targets: {}
`)

	// Create a git repo with both skills and agents
	repoDir := filepath.Join(sb.Home, "mixed-repo")
	os.MkdirAll(filepath.Join(repoDir, "skills", "my-skill"), 0755)
	os.WriteFile(filepath.Join(repoDir, "skills", "my-skill", "SKILL.md"),
		[]byte("---\nname: my-skill\n---\n# My Skill"), 0644)
	os.MkdirAll(filepath.Join(repoDir, "agents"), 0755)
	os.WriteFile(filepath.Join(repoDir, "agents", "my-agent.md"),
		[]byte("# My Agent"), 0644)
	initGitRepo(t, repoDir)

	result := sb.RunCLI("install", "file://"+repoDir, "--yes")
	result.AssertSuccess(t)

	// Skill should be in skills source
	skillPath := filepath.Join(sb.SourcePath, "my-skill")
	if !sb.FileExists(filepath.Join(skillPath, "SKILL.md")) {
		t.Error("skill should be installed to skills source dir")
	}

	// Agent should be in agents source (NOT skills source)
	agentsDir := filepath.Join(filepath.Dir(sb.SourcePath), "agents")
	agentPath := filepath.Join(agentsDir, "my-agent.md")
	if !sb.FileExists(agentPath) {
		t.Errorf("agent should be installed to agents dir (%s), not skills dir", agentsDir)
	}

	// Agent should NOT be in skills source
	wrongPath := filepath.Join(sb.SourcePath, "my-agent.md")
	if sb.FileExists(wrongPath) {
		t.Error("agent should NOT be in skills source dir")
	}
}
