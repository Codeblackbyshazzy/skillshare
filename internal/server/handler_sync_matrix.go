package server

import (
	"encoding/json"
	"net/http"

	"skillshare/internal/config"
	"skillshare/internal/resource"
	ssync "skillshare/internal/sync"
)

type syncMatrixEntry struct {
	Skill  string `json:"skill"`
	Target string `json:"target"`
	Status string `json:"status"`
	Reason string `json:"reason"`
	Kind   string `json:"kind,omitempty"`
}

func (s *Server) handleSyncMatrix(w http.ResponseWriter, r *http.Request) {
	// Snapshot config under RLock, then release before I/O.
	s.mu.RLock()
	source := s.cfg.Source
	agentsSource := s.agentsSource()
	targets := s.cloneTargets()
	s.mu.RUnlock()

	skills, err := ssync.DiscoverSourceSkills(source)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to discover skills: "+err.Error())
		return
	}

	var agents []resource.DiscoveredResource
	if agentsSource != "" {
		discovered, _ := resource.AgentKind{}.Discover(agentsSource)
		agents = resource.ActiveAgents(discovered)
	}
	builtinAgents := config.DefaultAgentTargets()

	targetFilter := r.URL.Query().Get("target")

	var entries []syncMatrixEntry
	for name, target := range targets {
		if targetFilter != "" && name != targetFilter {
			continue
		}
		// Skills
		sc := target.SkillsConfig()
		if sc.Mode == "symlink" {
			for _, skill := range skills {
				entries = append(entries, syncMatrixEntry{
					Skill:  skill.FlatName,
					Target: name,
					Status: "na",
					Reason: "symlink mode — filters not applicable",
				})
			}
		} else {
			for _, skill := range skills {
				status, reason := ssync.ClassifySkillForTarget(skill.FlatName, skill.Targets, name, sc.Include, sc.Exclude)
				entries = append(entries, syncMatrixEntry{
					Skill:  skill.FlatName,
					Target: name,
					Status: status,
					Reason: reason,
				})
			}
		}
		// Agents — resolve path from user config or builtin defaults
		ac := target.AgentsConfig()
		agentPath := ac.Path
		if agentPath == "" {
			if builtin, ok := builtinAgents[name]; ok {
				agentPath = builtin.Path
			}
		}
		if agentPath == "" || len(agents) == 0 {
			continue
		}
		for _, agent := range agents {
			status, reason := ssync.ClassifySkillForTarget(agent.FlatName, nil, name, ac.Include, ac.Exclude)
			entries = append(entries, syncMatrixEntry{
				Skill:  agent.FlatName,
				Target: name,
				Status: status,
				Reason: reason,
				Kind:   "agent",
			})
		}
	}

	writeJSON(w, map[string]any{"entries": entries})
}

func (s *Server) handleSyncMatrixPreview(w http.ResponseWriter, r *http.Request) {
	// Snapshot config under RLock, then release before I/O.
	s.mu.RLock()
	source := s.cfg.Source
	s.mu.RUnlock()

	var body struct {
		Target  string   `json:"target"`
		Include []string `json:"include"`
		Exclude []string `json:"exclude"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Target == "" {
		writeError(w, http.StatusBadRequest, "target is required")
		return
	}

	// Validate patterns before discovering skills
	if _, err := ssync.FilterSkills(nil, body.Include, nil); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := ssync.FilterSkills(nil, nil, body.Exclude); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	skills, err := ssync.DiscoverSourceSkills(source)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to discover skills: "+err.Error())
		return
	}

	var entries []syncMatrixEntry
	for _, skill := range skills {
		status, reason := ssync.ClassifySkillForTarget(skill.FlatName, skill.Targets, body.Target, body.Include, body.Exclude)
		entries = append(entries, syncMatrixEntry{
			Skill:  skill.FlatName,
			Target: body.Target,
			Status: status,
			Reason: reason,
		})
	}

	writeJSON(w, map[string]any{"entries": entries})
}
