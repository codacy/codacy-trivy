package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/codacy/codacy-trivy/internal/openssfdb"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

const (
	defaultRepoURL  = "https://github.com/ossf/malicious-packages.git"
	defaultOutput   = "/dist/cache/openssf-malicious-packages.json.gz"
	defaultRef      = ""
	defaultSourceID = "OpenSSF Malicious Packages DB"
)

func main() {
	repoURL := flag.String("repo", defaultRepoURL, "OpenSSF malicious packages repository URL")
	repoDir := flag.String("repo-dir", "", "Pre-cloned OpenSSF repository to reuse instead of cloning")
	ref := flag.String("ref", defaultRef, "Specific git reference to checkout when cloning the repository")
	output := flag.String("out", defaultOutput, "Destination path for the gzipped JSON payload")

	flag.Parse()

	ctx := context.Background()

	var (
		sourcePath string
		sourceMeta string
		cleanup    func()
		err        error
	)

	switch {
	case *repoDir != "":
		sourcePath, err = filepath.Abs(*repoDir)
		if err != nil {
			log.Fatalf("resolve repo dir: %v", err)
		}
		sourceMeta = fmt.Sprintf("%s (local)", defaultSourceID)
	default:
		sourcePath, cleanup, sourceMeta, err = cloneRepository(ctx, *repoURL, *ref)
		if err != nil {
			log.Fatalf("clone repository: %v", err)
		}
		defer cleanup()
	}

	builder := openssfdb.NewBuilder()

	outputPayload, err := builder.Build(ctx, sourcePath, sourceMeta)
	if err != nil {
		log.Fatalf("build payload: %v", err)
	}

	if err := openssfdb.WriteGzippedJSON(*output, outputPayload); err != nil {
		log.Fatalf("write payload: %v", err)
	}
}

func cloneRepository(ctx context.Context, repoURL, ref string) (string, func(), string, error) {
	tmpDir, err := os.MkdirTemp("", "openssf-malicious-*")
	if err != nil {
		return "", nil, "", err
	}
	cleanup := func() {
		_ = os.RemoveAll(tmpDir)
	}

	options := &git.CloneOptions{
		URL:   repoURL,
		Depth: 1,
	}
	if ref != "" {
		options.ReferenceName = plumbing.ReferenceName(ref)
	}

	repo, err := git.PlainCloneContext(ctx, tmpDir, false, options)
	if err != nil {
		cleanup()
		return "", nil, "", err
	}

	sourceMeta := fmt.Sprintf("%s@%s", repoURL, resolveHeadHash(repo))

	return tmpDir, cleanup, sourceMeta, nil
}

func resolveHeadHash(repo *git.Repository) string {
	headRef, err := repo.Head()
	if err != nil {
		return "unknown"
	}
	return headRef.Hash().String()
}
