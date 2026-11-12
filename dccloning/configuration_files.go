package dccloning

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type configEnvironment interface {
	prerequisites(context.Context) (ConfigPrerequisites, error)
	configDirectories(context.Context) ([]string, error)
	equal(string, string) (bool, error)
}

func generateConfiguration(ctx context.Context, options ConfigOptions, environment configEnvironment, publish publishFile) (result Configured, resultErr error) {
	result.Outcome, result.ChecksSkipped = NotWritten, options.Offline
	data, err := EncodeCloneConfiguration(options.Configuration)
	if err != nil {
		return result, err
	}
	if err := context.Cause(ctx); err != nil {
		return result, err
	}
	directory := options.Directory
	if !options.Offline {
		result.Prerequisites, err = environment.prerequisites(ctx)
		if err != nil {
			return result, err
		}
		if !result.Prerequisites.Complete {
			return result, fmt.Errorf("%w: preparation returned incomplete observations", ErrClonePrerequisite)
		}
		// File-location/collision validation is part of online preparation too.
		result.Prerequisites.Complete = false
		directories, err := environment.configDirectories(ctx)
		if err != nil {
			return result, err
		}
		if len(directories) == 0 || directories[0] == "" {
			return result, fmt.Errorf("%w: no DSA working directory", ErrInvalidPath)
		}
		if directory == "" {
			directory = directories[0]
		}
		directory, err = filepath.Abs(directory)
		if err != nil {
			return result, fmt.Errorf("resolve clone output directory: %w", err)
		}
		rank, err := pathRank(directory, directories, environment.equal)
		if err != nil {
			return result, err
		}
		if rank < 0 {
			return result, fmt.Errorf("%w: directory is outside the clone configuration search locations", ErrInvalidPath)
		}
		for _, location := range directories {
			if err := context.Cause(ctx); err != nil {
				return result, err
			}
			path := filepath.Join(location, ConfigFileName)
			if _, err := os.Lstat(path); err == nil {
				return result, fmt.Errorf("%w: clone configuration at %s", ErrOutputExists, path)
			} else if !errors.Is(err, os.ErrNotExist) {
				return result, fmt.Errorf("inspect existing clone configuration: %w", err)
			}
		}
	}
	if directory == "" {
		return result, ErrInvalidPath
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		return result, fmt.Errorf("resolve clone output directory: %w", err)
	}
	result.Path = filepath.Join(directory, ConfigFileName)
	info, err := os.Stat(directory)
	if err != nil {
		return result, fmt.Errorf("inspect clone output directory: %w", err)
	}
	if !info.IsDir() {
		return result, ErrInvalidPath
	}
	result.Prerequisites.Complete = !options.Offline
	// The same owned-temporary-file publication primitive is used by inclusion
	// lists. It bounds cleanup and does not retry an uncertain MoveFileEx result.
	result.Outcome, err = writeArtifact(ctx, result.Path, data, options.Offline, publish)
	return result, err
}
