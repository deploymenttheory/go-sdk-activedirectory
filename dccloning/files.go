package dccloning

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func readList(path string) (data []byte, resultErr error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open inclusion file: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	data, err = io.ReadAll(io.LimitReader(file, maxListBytes+1))
	if err != nil {
		return data, fmt.Errorf("read inclusion file: %w", err)
	}
	if len(data) > maxListBytes {
		return nil, fmt.Errorf("%w: inclusion file exceeds size limit", ErrInvalidList)
	}
	return data, nil
}

type publishFile func(temporary, destination string, overwrite bool) error

func generate(ctx context.Context, m machine, options GenerateOptions, read fileReader, publish publishFile) (result Generated, resultErr error) {
	result.Outcome = NotWritten
	if err := context.Cause(ctx); err != nil {
		return result, err
	}
	directory, err := filepath.Abs(options.Directory)
	if err != nil {
		return result, fmt.Errorf("%w: %w", ErrInvalidPath, err)
	}
	result.Path = filepath.Join(directory, CustomFileName)
	info, err := os.Stat(directory)
	if err != nil {
		return result, fmt.Errorf("output directory: %w", err)
	}
	if !info.IsDir() {
		return result, ErrInvalidPath
	}
	r, paths, err := inspect(ctx, m, read, false)
	result.Result = r
	if err != nil {
		return result, err
	}
	rank, err := pathRank(directory, paths.directories, m.equal)
	if err != nil {
		return result, err
	}
	if rank < 0 {
		return result, fmt.Errorf("%w: directory is outside the custom-list search locations", ErrInvalidPath)
	}
	// The reference returns without touching output when the default-only delta
	// is empty, before checking whether an existing file requires Force.
	if len(r.Entries) == 0 {
		return result, nil
	}
	if r.CustomListPath != "" {
		current, rankErr := pathRank(filepath.Dir(r.CustomListPath), paths.directories, m.equal)
		if rankErr != nil {
			return result, rankErr
		}
		if rank > current {
			return result, ErrPrecedence
		}
	}
	if _, err := os.Lstat(result.Path); err == nil {
		if !options.Overwrite {
			return result, ErrOutputExists
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, fmt.Errorf("inspect output file: %w", err)
	}
	data, err := EncodeCustomAllowList(r.Entries)
	if err != nil {
		return result, err
	}
	result.Outcome, err = writeArtifact(ctx, result.Path, data, options.Overwrite, publish)
	return result, err
}

func pathRank(path string, directories []string, equal func(string, string) (bool, error)) (int, error) {
	for i, candidate := range directories {
		match, err := equal(filepath.Clean(path), filepath.Clean(candidate))
		if err != nil {
			return -1, err
		}
		if match {
			return i, nil
		}
	}
	return -1, nil
}

func writeArtifact(ctx context.Context, destination string, data []byte, overwrite bool, publish publishFile) (outcome WriteOutcome, resultErr error) {
	outcome = NotWritten
	file, err := os.CreateTemp(filepath.Dir(destination), ".ad-sdk-cloning-*")
	if err != nil {
		return outcome, fmt.Errorf("create inclusion temporary file: %w", err)
	}
	temporary := file.Name()
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, file.Close())
		}
		if err := os.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, fmt.Errorf("remove owned inclusion temporary file: %w", err))
		}
	}()
	n, err := file.Write(data)
	if err != nil {
		return outcome, fmt.Errorf("write inclusion temporary file: %w", err)
	}
	if n != len(data) {
		return outcome, io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		return outcome, fmt.Errorf("sync inclusion temporary file: %w", err)
	}
	err = file.Close()
	closed = true
	if err != nil {
		return outcome, fmt.Errorf("close inclusion temporary file: %w", err)
	}
	if err := context.Cause(ctx); err != nil {
		return outcome, err
	}
	if err := publish(temporary, destination, overwrite); err != nil {
		return WriteUncertain, fmt.Errorf("publish inclusion file (not retried): %w", err)
	}
	return Written, nil
}
