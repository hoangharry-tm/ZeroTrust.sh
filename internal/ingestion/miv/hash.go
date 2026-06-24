// Copyright 2026 Minh Hoang Ton
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package miv

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	ggufMagic = 0x46554747 // "GGUF" in little-endian

	ggufTypeUINT8   = 0
	ggufTypeINT8    = 1
	ggufTypeUINT16  = 2
	ggufTypeINT16   = 3
	ggufTypeUINT32  = 4
	ggufTypeINT32   = 5
	ggufTypeFLOAT32 = 6
	ggufTypeBOOL    = 7
	ggufTypeSTRING  = 8
	ggufTypeARRAY   = 9
	ggufTypeUINT64  = 10
	ggufTypeINT64   = 11
	ggufTypeFLOAT64 = 12

	hashChunkSize = 32 << 20 // 32 MB streaming chunks
	// GGUF string sanity limit: 1 MiB.
	// Real model names and keys are always < 256 bytes; this guards against
	// a malformed file sending us into a huge allocation.
	maxGGUFStringLen = 1 << 20
)

// hashGGUF computes the SHA-256 hex digest of the GGUF model file at modelPath.
// Files larger than 32 MB are streamed in 32 MB chunks to bound memory usage.
// Context cancellation halts streaming between chunks.
func hashGGUF(ctx context.Context, modelPath string) (string, error) {
	f, err := os.Open(modelPath)
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck

	h := sha256.New()
	buf := make([]byte, hashChunkSize)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, err := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read model file: %w", err)
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// readGGUFModelID extracts the "general.name" value from a GGUF file's
// metadata KV section. Supports GGUF versions 2 and 3 (little-endian).
// Returns ErrNotGGUF if the file is not a valid GGUF file.
func readGGUFModelID(modelPath string) (string, error) {
	f, err := os.Open(modelPath)
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck

	r := bufio.NewReader(f)

	var magic uint32
	if err := binary.Read(r, binary.LittleEndian, &magic); err != nil {
		return "", fmt.Errorf("read magic: %w", err)
	}
	if magic != ggufMagic {
		return "", ErrNotGGUF
	}

	var version uint32
	if err := binary.Read(r, binary.LittleEndian, &version); err != nil {
		return "", fmt.Errorf("read version: %w", err)
	}
	if version < 2 {
		return "", fmt.Errorf("unsupported GGUF version %d (need 2+)", version)
	}

	var nTensors, nKV uint64
	if err := binary.Read(r, binary.LittleEndian, &nTensors); err != nil {
		return "", fmt.Errorf("read tensor count: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &nKV); err != nil {
		return "", fmt.Errorf("read kv count: %w", err)
	}

	for range nKV {
		key, err := readGGUFString(r)
		if err != nil {
			return "", fmt.Errorf("read kv key: %w", err)
		}

		var valueType uint32
		if err := binary.Read(r, binary.LittleEndian, &valueType); err != nil {
			return "", fmt.Errorf("read value type for %q: %w", key, err)
		}

		if key == "general.name" {
			if valueType != ggufTypeSTRING {
				return "", fmt.Errorf("general.name has unexpected type %d", valueType)
			}
			return readGGUFString(r)
		}

		if err := skipGGUFValue(r, valueType); err != nil {
			return "", fmt.Errorf("skip value for %q: %w", key, err)
		}
	}

	return "", errors.New("general.name not found in GGUF metadata")
}

func readGGUFString(r io.Reader) (string, error) {
	var length uint64
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return "", err
	}
	if length > maxGGUFStringLen {
		return "", fmt.Errorf("string length %d exceeds sanity limit", length)
	}
	b := make([]byte, length)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return string(b), nil
}

func skipGGUFValue(r io.Reader, valueType uint32) error {
	var fixedSize int
	switch valueType {
	case ggufTypeUINT8, ggufTypeINT8, ggufTypeBOOL:
		fixedSize = 1
	case ggufTypeUINT16, ggufTypeINT16:
		fixedSize = 2
	case ggufTypeUINT32, ggufTypeINT32, ggufTypeFLOAT32:
		fixedSize = 4
	case ggufTypeUINT64, ggufTypeINT64, ggufTypeFLOAT64:
		fixedSize = 8
	case ggufTypeSTRING:
		_, err := readGGUFString(r)
		return err
	case ggufTypeARRAY:
		var elemType uint32
		var count uint64
		if err := binary.Read(r, binary.LittleEndian, &elemType); err != nil {
			return err
		}
		if err := binary.Read(r, binary.LittleEndian, &count); err != nil {
			return err
		}
		for range count {
			if err := skipGGUFValue(r, elemType); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown GGUF value type %d", valueType)
	}
	_, err := io.ReadFull(r, make([]byte, fixedSize))
	return err
}
